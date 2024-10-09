use crate::{
    args::Args,
    proxy::{
        self,
        types::{Call, RpcParamsEstimate},
    },
    utils, ServerState, StarkVrfProof,
};
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    RequestExt,
};
use cainome_cairo_serde::CairoSerde;
use clap::Parser;
use http_body_util::BodyExt;
use hyper::{header::CONTENT_TYPE, StatusCode, Uri};
use katana_primitives::{block::BlockTag, chain::ChainId, felt, transaction::InvokeTx, Felt};
use katana_rpc_types::transaction::{BroadcastedInvokeTx, BroadcastedTx};
use num::{BigInt, Num};
use serde_json::Value;
use stark_vrf::{generate_public_key, BaseField, StarkVRF};
use starknet::{
    accounts::Account,
    core::types::{
        BlockId, BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1,
        BroadcastedInvokeTransactionV3, BroadcastedTransaction, SimulatedTransaction,
        SimulationFlag,
    },
    macros::{selector, short_string},
    providers::Provider,
};
use std::{str::FromStr, time::Duration};
use tokio::time::sleep;
use tracing::{info, warn};

use super::types::{RpcParamsInvoke, RpcRequest};

pub async fn proxy_handler(
    State(state): State<ServerState>,
    mut req: Request,
) -> Result<Response, StatusCode> {
    let args = state.args;

    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("{}{}", args.rpc, path_query);

    let content_type_header = req.headers().get(CONTENT_TYPE);
    let content_type = content_type_header.and_then(|value| value.to_str().ok());

    if let Some(content_type) = content_type {
        if content_type.starts_with("application/json") {
            let (mut parts, body) = req.into_parts();

            // this won't work if the body is an long running stream
            let mut bytes = body
                .collect()
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR))?
                .to_bytes();

            let reqclone = Request::from_parts(parts.clone(), Body::from(bytes.clone()));
            let extracted: Result<RpcRequest<Value>, _> = reqclone.extract().await;
            if let Ok(payload) = extracted {
                info!("{}", payload.method);

                if payload.method == "starknet_estimateFee" {
                    let reqclone = Request::from_parts(parts.clone(), Body::from(bytes.clone()));
                    let extracted: Result<RpcRequest<RpcParamsEstimate>, _> =
                        reqclone.extract().await;
                    if let Ok(mut payload) = extracted {
                        // println!("payload {:#?}", payload);

                        if let BroadcastedTx::Invoke(invoke) = payload.params.request[0].clone() {
                            let invoke =
                                &invoke.into_tx_with_chain_id(ChainId::Id(short_string!("KATANA")));

                            let request_random_calls =
                                get_request_random_calls(invoke, args.vrf_provider_address);

                            if !request_random_calls.is_empty() {
                                let submit_random_call =
                                    build_submit_random_call_from_request_random(
                                        &request_random_calls[0],
                                        args.clone(),
                                    );

                                let mut calls = get_calls(invoke);
                                calls.insert(
                                    0,
                                    Call {
                                        to: submit_random_call.to,
                                        selector: submit_random_call.selector,
                                        calldata: submit_random_call.calldata,
                                    },
                                );

                                let calldata: Vec<Felt> =
                                    Vec::<proxy::types::Call>::cairo_serialize(&calls);

                                let request = payload.params.request[0].clone();
                                let new_request =
                                    broadcasted_tx_with_new_calldata(&request, &calldata);
                                payload.params.request[0] = new_request;

                                let json = serde_json::to_string_pretty(&payload).unwrap();
                                bytes = Bytes::from(json);

                                parts.headers.remove("content-length");
                                parts.headers.append(
                                    "content-length",
                                    HeaderValue::from_str(&bytes.len().to_string()).unwrap(),
                                );
                                warn!("estimateFee with submit_random")
                            }
                        }
                    }
                }
                if payload.method == "starknet_addInvokeTransaction" {
                    let reqclone = Request::from_parts(parts.clone(), Body::from(bytes.clone()));
                    let extracted: Result<RpcRequest<RpcParamsInvoke>, _> =
                        reqclone.extract().await;
                    if let Ok(payload) = extracted {
                        let invoke = &payload
                            .params
                            .invoke_transaction
                            .clone()
                            .into_tx_with_chain_id(ChainId::Id(short_string!("KATANA")));

                        let request_random_calls =
                            get_request_random_calls(invoke, args.vrf_provider_address);

                        if !request_random_calls.is_empty() {
                            let submit_random_call = build_submit_random_call_from_request_random(
                                &request_random_calls[0],
                                args.clone(),
                            );

                            let account = args.get_account();

                            let submit_random_result =
                                account.execute_v1(vec![submit_random_call]).send().await;

                            warn!("submit_random: {:?}", submit_random_result);
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }

            req = Request::from_parts(parts, Body::from(bytes));
        }
    }

    // forward request to rpc
    *req.uri_mut() = Uri::try_from(uri).unwrap();

    Ok(state
        .client
        .request(req)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .into_response())
}

pub fn build_submit_random_call_from_request_random(
    request_random_call: &Call,
    args: Args,
) -> starknet::core::types::Call {
    let seed = request_random_call.calldata[request_random_call.calldata.len() - 1];
    // info!("seed: {}", seed);

    let proof = get_proof(seed);

    let submit_random_call = starknet::core::types::Call {
        to: args.vrf_provider_address,
        selector: selector!("submit_random"),
        calldata: vec![
            seed,
            Felt::from_hex(&proof.gamma_x).unwrap(),
            Felt::from_hex(&proof.gamma_y).unwrap(),
            Felt::from_hex(&proof.c).unwrap(),
            Felt::from_hex(&proof.s).unwrap(),
            Felt::from_hex(&proof.sqrt_ratio).unwrap(),
        ],
    };
    submit_random_call
}

pub async fn build_submit_random_call_from_simulation(
    simulation: SimulatedTransaction,
    args: Args,
) -> Option<starknet::core::types::Call> {
    match simulation.transaction_trace {
        starknet::core::types::TransactionTrace::Invoke(invoke_transaction_trace) => {
            match invoke_transaction_trace.execute_invocation {
                starknet::core::types::ExecuteInvocation::Success(function_invocation) => {
                    if let Some(event) = function_invocation
                        .calls
                        .first()
                        .unwrap()
                        .events
                        .iter()
                        .find(|e| e.keys[0] == selector!("RequestRandom"))
                    {
                        // info!("event: {:?}", event);
                        let seed = event.data[event.data.len() - 1];
                        // info!("seed: {}", seed);

                        let proof = get_proof(seed);

                        let submit_random_call = starknet::core::types::Call {
                            to: args.vrf_provider_address,
                            selector: selector!("submit_random"),
                            calldata: vec![
                                seed,
                                Felt::from_hex(&proof.gamma_x).unwrap(),
                                Felt::from_hex(&proof.gamma_y).unwrap(),
                                Felt::from_hex(&proof.c).unwrap(),
                                Felt::from_hex(&proof.s).unwrap(),
                                Felt::from_hex(&proof.sqrt_ratio).unwrap(),
                            ],
                        };

                        Option::Some(submit_random_call)
                    } else {
                        Option::None
                    }
                }
                starknet::core::types::ExecuteInvocation::Reverted(_) => Option::None,
            }
        }
        _ => Option::None,
    }
}

pub async fn simulate_request_random(
    request_random_calls: &Vec<Call>,
    invoke: &InvokeTx,
    args: Args,
) -> SimulatedTransaction {
    let provider = args.get_provider();

    // create new tx & calldata with only request_random
    let mut calldata = vec![
        felt!("0x1"),
        request_random_calls[0].to,
        request_random_calls[0].selector,
        request_random_calls[0].calldata.len().into(),
    ];
    calldata.append(request_random_calls[0].calldata.clone().as_mut());
    let tx = invoke_tx_to_broadcasted_invoke_tx(invoke, &calldata);

    // println!("{:?}", tx);

    let simulation = provider
        .simulate_transaction(
            BlockId::Tag(BlockTag::Pending),
            BroadcastedTransaction::Invoke(tx),
            vec![SimulationFlag::SkipValidate],
        )
        .await
        .unwrap();

    simulation
}
pub fn get_calls(invoke: &InvokeTx) -> Vec<Call> {
    let calldata = match invoke {
        InvokeTx::V1(invoke_tx_v1) => invoke_tx_v1.calldata.clone(),
        InvokeTx::V3(invoke_tx_v3) => invoke_tx_v3.calldata.clone(),
    };

    Vec::<Call>::cairo_deserialize(&calldata, 0).unwrap()
}

pub fn get_request_random_calls(invoke: &InvokeTx, vrf_provider_address: Felt) -> Vec<Call> {
    let calls = get_calls(invoke);
    calls
        .iter()
        .filter(|c| c.to == vrf_provider_address && c.selector == selector!("request_random"))
        .cloned()
        .collect()
}

pub fn get_proof(seed: Felt) -> StarkVrfProof {
    let secret_key = Args::parse().get_secret_key();
    let public_key = generate_public_key(secret_key.parse().unwrap());

    let seed: Vec<_> = [seed.to_hex_string()]
        .iter()
        .map(|x| {
            let dec_string = BigInt::from_str_radix(&x[2..], 16).unwrap().to_string();
            BaseField::from_str(&dec_string).unwrap()
        })
        .collect();

    let ecvrf = StarkVRF::new(public_key).unwrap();
    let proof = ecvrf
        .prove(&secret_key.parse().unwrap(), seed.as_slice())
        .unwrap();
    let sqrt_ratio_hint = ecvrf.hash_to_sqrt_ratio_hint(seed.as_slice());
    let rnd = ecvrf.proof_to_hash(&proof).unwrap();

    StarkVrfProof {
        gamma_x: utils::format(proof.0.x),
        gamma_y: utils::format(proof.0.y),
        c: utils::format(proof.1),
        s: utils::format(proof.2),
        sqrt_ratio: utils::format(sqrt_ratio_hint),
        rnd: utils::format(rnd),
    }
}

pub fn broadcasted_tx_with_new_calldata(
    request: &BroadcastedTx,
    calldata: &Vec<Felt>,
) -> BroadcastedTx {
    match request {
        BroadcastedTx::Invoke(ref broadcasted_invoke_tx) => match &broadcasted_invoke_tx.0 {
            BroadcastedInvokeTransaction::V1(tx_v1) => BroadcastedTx::Invoke(BroadcastedInvokeTx(
                BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                    sender_address: tx_v1.sender_address,
                    calldata: calldata.clone(),
                    max_fee: tx_v1.max_fee,
                    // signature: tx_v1.signature.clone(),
                    signature: vec![],
                    nonce: tx_v1.nonce,
                    is_query: tx_v1.is_query,
                }),
            )),
            BroadcastedInvokeTransaction::V3(tx_v3) => BroadcastedTx::Invoke(BroadcastedInvokeTx(
                BroadcastedInvokeTransaction::V3(BroadcastedInvokeTransactionV3 {
                    sender_address: tx_v3.sender_address,
                    calldata: calldata.clone(),
                    //signature: tx_v3.signature.clone(),
                    signature: vec![],
                    nonce: tx_v3.nonce,
                    resource_bounds: tx_v3.resource_bounds.clone(),
                    tip: tx_v3.tip,
                    paymaster_data: tx_v3.paymaster_data.clone(),
                    account_deployment_data: tx_v3.account_deployment_data.clone(),
                    nonce_data_availability_mode: tx_v3.nonce_data_availability_mode,
                    fee_data_availability_mode: tx_v3.fee_data_availability_mode,
                    is_query: tx_v3.is_query,
                }),
            )),
        },
        _ => {
            unreachable!()
        }
    }
}

pub fn invoke_tx_to_broadcasted_invoke_tx(
    invoke: &InvokeTx,
    request_random_calldata: &[Felt],
) -> BroadcastedInvokeTransaction {
    match invoke {
        InvokeTx::V1(invoke_tx_v1) => BroadcastedInvokeTransaction::V1(
            starknet::core::types::BroadcastedInvokeTransactionV1 {
                sender_address: invoke_tx_v1.sender_address.into(),
                calldata: request_random_calldata.to_vec(),
                max_fee: invoke_tx_v1.max_fee.into(),
                // signature: invoke_tx_v1.signature.clone(),
                signature: vec![],
                nonce: invoke_tx_v1.nonce,
                is_query: false, // ?
            },
        ),
        InvokeTx::V3(invoke_tx_v3) => BroadcastedInvokeTransaction::V3(
            starknet::core::types::BroadcastedInvokeTransactionV3 {
                sender_address: invoke_tx_v3.sender_address.into(),
                calldata: request_random_calldata.to_vec(),
                // signature: invoke_tx_v3.signature.clone(),
                signature: vec![],
                nonce: invoke_tx_v3.nonce,
                resource_bounds: invoke_tx_v3.resource_bounds.clone(),
                tip: invoke_tx_v3.tip,
                paymaster_data: invoke_tx_v3.paymaster_data.clone(),
                account_deployment_data: invoke_tx_v3.account_deployment_data.clone(),
                nonce_data_availability_mode: invoke_tx_v3.nonce_data_availability_mode,
                fee_data_availability_mode: invoke_tx_v3.fee_data_availability_mode,
                is_query: false, // ?
            },
        ),
    }
}
