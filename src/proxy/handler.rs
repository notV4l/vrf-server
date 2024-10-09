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
use katana_primitives::{chain::ChainId, transaction::InvokeTx, Felt};
use katana_rpc_types::transaction::{BroadcastedInvokeTx, BroadcastedTx};
use num::{BigInt, Num};
use serde_json::Value;
use stark_vrf::{generate_public_key, BaseField, StarkVRF};
use starknet::{
    accounts::Account,
    core::types::{
        BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1,
        BroadcastedInvokeTransactionV3,
    },
    macros::{selector, short_string},
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
                                let seed = request_random_calls[0].calldata[0];

                                let submit_random_call =
                                    build_submit_random_call(seed, args.clone());
                                let assert_consumed_call = build_assert_consumed_call(seed, args.clone());

                                let mut calls = get_calls(invoke);
                                calls.insert(0, submit_random_call);
                                calls.push(assert_consumed_call);

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
                            let seed = request_random_calls[0].calldata[0];
                            let submit_random_call = build_submit_random_call(seed, args.clone());
                            let asssert_consumed_call = build_assert_consumed_call(seed, args.clone());

                            let account = args.get_account();

                            let submit_random_result = account
                                .execute_v1(vec![starknet::core::types::Call {
                                    to: submit_random_call.to,
                                    selector: submit_random_call.selector,
                                    calldata: submit_random_call.calldata,
                                }])
                                .send()
                                .await;

                            warn!("submit_random: {:?}", submit_random_result);
                            sleep(Duration::from_millis(50)).await;

                            req = Request::from_parts(parts, Body::from(bytes));
                            *req.uri_mut() = Uri::try_from(uri).unwrap();
                            let client_execution = state
                                .client
                                .request(req)
                                .await
                                .map_err(|_| StatusCode::BAD_REQUEST)?
                                ;

                            let assert_consumed_result = account
                                .execute_v1(vec![starknet::core::types::Call {
                                    to: asssert_consumed_call.to,
                                    selector: asssert_consumed_call.selector,
                                    calldata: asssert_consumed_call.calldata,
                                }])
                                .send()
                                .await;
                            warn!("assert_consumed_result: {:?}", assert_consumed_result);

                            return Ok(client_execution.into_response());
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

pub fn build_submit_random_call(seed: Felt, args: Args) -> Call {
    let proof = get_proof(seed);

    Call {
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
    }
}

pub fn build_assert_consumed_call(seed: Felt, args: Args) -> Call {
    Call {
        to: args.vrf_provider_address,
        selector: selector!("assert_consumed"),
        calldata: vec![seed],
    }
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
