mod oracle;

use axum::{
    async_trait,
    body::Body,
    extract::{self, FromRequest, Request, State},
    http::HeaderValue,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestExt, Router,
};
use cainome_cairo_serde::{call, CairoSerde};
use clap::Parser;
use http_body_util::BodyExt;
use hyper::{header::CONTENT_TYPE, Method, StatusCode, Uri};
use katana_primitives::{block::BlockTag, chain::ChainId, felt, transaction::InvokeTx, Felt};
use num::{BigInt, Num};
use oracle::*;
use serde::{Deserialize, Serialize};
use stark_vrf::{generate_public_key, BaseField, StarkVRF};
use starknet::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::{
        chain_id,
        types::{BlockId, BroadcastedInvokeTransaction, BroadcastedTransaction, SimulationFlag},
    },
    macros::{selector, short_string},
    providers::{Provider, Url},
    signers::{LocalWallet, SigningKey},
};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::{signal, time::sleep};
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;

use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient};

use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    /// Secret key
    #[arg(short, long, /*required = true,*/ default_value = "1056")] // 0x420
    secret_key: u64,

    /// Secret key
    #[arg(short, long, default_value = "8888")]
    port: u64,

    /// Vrf provider
    #[arg(
        short,
        long,
        default_value = "0x061ea5f7ebeed84fa95b19d53d362ec786620953a99b298fe25925abb145e377"
    )]
    vrf_provider_address: Felt,

    /// RPC
    #[arg(short, long, default_value = "http://localhost:5050")]
    rpc: Url,

    #[arg(
        short,
        long,
        default_value = "0x1c9053c053edf324aec366a34c6901b1095b07af69495bffec7d7fe21effb1b"
    )]
    private_key: Felt,

    #[arg(
        short,
        long,
        default_value = "0x6b86e40118f29ebe393a75469b4d926c7a44c2e2681b6d319520b7c1156d114"
    )]
    address: Felt,
}

fn format<T: std::fmt::Display>(v: T) -> String {
    let int = BigInt::from_str(&format!("{v}")).unwrap();
    format!("0x{}", int.to_str_radix(16))
}

#[derive(Debug, Serialize, Deserialize)]
struct InfoResult {
    public_key_x: String,
    public_key_y: String,
}

fn get_secret_key() -> String {
    let args = Args::parse();
    args.secret_key.to_string()
}

async fn vrf_info() -> Json<InfoResult> {
    let secret_key = get_secret_key();
    let public_key = generate_public_key(secret_key.parse().unwrap());

    Json(InfoResult {
        public_key_x: format(public_key.x),
        public_key_y: format(public_key.y),
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonResult {
    result: StarkVrfProof,
}

async fn stark_vrf(extract::Json(payload): extract::Json<StarkVrfRequest>) -> Json<JsonResult> {
    debug!("received payload {payload:?}");
    let secret_key = get_secret_key();
    let public_key = generate_public_key(secret_key.parse().unwrap());

    println!("public key {public_key}");

    let seed: Vec<_> = payload
        .seed
        .iter()
        .map(|x| {
            let dec_string = BigInt::from_str_radix(&x[2..], 16).unwrap().to_string();
            println!("seed string {dec_string}");
            BaseField::from_str(&dec_string).unwrap()
        })
        .collect();

    let ecvrf = StarkVRF::new(public_key).unwrap();
    let proof = ecvrf
        .prove(&secret_key.parse().unwrap(), seed.as_slice())
        .unwrap();
    let sqrt_ratio_hint = ecvrf.hash_to_sqrt_ratio_hint(seed.as_slice());
    let rnd = ecvrf.proof_to_hash(&proof).unwrap();

    println!("proof gamma: {}", proof.0);
    println!("proof c: {}", proof.1);
    println!("proof s: {}", proof.2);
    println!("proof verify hint: {}", sqrt_ratio_hint);

    let result = StarkVrfProof {
        gamma_x: format(proof.0.x),
        gamma_y: format(proof.0.y),
        c: format(proof.1),
        s: format(proof.2),
        sqrt_ratio: format(sqrt_ratio_hint),
        rnd: format(rnd),
    };

    println!("result {result:?}");

    //let n = (payload.n as f64).sqrt() as u64;
    Json(JsonResult { result })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    async fn index() -> &'static str {
        "OK"
    }

    let client: Client =
        hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

    let app = Router::new()
        .route("/", get(handler))
        .route("/", post(handler))
        // .route("/info", get(vrf_info))
        // .route("/stark_vrf", post(stark_vrf))
        // .route("/", get(index))
        // .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin("*".parse::<HeaderValue>().unwrap())
                .allow_headers(Any)
                .allow_methods([Method::GET, Method::POST]),
        )
        .with_state((args.clone(), client));
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .expect("Failed to bind to port 3000, port already in use by another process. Change the port or terminate the other process.");

    debug!("Server started on http://0.0.0.0:{}", args.port);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

use cainome_cairo_serde_derive::CairoSerde;
/// A contract call as part of a multi-call execution request.
#[derive(Debug, Clone, CairoSerde)]
pub struct Call {
    /// Address of the contract being invoked.
    pub to: Felt,
    /// Entrypoint selector of the function being invoked.
    pub selector: Felt,
    /// List of calldata to be sent for the call.
    pub calldata: Vec<Felt>,
}

use katana_rpc_types::transaction::BroadcastedInvokeTx;
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: RpcParams,
    id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcParams {
    invoke_transaction: BroadcastedInvokeTx,
}

#[async_trait]
impl<S> FromRequest<S> for RpcRequest
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?;

        if content_type.starts_with("application/json") {
            let Json(payload) = req
                .extract::<Json<RpcRequest>, _>()
                .await
                .map_err(|err| err.into_response())?;

            Ok(payload)
        } else {
            Err(StatusCode::BAD_REQUEST.into_response())
        }
    }
}

async fn handler(
    State((args, client)): State<(Args, Client)>,
    mut req: Request,
) -> Result<Response, StatusCode> {
    // println!(">>> request: {:?}", req);

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
            let (parts, body) = req.into_parts();

            // this won't work if the body is an long running stream
            let bytes = body
                .collect()
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR))?
                .to_bytes();

            let reqclone = Request::from_parts(parts.clone(), Body::from(bytes.clone()));
            let extracted: Result<RpcRequest, _> = reqclone.extract().await;
            if let Ok(payload) = extracted {
                println!(">>> payload: {:#?}", payload);

                if payload.method == "starknet_addInvokeTransaction" {
                    let invoke = &payload
                        .params
                        .invoke_transaction
                        .clone()
                        .into_tx_with_chain_id(ChainId::Id(short_string!("KATANA")));

                    let (sender_address, calldata) = match invoke {
                        InvokeTx::V1(invoke_tx_v1) => {
                            (invoke_tx_v1.sender_address, invoke_tx_v1.calldata.clone())
                        }
                        InvokeTx::V3(invoke_tx_v3) => {
                            (invoke_tx_v3.sender_address, invoke_tx_v3.calldata.clone())
                        }
                    };

                    let calls = Vec::<Call>::cairo_deserialize(&calldata, 0).unwrap();

                    let request_random_calls: Vec<Call> = calls
                        .iter()
                        .filter(|c| {
                            c.to == args.vrf_provider_address
                                && c.selector == selector!("request_random")
                        })
                        .cloned()
                        .collect();

                    if request_random_calls.len() > 0 {
                        println!(">>> calls: {:#?}", calls);
                        // sleep(Duration::from_secs(2)).await;
                        println!(">>> request_random_calls: {:#?}", request_random_calls);
                        println!(">>> sent by : {:#?}", sender_address);

                        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(args.rpc)));

                        let signer =
                            LocalWallet::from(SigningKey::from_secret_scalar(args.private_key));

                        let mut account = SingleOwnerAccount::new(
                            provider.clone(),
                            signer,
                            args.address,
                            short_string!("KATANA"),
                            ExecutionEncoding::New,
                        );

                        account
                            .set_block_id(starknet::core::types::BlockId::Tag(BlockTag::Pending));

                        // create new tx & calldata with only request_random
                        let mut calldata = vec![
                            felt!("0x1"),
                            request_random_calls[0].to,
                            request_random_calls[0].selector,
                            request_random_calls[0].calldata.len().into(),
                        ];
                        calldata.append(request_random_calls[0].calldata.clone().as_mut());
                        let tx = invoke_tx_to_broadcasted_invoke_tx(&invoke, &calldata);

                        println!("{:?}", tx);

                        let simulation_flags = SimulationFlag::SkipValidate;
                        let simulation = provider
                            .clone()
                            .simulate_transaction(
                                BlockId::Tag(BlockTag::Pending),
                                BroadcastedTransaction::Invoke(tx),
                                vec![simulation_flags],
                            )
                            .await
                            .unwrap();

                        // println!("simulation: {:#?}", simulation);

                        match simulation.transaction_trace {
                            starknet::core::types::TransactionTrace::Invoke(
                                invoke_transaction_trace,
                            ) => match invoke_transaction_trace.execute_invocation {
                                starknet::core::types::ExecuteInvocation::Success(
                                    function_invocation,
                                ) => {
                                    if let Some(event) = function_invocation
                                        .calls
                                        .first()
                                        .unwrap()
                                        .events
                                        .iter()
                                        .find(|e| e.keys[0] == selector!("RequestRandom"))
                                    {
                                        println!("event: {:?}", event);
                                        // const seed = event.data[event.data.length - 1];
                                        let seed = event.data[event.data.len() - 1];
                                        println!("seed: {}", seed);

                                        let proof = get_proof(seed);
                                        println!("proof: {:?}", proof);

                                        let front_run_call = starknet::core::types::Call {
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

                                        let front_run_result =
                                            account.execute_v1(vec![front_run_call]).send().await;

                                        println!("front_run_result: {:?}", front_run_result);
                                        sleep(Duration::from_millis(100)).await;
                                    }
                                }
                                starknet::core::types::ExecuteInvocation::Reverted(_) => {}
                            },
                            _ => {}
                        }
                    }
                }
            } else {
                eprintln!("{}", "not invoke tx");
            }

            req = Request::from_parts(parts, Body::from(bytes));
        }
    }

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    Ok(client
        .request(req)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .into_response())
}

pub fn get_proof(seed: Felt) -> StarkVrfProof {
    let secret_key = get_secret_key();
    let public_key = generate_public_key(secret_key.parse().unwrap());

    let seed: Vec<_> = vec![seed.to_hex_string()]
        .iter()
        .map(|x| {
            let dec_string = BigInt::from_str_radix(&x[2..], 16).unwrap().to_string();
            println!("seed string {dec_string}");
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
        gamma_x: format(proof.0.x),
        gamma_y: format(proof.0.y),
        c: format(proof.1),
        s: format(proof.2),
        sqrt_ratio: format(sqrt_ratio_hint),
        rnd: format(rnd),
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
                signature: invoke_tx_v1.signature.clone(),
                nonce: invoke_tx_v1.nonce,
                is_query: false, // ?
            },
        ),
        InvokeTx::V3(invoke_tx_v3) => BroadcastedInvokeTransaction::V3(
            starknet::core::types::BroadcastedInvokeTransactionV3 {
                sender_address: invoke_tx_v3.sender_address.into(),
                calldata: request_random_calldata.to_vec(),
                signature: invoke_tx_v3.signature.clone(),
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
    // &payload.params.invoke_transaction.clone(),
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
