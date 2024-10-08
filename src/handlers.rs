use crate::{utils, ServerState, StarkVrfProof, StarkVrfRequest};
use axum::{
    extract::{self, State},
    Json,
};
use num::{BigInt, Num};
use serde::{Deserialize, Serialize};
use stark_vrf::{generate_public_key, BaseField, StarkVRF};
use std::str::FromStr;
use tracing::debug;

//
//
//

pub async fn health() -> &'static str {
    "OK"
}

//
//
//

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonResult {
    pub result: StarkVrfProof,
}

// State(state): State<ServerState>,
// mut req: Request,
pub async fn stark_vrf(
    State(state): State<ServerState>,
    extract::Json(payload): extract::Json<StarkVrfRequest>,
) -> Json<JsonResult> {
    debug!("received payload {payload:?}");
    let secret_key = state.args.get_secret_key();
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
        gamma_x: utils::format(proof.0.x),
        gamma_y: utils::format(proof.0.y),
        c: utils::format(proof.1),
        s: utils::format(proof.2),
        sqrt_ratio: utils::format(sqrt_ratio_hint),
        rnd: utils::format(rnd),
    };

    println!("result {result:?}");

    //let n = (payload.n as f64).sqrt() as u64;
    Json(JsonResult { result })
}

//
//
//

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResult {
    pub public_key_x: String,
    pub public_key_y: String,
}

pub async fn vrf_info(State(state): State<ServerState>) -> Json<InfoResult> {
    let secret_key = state.args.get_secret_key();
    let public_key = generate_public_key(secret_key.parse().unwrap());

    Json(InfoResult {
        public_key_x: utils::format(public_key.x),
        public_key_y: utils::format(public_key.y),
    })
}
