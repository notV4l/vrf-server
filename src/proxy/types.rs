use axum::{
    async_trait,
    extract::{FromRequest, Request},
    response::{IntoResponse, Response},
    Json, RequestExt,
};
use cainome_cairo_serde_derive::CairoSerde;
use katana_primitives::{block::BlockIdOrTag, Felt};
use katana_rpc_types::{
    transaction::{BroadcastedInvokeTx, BroadcastedTx},
    SimulationFlagForEstimateFee,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, CairoSerde)]
pub struct Call {
    /// Address of the contract being invoked.
    pub to: Felt,
    /// Entrypoint selector of the function being invoked.
    pub selector: Felt,
    /// List of calldata to be sent for the call.
    pub calldata: Vec<Felt>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest<T> {
    pub jsonrpc: String,
    pub method: String,
    pub params: T,
    pub id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcParamsInvoke {
    pub invoke_transaction: BroadcastedInvokeTx,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcParamsEstimate {
    pub request: Vec<BroadcastedTx>,
    pub simulation_flags: Vec<SimulationFlagForEstimateFee>,
    pub block_id: BlockIdOrTag,
}

//
//
//

#[async_trait]
impl<S> FromRequest<S> for RpcRequest<Value>
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let Json(payload) = req
            .extract::<Json<RpcRequest<Value>>, _>()
            .await
            .map_err(|err| err.into_response())?;

        Ok(payload)
    }
}

#[async_trait]
impl<S> FromRequest<S> for RpcRequest<RpcParamsEstimate>
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let Json(payload) = req
            .extract::<Json<RpcRequest<RpcParamsEstimate>>, _>()
            .await
            .map_err(|err| err.into_response())?;

        Ok(payload)
    }
}

#[async_trait]
impl<S> axum::extract::FromRequest<S> for RpcRequest<RpcParamsInvoke>
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let Json(payload) = req
            .extract::<Json<RpcRequest<RpcParamsInvoke>>, _>()
            .await
            .map_err(|err| err.into_response())?;

        Ok(payload)
    }
}
