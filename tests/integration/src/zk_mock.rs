//! Mock for Xion's native ZK module (`xion.zk.v1`).
//!
//! Intercepts `QueryRequest::Grpc` calls to `/xion.zk.v1.Query/ProofVerify`
//! in cw_multi_test, simulating the chain's Groth16 verification.
//!
//! NOTE: Xion v29 also has `/xion.zk.v1.Query/ProofVerifyGnark` for gnark
//! native binary format. The zkdcap verifier will migrate to that endpoint.

use cosmwasm_std::{Addr, Api, Binary, BlockInfo, CustomMsg, CustomQuery, GrpcQuery, Querier, StdError, StdResult, Storage};
use cw_multi_test::{AppResponse, CosmosRouter, Stargate};
use prost::Message;
use serde::de::DeserializeOwned;

/// Protobuf: xion.zk.v1.QueryVerifyRequest
#[derive(Clone, PartialEq, Message)]
pub struct QueryVerifyRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub proof: Vec<u8>,
    #[prost(string, repeated, tag = "2")]
    pub public_inputs: Vec<String>,
    #[prost(string, tag = "3")]
    pub vkey_name: String,
    #[prost(uint64, tag = "4")]
    pub vkey_id: u64,
}

/// Protobuf: xion.zk.v1.ProofVerifyResponse
#[derive(Clone, PartialEq, Message)]
pub struct ProofVerifyResponse {
    #[prost(bool, tag = "1")]
    pub verified: bool,
}

const ZK_VERIFY_PATH: &str = "/xion.zk.v1.Query/ProofVerify";

/// Mock Stargate handler that intercepts Xion ZK module queries.
#[derive(Clone)]
pub struct ZkMockStargate {
    pub always_verify: bool,
}

impl ZkMockStargate {
    pub fn accepting() -> Self {
        Self { always_verify: true }
    }

    #[allow(dead_code)]
    pub fn rejecting() -> Self {
        Self { always_verify: false }
    }

    fn handle_proof_verify(&self, data: &[u8]) -> StdResult<Binary> {
        let req = QueryVerifyRequest::decode(data)
            .map_err(|e| StdError::msg(format!("decode QueryVerifyRequest: {e}")))?;

        if req.proof.is_empty() {
            return Ok(Binary::from(encode_response(false)));
        }

        Ok(Binary::from(encode_response(self.always_verify)))
    }
}

fn encode_response(verified: bool) -> Vec<u8> {
    let resp = ProofVerifyResponse { verified };
    let mut buf = Vec::new();
    resp.encode(&mut buf).expect("prost encode");
    buf
}

impl Stargate for ZkMockStargate {
    fn execute_stargate<ExecC, QueryC>(
        &self,
        _api: &dyn Api,
        _storage: &mut dyn Storage,
        _router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        _block: &BlockInfo,
        _sender: Addr,
        _type_url: String,
        _value: Binary,
    ) -> StdResult<AppResponse>
    where
        ExecC: CustomMsg + DeserializeOwned + 'static,
        QueryC: CustomQuery + DeserializeOwned + 'static,
    {
        Ok(AppResponse::default())
    }

    fn query_stargate(
        &self,
        _api: &dyn Api,
        _storage: &dyn Storage,
        _querier: &dyn Querier,
        _block: &BlockInfo,
        path: String,
        data: Binary,
    ) -> StdResult<Binary> {
        if path == ZK_VERIFY_PATH {
            return self.handle_proof_verify(&data);
        }
        Err(StdError::msg(format!("unexpected stargate query: {path}")))
    }

    fn execute_any<ExecC, QueryC>(
        &self,
        _api: &dyn Api,
        _storage: &mut dyn Storage,
        _router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        _block: &BlockInfo,
        _sender: Addr,
        _msg: cosmwasm_std::AnyMsg,
    ) -> StdResult<AppResponse>
    where
        ExecC: CustomMsg + DeserializeOwned + 'static,
        QueryC: CustomQuery + DeserializeOwned + 'static,
    {
        Ok(AppResponse::default())
    }

    fn query_grpc(
        &self,
        _api: &dyn Api,
        _storage: &dyn Storage,
        _querier: &dyn Querier,
        _block: &BlockInfo,
        request: GrpcQuery,
    ) -> StdResult<Binary> {
        if request.path == ZK_VERIFY_PATH {
            return self.handle_proof_verify(&request.data);
        }
        Err(StdError::msg(format!("unexpected gRPC query: {}", request.path)))
    }
}
