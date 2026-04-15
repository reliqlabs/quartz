//! Mock for Xion's native ZK module (`xion.zk.v1`).
//!
//! Intercepts gRPC queries to `/xion.zk.v1.Query/ProofVerify` and validates:
//! 1. Proof bytes are valid SnarkJS-format Groth16 JSON
//! 2. Proof has pi_a, pi_b, pi_c fields and protocol="groth16"
//! 3. Public inputs are present
//!
//! Does NOT perform the actual BN254 pairing check — that requires
//! ark-groth16 or the real Xion module. This mock validates the
//! serialization pipeline is correct.

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
    /// If true, structurally valid proofs pass. If false, everything fails.
    pub always_verify: bool,
    /// If true, validate proof JSON structure. If false, accept any non-empty proof.
    pub validate_structure: bool,
}

impl ZkMockStargate {
    /// Accept any non-empty proof (for handshake tests that use MockAttestation)
    pub fn accepting() -> Self {
        Self {
            always_verify: true,
            validate_structure: false,
        }
    }

    /// Reject everything (for testing error paths)
    #[allow(dead_code)]
    pub fn rejecting() -> Self {
        Self {
            always_verify: false,
            validate_structure: false,
        }
    }

    /// Validate proof structure before accepting (for zkdcap integration tests)
    pub fn validating() -> Self {
        Self {
            always_verify: true,
            validate_structure: true,
        }
    }

    fn handle_proof_verify(&self, data: &[u8]) -> StdResult<Binary> {
        let req = QueryVerifyRequest::decode(data)
            .map_err(|e| StdError::msg(format!("decode QueryVerifyRequest: {e}")))?;

        if req.proof.is_empty() {
            return Ok(Binary::from(encode_response(false)));
        }

        if !self.always_verify {
            return Ok(Binary::from(encode_response(false)));
        }

        if self.validate_structure {
            // Parse proof as SnarkJS JSON and validate structure
            let proof_json: serde_json::Value = serde_json::from_slice(&req.proof)
                .map_err(|e| StdError::msg(format!("proof is not valid JSON: {e}")))?;

            let has_pi_a = proof_json.get("pi_a").is_some();
            let has_pi_b = proof_json.get("pi_b").is_some();
            let has_pi_c = proof_json.get("pi_c").is_some();
            let has_protocol = proof_json
                .get("protocol")
                .and_then(|v| v.as_str())
                .map(|s| s == "groth16")
                .unwrap_or(false);

            if !has_pi_a || !has_pi_b || !has_pi_c || !has_protocol {
                return Ok(Binary::from(encode_response(false)));
            }

            // Validate public inputs are present
            if req.public_inputs.is_empty() {
                return Ok(Binary::from(encode_response(false)));
            }

            // Validate vkey name is provided
            if req.vkey_name.is_empty() && req.vkey_id == 0 {
                return Ok(Binary::from(encode_response(false)));
            }
        }

        Ok(Binary::from(encode_response(true)))
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
