//! Mock for Xion's native ZK module (`xion.zk.v1`).
//!
//! Handles both proof verification endpoints:
//! - `/xion.zk.v1.Query/ProofVerify` — circom/SnarkJS format (current)
//! - `/xion.zk.v1.Query/ProofVerifyGnark` — gnark native binary format (v29+)

use cosmwasm_std::{
    Addr, Api, Binary, BlockInfo, CustomMsg, CustomQuery, GrpcQuery, Querier, StdError, StdResult,
    Storage,
};
use cw_multi_test::{AppResponse, CosmosRouter, Stargate};
use prost::Message;
use serde::de::DeserializeOwned;

// ── Circom/SnarkJS endpoint (current zkdcap verifier) ──────────────

/// xion.zk.v1.QueryVerifyRequest (circom format)
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

/// xion.zk.v1.ProofVerifyResponse
#[derive(Clone, PartialEq, Message)]
pub struct ProofVerifyResponse {
    #[prost(bool, tag = "1")]
    pub verified: bool,
}

// ── gnark native endpoint (v29+) ───────────────────────────────────

/// xion.zk.v1.QueryVerifyGnarkRequest
/// proof and public_inputs are gnark native binary format.
/// public_inputs: concatenated 32-byte big-endian fr.Element values.
#[derive(Clone, PartialEq, Message)]
pub struct QueryVerifyGnarkRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub proof: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_inputs: Vec<u8>,
    #[prost(string, tag = "3")]
    pub vkey_name: String,
    #[prost(uint64, tag = "4")]
    pub vkey_id: u64,
}

/// xion.zk.v1.ProofVerifyGnarkResponse
#[derive(Clone, PartialEq, Message)]
pub struct ProofVerifyGnarkResponse {
    #[prost(bool, tag = "1")]
    pub verified: bool,
}

// ── Mock handler ───────────────────────────────────────────────────

const ZK_VERIFY_PATH: &str = "/xion.zk.v1.Query/ProofVerify";
const ZK_VERIFY_GNARK_PATH: &str = "/xion.zk.v1.Query/ProofVerifyGnark";

/// Mock Stargate handler that intercepts Xion ZK module queries.
#[derive(Clone)]
pub struct ZkMockStargate {
    pub always_verify: bool,
    pub validate_structure: bool,
}

impl ZkMockStargate {
    /// Accept any non-empty proof
    pub fn accepting() -> Self {
        Self {
            always_verify: true,
            validate_structure: false,
        }
    }

    /// Reject everything
    #[allow(dead_code)]
    pub fn rejecting() -> Self {
        Self {
            always_verify: false,
            validate_structure: false,
        }
    }

    /// Validate proof structure before accepting
    pub fn validating() -> Self {
        Self {
            always_verify: true,
            validate_structure: true,
        }
    }

    /// Handle circom/SnarkJS ProofVerify
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
            let proof_json: serde_json::Value = serde_json::from_slice(&req.proof)
                .map_err(|e| StdError::msg(format!("proof is not valid JSON: {e}")))?;

            let valid = proof_json.get("pi_a").is_some()
                && proof_json.get("pi_b").is_some()
                && proof_json.get("pi_c").is_some()
                && proof_json
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "groth16")
                    .unwrap_or(false);

            if !valid {
                return Ok(Binary::from(encode_response(false)));
            }

            if req.public_inputs.is_empty() || (req.vkey_name.is_empty() && req.vkey_id == 0) {
                return Ok(Binary::from(encode_response(false)));
            }
        }

        Ok(Binary::from(encode_response(true)))
    }

    /// Handle gnark native ProofVerifyGnark
    fn handle_proof_verify_gnark(&self, data: &[u8]) -> StdResult<Binary> {
        let req = QueryVerifyGnarkRequest::decode(data)
            .map_err(|e| StdError::msg(format!("decode QueryVerifyGnarkRequest: {e}")))?;

        if req.proof.is_empty() {
            return Ok(Binary::from(encode_gnark_response(false)));
        }

        if !self.always_verify {
            return Ok(Binary::from(encode_gnark_response(false)));
        }

        if self.validate_structure {
            // gnark proof: must be non-empty binary (serialized groth16.Proof)
            // Typical BN254 Groth16 proof is ~384 bytes (3 curve points)
            if req.proof.len() < 96 {
                return Ok(Binary::from(encode_gnark_response(false)));
            }

            // public_inputs: concatenated 32-byte field elements
            if req.public_inputs.is_empty() || req.public_inputs.len() % 32 != 0 {
                return Ok(Binary::from(encode_gnark_response(false)));
            }

            if req.vkey_name.is_empty() && req.vkey_id == 0 {
                return Ok(Binary::from(encode_gnark_response(false)));
            }
        }

        Ok(Binary::from(encode_gnark_response(true)))
    }

    pub fn dispatch(&self, path: &str, data: &[u8]) -> StdResult<Binary> {
        match path {
            ZK_VERIFY_PATH => self.handle_proof_verify(data),
            ZK_VERIFY_GNARK_PATH => self.handle_proof_verify_gnark(data),
            _ => Err(StdError::msg(format!("unexpected ZK query path: {path}"))),
        }
    }
}

fn encode_response(verified: bool) -> Vec<u8> {
    let resp = ProofVerifyResponse { verified };
    let mut buf = Vec::new();
    resp.encode(&mut buf).expect("prost encode");
    buf
}

fn encode_gnark_response(verified: bool) -> Vec<u8> {
    let resp = ProofVerifyGnarkResponse { verified };
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
        self.dispatch(&path, &data)
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
        self.dispatch(&request.path, &request.data)
    }
}
