//! Mock for Xion's native ZK module (`xion.zk.v1`).
//!
//! Handles the proof verification endpoints:
//! - `/xion.zk.v1.Query/ProofVerify` — circom/SnarkJS format (legacy live test)
//! - `/xion.zk.v1.Query/ProofVerifyUltraHonk` — Noir/bb UltraHonk (current)

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

// ── UltraHonk endpoint (Noir/bb, current) ──────────────────────────

/// xion.zk.v1.QueryVerifyUltraHonkRequest
/// `public_inputs` is the packed 672-byte / 21-field dcap-noir blob (raw
/// concatenated 32-byte big-endian BN254 field elements).
#[derive(Clone, PartialEq, Message)]
pub struct QueryVerifyUltraHonkRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub proof: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_inputs: Vec<u8>,
    #[prost(string, tag = "3")]
    pub vkey_name: String,
    #[prost(uint64, tag = "4")]
    pub vkey_id: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub expected_vkey_sha256: Vec<u8>,
}

/// xion.zk.v1.ProofVerifyUltraHonkResponse
#[derive(Clone, PartialEq, Message)]
pub struct ProofVerifyUltraHonkResponse {
    #[prost(bool, tag = "1")]
    pub verified: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub vkey_sha256: Vec<u8>,
}

// ── Mock handler ───────────────────────────────────────────────────

const ZK_VERIFY_PATH: &str = "/xion.zk.v1.Query/ProofVerify";
const ZK_VERIFY_ULTRAHONK_PATH: &str = "/xion.zk.v1.Query/ProofVerifyUltraHonk";
pub const TEST_ULTRAHONK_VKEY_SHA256: [u8; 32] = [0x42; 32];

/// Mock Stargate handler that intercepts Xion ZK module queries.
#[derive(Clone)]
pub struct ZkMockStargate {
    pub always_verify: bool,
    pub validate_structure: bool,
    ultrahonk_response_vkey_sha256: Option<[u8; 32]>,
}

impl ZkMockStargate {
    /// Accept any non-empty proof
    pub fn accepting() -> Self {
        Self {
            always_verify: true,
            validate_structure: false,
            ultrahonk_response_vkey_sha256: Some(TEST_ULTRAHONK_VKEY_SHA256),
        }
    }

    /// Reject everything
    #[allow(dead_code)]
    pub fn rejecting() -> Self {
        Self {
            always_verify: false,
            validate_structure: false,
            ultrahonk_response_vkey_sha256: Some(TEST_ULTRAHONK_VKEY_SHA256),
        }
    }

    /// Validate proof structure before accepting
    pub fn validating() -> Self {
        Self {
            always_verify: true,
            validate_structure: true,
            ultrahonk_response_vkey_sha256: Some(TEST_ULTRAHONK_VKEY_SHA256),
        }
    }

    /// Override response tag 2. `None` models an older Xion server that omits
    /// `vkey_sha256`; a different digest models a mismatched response.
    pub fn with_ultrahonk_response_vkey_sha256(mut self, sha256: Option<[u8; 32]>) -> Self {
        self.ultrahonk_response_vkey_sha256 = sha256;
        self
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

    /// Handle Noir/bb ProofVerifyUltraHonk
    fn handle_proof_verify_ultrahonk(&self, data: &[u8]) -> StdResult<Binary> {
        let req = QueryVerifyUltraHonkRequest::decode(data)
            .map_err(|e| StdError::msg(format!("decode QueryVerifyUltraHonkRequest: {e}")))?;

        if req.expected_vkey_sha256 != TEST_ULTRAHONK_VKEY_SHA256 {
            return Err(StdError::msg("verification key hash mismatch"));
        }

        if req.proof.is_empty() {
            return Ok(Binary::from(encode_ultrahonk_response(
                false,
                self.ultrahonk_response_vkey_sha256,
            )));
        }

        if !self.always_verify {
            return Ok(Binary::from(encode_ultrahonk_response(
                false,
                self.ultrahonk_response_vkey_sha256,
            )));
        }

        if self.validate_structure {
            // UltraHonk proofs are large; a real bb proof is multiple KB. Just
            // sanity-check it's not a stub.
            if req.proof.len() < 64 {
                return Ok(Binary::from(encode_ultrahonk_response(
                    false,
                    self.ultrahonk_response_vkey_sha256,
                )));
            }

            // public_inputs MUST be the packed 672-byte / 21-field dcap-noir blob.
            if req.public_inputs.len() != quartz_zkdcap::ULTRAHONK_PUBLIC_INPUTS_LEN {
                return Ok(Binary::from(encode_ultrahonk_response(
                    false,
                    self.ultrahonk_response_vkey_sha256,
                )));
            }

            if req.vkey_name.is_empty() && req.vkey_id == 0 {
                return Ok(Binary::from(encode_ultrahonk_response(
                    false,
                    self.ultrahonk_response_vkey_sha256,
                )));
            }
        }

        Ok(Binary::from(encode_ultrahonk_response(
            true,
            self.ultrahonk_response_vkey_sha256,
        )))
    }

    pub fn dispatch(&self, path: &str, data: &[u8]) -> StdResult<Binary> {
        match path {
            ZK_VERIFY_PATH => self.handle_proof_verify(data),
            ZK_VERIFY_ULTRAHONK_PATH => self.handle_proof_verify_ultrahonk(data),
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

fn encode_ultrahonk_response(verified: bool, vkey_sha256: Option<[u8; 32]>) -> Vec<u8> {
    let resp = ProofVerifyUltraHonkResponse {
        verified,
        vkey_sha256: vkey_sha256.map(Vec::from).unwrap_or_default(),
    };
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
