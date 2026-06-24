//! CosmWasm adapter: UltraHonk verification via Xion
//! `/xion.zk.v1.Query/ProofVerifyUltraHonk`.

use cosmwasm_std::QuerierWrapper;
use prost::Message;

use crate::ProofBackend;

#[derive(Clone, PartialEq, prost::Message)]
struct QueryVerifyUltraHonkRequest {
    #[prost(bytes = "vec", tag = "1")]
    proof: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    public_inputs: Vec<u8>,
    #[prost(string, tag = "3")]
    vkey_name: String,
    #[prost(uint64, tag = "4")]
    vkey_id: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ProofVerifyUltraHonkResponse {
    #[prost(bool, tag = "1")]
    verified: bool,
}

/// [`ProofBackend`] that resolves a vkey from the x/zk store and verifies the
/// proof on-chain. `vkey_id` 0 means "resolve by name" (the usual path; matches
/// the deployed `dcap-ultrahonk-v1`).
pub struct XionUltraHonkBackend<'a> {
    pub querier: QuerierWrapper<'a>,
    pub vkey_name: String,
    pub vkey_id: u64,
}

impl<'a> XionUltraHonkBackend<'a> {
    /// Resolve the vkey by name (`vkey_id` 0).
    pub fn by_name(querier: QuerierWrapper<'a>, vkey_name: String) -> Self {
        Self {
            querier,
            vkey_name,
            vkey_id: 0,
        }
    }
}

impl ProofBackend for XionUltraHonkBackend<'_> {
    fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> bool {
        // UltraHonk public_inputs go on the wire as raw concatenated 32-byte
        // big-endian field elements (what `bb prove` emits) — NO gnark
        // nbPublic/nbSecret/vec_len witness header.
        let req = QueryVerifyUltraHonkRequest {
            proof: proof.to_vec(),
            public_inputs: public_inputs.to_vec(),
            vkey_name: self.vkey_name.clone(),
            vkey_id: self.vkey_id,
        };
        let mut req_bytes = Vec::new();
        if req.encode(&mut req_bytes).is_err() {
            return false;
        }
        // query_grpc (raw bytes): a JSON-decoding querier path would choke on
        // the proto response bytes.
        match self.querier.query_grpc(
            "/xion.zk.v1.Query/ProofVerifyUltraHonk".to_string(),
            cosmwasm_std::Binary::new(req_bytes),
        ) {
            Ok(resp) => ProofVerifyUltraHonkResponse::decode(resp.as_slice())
                .map(|r| r.verified)
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}
