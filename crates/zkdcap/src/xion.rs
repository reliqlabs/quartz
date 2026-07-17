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
    #[prost(bytes = "vec", tag = "5")]
    expected_vkey_sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ProofVerifyUltraHonkResponse {
    #[prost(bool, tag = "1")]
    verified: bool,
    #[prost(bytes = "vec", tag = "2")]
    vkey_sha256: Vec<u8>,
}

/// [`ProofBackend`] that resolves a vkey from the x/zk store and verifies the
/// proof on-chain. Every supported constructor requires the SHA-256 digest of
/// the exact stored verification-key bytes. The request sends that pin and the
/// response must echo it, so an older Xion server that ignores request tag 5
/// and omits response tag 2 fails closed.
pub struct XionUltraHonkBackend<'a> {
    querier: QuerierWrapper<'a>,
    vkey_name: String,
    vkey_id: u64,
    expected_vkey_sha256: [u8; 32],
}

impl<'a> XionUltraHonkBackend<'a> {
    /// Resolve the vkey by name (`vkey_id` 0).
    pub fn by_name(
        querier: QuerierWrapper<'a>,
        vkey_name: String,
        expected_vkey_sha256: [u8; 32],
    ) -> Self {
        Self {
            querier,
            vkey_name,
            vkey_id: 0,
            expected_vkey_sha256,
        }
    }

    /// Resolve the vkey by numeric ID.
    pub fn by_id(
        querier: QuerierWrapper<'a>,
        vkey_id: u64,
        expected_vkey_sha256: [u8; 32],
    ) -> Self {
        Self {
            querier,
            vkey_name: String::new(),
            vkey_id,
            expected_vkey_sha256,
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
            expected_vkey_sha256: self.expected_vkey_sha256.to_vec(),
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
                .map(|r| {
                    r.verified && r.vkey_sha256.as_slice() == self.expected_vkey_sha256.as_slice()
                })
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use cosmwasm_std::{
        from_json, Binary, ContractResult, Empty, GrpcQuery, Querier, QuerierResult,
        QuerierWrapper, QueryRequest, SystemError, SystemResult,
    };

    use super::*;

    struct GrpcMock {
        response: Binary,
        captured_request: Rc<RefCell<Option<QueryVerifyUltraHonkRequest>>>,
    }

    impl Querier for GrpcMock {
        fn raw_query(&self, request: &[u8]) -> QuerierResult {
            let parsed: QueryRequest<Empty> = match from_json(request) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return SystemResult::Err(SystemError::InvalidRequest {
                        error: err.to_string(),
                        request: request.into(),
                    });
                }
            };
            let QueryRequest::Grpc(GrpcQuery { path, data }) = parsed else {
                return SystemResult::Err(SystemError::UnsupportedRequest {
                    kind: "non-gRPC query".to_string(),
                });
            };
            if path != "/xion.zk.v1.Query/ProofVerifyUltraHonk" {
                return SystemResult::Err(SystemError::UnsupportedRequest { kind: path });
            }
            let decoded = match QueryVerifyUltraHonkRequest::decode(data.as_slice()) {
                Ok(decoded) => decoded,
                Err(err) => {
                    return SystemResult::Err(SystemError::InvalidRequest {
                        error: err.to_string(),
                        request: data,
                    });
                }
            };
            self.captured_request.replace(Some(decoded));
            SystemResult::Ok(ContractResult::Ok(self.response.clone()))
        }
    }

    fn encoded_response(verified: bool, vkey_sha256: Vec<u8>) -> Binary {
        let response = ProofVerifyUltraHonkResponse {
            verified,
            vkey_sha256,
        };
        let mut encoded = Vec::new();
        response.encode(&mut encoded).unwrap();
        encoded.into()
    }

    fn verify_with_response(
        expected: [u8; 32],
        verified: bool,
        returned_hash: Vec<u8>,
    ) -> (bool, QueryVerifyUltraHonkRequest) {
        let captured_request = Rc::new(RefCell::new(None));
        let querier = GrpcMock {
            response: encoded_response(verified, returned_hash),
            captured_request: Rc::clone(&captured_request),
        };
        let backend = XionUltraHonkBackend::by_name(
            QuerierWrapper::new(&querier),
            "dcap-v1".into(),
            expected,
        );
        let accepted = backend.verify(&[1, 2, 3], &[4, 5, 6]);
        let request = captured_request
            .borrow_mut()
            .take()
            .expect("backend issued query");
        (accepted, request)
    }

    #[test]
    fn matching_verified_response_is_accepted_and_request_is_pinned() {
        let expected = [0x42; 32];
        let (accepted, request) = verify_with_response(expected, true, expected.to_vec());

        assert!(accepted);
        assert_eq!(request.expected_vkey_sha256, expected);
        assert_eq!(request.vkey_name, "dcap-v1");
        assert_eq!(request.vkey_id, 0);
    }

    #[test]
    fn verified_response_missing_hash_fails_closed() {
        let (accepted, _) = verify_with_response([0x42; 32], true, Vec::new());
        assert!(!accepted);
    }

    #[test]
    fn verified_response_with_mismatched_hash_fails_closed() {
        let (accepted, _) = verify_with_response([0x42; 32], true, vec![0x24; 32]);
        assert!(!accepted);
    }

    #[test]
    fn matching_hash_does_not_override_rejected_proof() {
        let expected = [0x42; 32];
        let (accepted, _) = verify_with_response(expected, false, expected.to_vec());
        assert!(!accepted);
    }
}
