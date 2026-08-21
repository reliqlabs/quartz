//! CosmWasm adapter: UltraHonk verification via Xion
//! `/xion.zk.v1.Query/ProofVerifyUltraHonk`.

use cosmwasm_std::QuerierWrapper;
use prost::Message;

use crate::{ProofBackend, VkeyTrust};

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

/// `/xion.zk.v1.Query/VKey`. Only reachable when the chain whitelists that path
/// for contract queries, which no release through `v30.0.0` did.
#[derive(Clone, PartialEq, prost::Message)]
struct QueryVKeyRequest {
    #[prost(uint64, tag = "1")]
    id: u64,
}

/// `/xion.zk.v1.Query/VKeyByName`, same availability caveat.
#[derive(Clone, PartialEq, prost::Message)]
struct QueryVKeyByNameRequest {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct VKey {
    #[prost(bytes = "vec", tag = "1")]
    key_bytes: Vec<u8>,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    description: String,
    #[prost(string, tag = "4")]
    circuit_hash: String,
    #[prost(string, tag = "5")]
    authority: String,
    #[prost(int32, tag = "6")]
    proof_system: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct QueryVKeyResponse {
    #[prost(message, optional, tag = "1")]
    vkey: Option<VKey>,
    #[prost(uint64, tag = "2")]
    id: u64,
}

/// [`ProofBackend`] that resolves a vkey from the x/zk store and verifies the
/// proof on-chain, enforcing the caller's [`VkeyTrust`] on the key's identity.
///
/// Every path fails closed. When the configured trust model cannot be checked
/// against the chain in front of it, this refuses rather than silently
/// downgrading to a weaker claim: a consumer that asked for byte identity and
/// got name-only resolution has been told something false.
pub struct XionUltraHonkBackend<'a> {
    querier: QuerierWrapper<'a>,
    vkey_name: String,
    vkey_id: u64,
    trust: VkeyTrust,
}

impl<'a> XionUltraHonkBackend<'a> {
    /// Resolve the vkey by name (`vkey_id` 0).
    pub fn by_name(querier: QuerierWrapper<'a>, vkey_name: String, trust: VkeyTrust) -> Self {
        Self {
            querier,
            vkey_name,
            vkey_id: 0,
            trust,
        }
    }

    /// Resolve the vkey by numeric ID.
    pub fn by_id(querier: QuerierWrapper<'a>, vkey_id: u64, trust: VkeyTrust) -> Self {
        Self {
            querier,
            vkey_name: String::new(),
            vkey_id,
            trust,
        }
    }

    /// Fetch the registry record. `Err(())` covers both a chain that does not
    /// whitelist the path for contracts and a malformed or absent record; the
    /// caller treats either as a refusal.
    fn fetch_vkey(&self) -> Result<VKey, ()> {
        let (path, body) = if self.vkey_name.is_empty() {
            (
                "/xion.zk.v1.Query/VKey",
                QueryVKeyRequest { id: self.vkey_id }.encode_to_vec(),
            )
        } else {
            (
                "/xion.zk.v1.Query/VKeyByName",
                QueryVKeyByNameRequest {
                    name: self.vkey_name.clone(),
                }
                .encode_to_vec(),
            )
        };
        let resp = self
            .querier
            .query_grpc(path.to_string(), cosmwasm_std::Binary::new(body))
            .map_err(|_| ())?;
        QueryVKeyResponse::decode(resp.as_slice())
            .map_err(|_| ())?
            .vkey
            .ok_or(())
    }
}

impl ProofBackend for XionUltraHonkBackend<'_> {
    fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> bool {
        // Establish key identity BEFORE spending a verify, and refuse outright
        // if the configured model cannot be established. `Bytes` has two routes:
        // the response echo (cheap, atomic, needs a chain that carries it) and a
        // registry readback (needs the VKey query whitelisted for contracts).
        // `readback_digest` is Some only when the readback route succeeded.
        let readback_digest = match &self.trust {
            VkeyTrust::NameOnly => None,
            VkeyTrust::Bytes(expected) => match self.fetch_vkey() {
                Ok(record) => {
                    let got = crate::sha256(&record.key_bytes);
                    if got != *expected {
                        return false;
                    }
                    Some(got)
                }
                // Unreachable readback is not a failure yet: the echo below may
                // still establish the same fact.
                Err(()) => None,
            },
            VkeyTrust::Authority(expected) => match self.fetch_vkey() {
                Ok(record) => {
                    if record.authority.as_str() != expected.as_str() {
                        return false;
                    }
                    None
                }
                // Nothing but the registry carries the authority, so an
                // unreachable query means this model cannot be enforced.
                Err(()) => return false,
            },
        };

        // UltraHonk public_inputs go on the wire as raw concatenated 32-byte
        // big-endian field elements (what `bb prove` emits) — NO gnark
        // nbPublic/nbSecret/vec_len witness header.
        let req = QueryVerifyUltraHonkRequest {
            proof: proof.to_vec(),
            public_inputs: public_inputs.to_vec(),
            vkey_name: self.vkey_name.clone(),
            vkey_id: self.vkey_id,
            // Sent whenever we have one. A server without request tag 5 ignores
            // it; one with tag 5 enforces it atomically with the verdict.
            expected_vkey_sha256: match &self.trust {
                VkeyTrust::Bytes(expected) => expected.to_vec(),
                _ => Vec::new(),
            },
        };
        let mut req_bytes = Vec::new();
        if req.encode(&mut req_bytes).is_err() {
            return false;
        }
        // query_grpc (raw bytes): a JSON-decoding querier path would choke on
        // the proto response bytes.
        let resp = match self.querier.query_grpc(
            "/xion.zk.v1.Query/ProofVerifyUltraHonk".to_string(),
            cosmwasm_std::Binary::new(req_bytes),
        ) {
            Ok(resp) => resp,
            Err(_) => return false,
        };
        let Ok(decoded) = ProofVerifyUltraHonkResponse::decode(resp.as_slice()) else {
            return false;
        };
        if !decoded.verified {
            return false;
        }

        match &self.trust {
            VkeyTrust::Bytes(expected) => {
                if decoded.vkey_sha256.is_empty() {
                    // No echo. Accept only if the readback already proved the
                    // same fact; otherwise this chain cannot enforce byte
                    // identity and we must not pretend otherwise.
                    readback_digest.is_some()
                } else {
                    // Echo present: it is the authoritative statement of which
                    // key answered, so it decides even if a readback agreed.
                    decoded.vkey_sha256.as_slice() == expected.as_slice()
                }
            }
            // Already established above, or deliberately unchecked.
            VkeyTrust::Authority(_) | VkeyTrust::NameOnly => true,
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
        let (accepted, request) =
            verify_with_trust(VkeyTrust::Bytes(expected), verified, returned_hash);
        (accepted, request.expect("backend issued a verify query"))
    }

    /// The mock answers every gRPC path with the same payload, so a `VKey`
    /// readback would decode as garbage. That models the chain we actually
    /// have: no release through v30.0.0 whitelists that path for contracts, so
    /// the readback route is unavailable and the echo decides.
    fn verify_with_trust(
        trust: VkeyTrust,
        verified: bool,
        returned_hash: Vec<u8>,
    ) -> (bool, Option<QueryVerifyUltraHonkRequest>) {
        let captured_request = Rc::new(RefCell::new(None));
        let querier = GrpcMock {
            response: encoded_response(verified, returned_hash),
            captured_request: Rc::clone(&captured_request),
        };
        let backend =
            XionUltraHonkBackend::by_name(QuerierWrapper::new(&querier), "dcap-v1".into(), trust);
        let accepted = backend.verify(&[1, 2, 3], &[4, 5, 6]);
        let request = captured_request.borrow_mut().take();
        (accepted, request)
    }

    // NameOnly is the only model a contract can enforce against a chain with
    // neither the digest echo nor a whitelisted VKey query, which describes
    // every Xion release through v30.0.0. It must accept a bare verified=true.
    #[test]
    fn name_only_accepts_a_bare_verdict() {
        let (accepted, request) = verify_with_trust(VkeyTrust::NameOnly, true, Vec::new());
        assert!(accepted, "NameOnly checks nothing beyond resolution");
        let request = request.expect("backend issued a verify query");
        assert!(
            request.expected_vkey_sha256.is_empty(),
            "NameOnly must not claim a pin it is not enforcing"
        );
    }

    #[test]
    fn name_only_still_respects_the_verdict() {
        let (accepted, _) = verify_with_trust(VkeyTrust::NameOnly, false, Vec::new());
        assert!(!accepted);
    }

    // Bytes without an echo and without a reachable readback cannot be
    // enforced, so it must refuse rather than degrade to NameOnly.
    #[test]
    fn bytes_refuses_when_the_chain_can_prove_nothing() {
        let (accepted, _) = verify_with_trust(VkeyTrust::Bytes([0x42; 32]), true, Vec::new());
        assert!(
            !accepted,
            "a consumer that asked for byte identity must not be told yes on resolution alone"
        );
    }

    // Authority needs the registry record, which the mock cannot supply, so it
    // refuses too. Same reasoning: no silent downgrade.
    #[test]
    fn authority_refuses_without_a_reachable_registry() {
        let (accepted, request) = verify_with_trust(
            VkeyTrust::Authority("xion10d07y265gmmuvt4z0w9aw880jnsr700jctf8qc".into()),
            true,
            Vec::new(),
        );
        assert!(!accepted);
        assert!(
            request.is_none(),
            "must refuse before spending a verify it cannot trust the answer to"
        );
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

#[cfg(test)]
mod live_chain_schema {
    use super::*;

    /// The deployed xion-testnet-2 (app_version 30.0.0) `ProofVerifyResponse`
    /// carries ONLY `verified` (tag 1). A successful verify is the two bytes
    /// `08 01`. Decoding that with our response type leaves `vkey_sha256`
    /// empty, so the digest comparison in `verify` can never hold and the
    /// backend rejects every proof the chain accepts.
    ///
    /// This is fail-closed, not exploitable, but it is a total liveness
    /// failure against every Xion release that exists today: v30.0.0's
    /// `QueryVerifyUltraHonkRequest` has no tag 5 and its response has no
    /// tag 2. Verified live on 2026-08-20 against vkey id 26
    /// (`zkdcap-tdx-v4-tdreport10-21-rehearsal-e7002e4`), which returns
    /// `{"verified":true}` for a proof this backend would reject.
    ///
    /// When Xion ships verify-by-hash, this test flips and is the signal to
    /// re-enable the echo comparison.
    #[test]
    fn live_chain_response_defeats_the_digest_echo() {
        let expected = [0xa9u8; 32];
        let on_the_wire = [0x08u8, 0x01u8]; // verified = true, nothing else

        let decoded = ProofVerifyUltraHonkResponse::decode(on_the_wire.as_slice()).unwrap();
        assert!(decoded.verified, "chain said verified");
        assert!(
            decoded.vkey_sha256.is_empty(),
            "v30.0.0 omits response tag 2"
        );

        // This is the exact conjunction `verify` evaluates.
        let accepted = decoded.verified && decoded.vkey_sha256.as_slice() == expected.as_slice();
        assert!(
            !accepted,
            "backend must fail closed when the chain omits the digest echo"
        );
    }

    /// Request tag 5 is encoded and sent, but no deployed Xion release has a
    /// field there, so a conformant server ignores it as an unknown field. The
    /// pin never reaches the chain; it is only ever checked against an echo
    /// that does not come back.
    #[test]
    fn request_carries_a_pin_no_deployed_server_reads() {
        let req = QueryVerifyUltraHonkRequest {
            proof: vec![1, 2, 3],
            public_inputs: vec![4, 5, 6],
            vkey_name: "zkdcap-tdx-v4-tdreport10-21-rehearsal-e7002e4".to_string(),
            vkey_id: 0,
            expected_vkey_sha256: vec![0xa9; 32],
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        // field 5, wire type 2 => key byte 0x2a, then length 32.
        assert!(
            buf.windows(2).any(|w| w == [0x2a, 0x20]),
            "tag 5 is on the wire"
        );
    }
}
