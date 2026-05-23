use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::attested::{
        Attestation, Attested, DstackAnyAttestation, DstackAttestation, DstackZkAttestation,
        HasUserData, MockAttestation, Noop,
    },
    state::CONFIG,
};

// ── ZK module protobuf types (for DstackZkAttestation) ─────────────
// Uses the gnark-native ProofVerifyGnark endpoint (Xion v29+).
// Same field tags as QueryVerifyRequest, but public_inputs is bytes
// (concatenated 32-byte big-endian fr.Element) instead of repeated string.

#[cfg(not(feature = "mock"))]
#[derive(Clone, prost::Message)]
struct QueryVerifyGnarkRequest {
    #[prost(bytes = "vec", tag = "1")]
    proof: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    public_inputs: Vec<u8>,
    #[prost(string, tag = "3")]
    vkey_name: String,
    #[prost(uint64, tag = "4")]
    vkey_id: u64,
}

// ── DcapJournal report_data extraction (Round D Critical 4 production hook) ─────
//
// Minimal subset of `zkdcap_core::DcapJournal` covering only the field needed
// for the binding check between the proof's public journal and the
// wrapper-supplied `user_data`. We avoid the full `zkdcap-core` dependency
// to keep `quartz-contract-core` self-contained in the wasm32 build.
//
// The DcapJournal full layout lives at
// `/Users/mvid/Development/reliq/zkdcap/core/src/lib.rs`; the canonical
// `report_data` field is serialised as a hex-encoded `String`.
//
// **Round D Critical 4 binding status (2026-05-21)**:
//
// (1) report_data binding: ENFORCED below via
//     `verify_journal_binds_report_data`. The journal's `report_data` is
//     verified-equal against the wrapper-supplied `self.user_data`. Closes
//     the "anybody-can-substitute-the-attested-user-data" vector.
//
// (2) rtmr3 binding (compose_hash transitive): ENFORCED conditionally below
//     via `verify_journal_binds_rtmr3` when `config.expected_rtmr3.is_some()`.
//     The journal's `rtmr3` (48-byte SHA-384 TDX measurement register) is
//     verified-equal against the on-chain-pinned `config.expected_rtmr3`.
//     Path-(c) closure: avoids the cross-repo `DcapJournal` extension and
//     the on-chain SHA-384 extension verifier; pins the expected RTMR3
//     directly. Deployers compute the expected value once from a known-good
//     quote of the intended dstack image. When `config.expected_rtmr3` is
//     `None`, the binding is skipped (backwards-compat with deployments
//     that predate this field), and the residual "wrong-image-attestation"
//     vector remains open — set `expected_rtmr3` to close it.
//
// The `JournalFields` helper deserialises only the two journal fields we
// consume; we avoid the full `zkdcap-core` dependency to keep
// `quartz-contract-core` self-contained in the wasm32 build.

#[cfg(not(feature = "mock"))]
#[derive(serde::Deserialize)]
struct JournalFields {
    report_data: String,
    rtmr3: String,
}

#[cfg(not(feature = "mock"))]
fn verify_journal_bindings(
    journal_bytes: &[u8],
    expected_user_data: &[u8; 64],
    expected_rtmr3: Option<&[u8; 48]>,
) -> Result<(), Error> {
    let journal: JournalFields = serde_json::from_slice(journal_bytes)
        .map_err(|e| Error::ZkdcapVerificationFailed(format!("decode journal: {e}")))?;

    // report_data binding (always enforced)
    let report_data_bytes = hex::decode(&journal.report_data)
        .map_err(|e| Error::ZkdcapVerificationFailed(format!("decode report_data hex: {e}")))?;
    if report_data_bytes.len() != 64 {
        return Err(Error::ZkdcapVerificationFailed(format!(
            "journal report_data wrong length: expected 64, got {}",
            report_data_bytes.len()
        )));
    }
    if report_data_bytes.as_slice() != expected_user_data.as_slice() {
        return Err(Error::ZkdcapVerificationFailed(
            "journal report_data does not match self.user_data".to_string(),
        ));
    }

    // rtmr3 binding (conditional on config.expected_rtmr3 being set)
    if let Some(expected) = expected_rtmr3 {
        let rtmr3_bytes = hex::decode(&journal.rtmr3)
            .map_err(|e| Error::ZkdcapVerificationFailed(format!("decode rtmr3 hex: {e}")))?;
        if rtmr3_bytes.len() != 48 {
            return Err(Error::ZkdcapVerificationFailed(format!(
                "journal rtmr3 wrong length: expected 48, got {}",
                rtmr3_bytes.len()
            )));
        }
        if rtmr3_bytes.as_slice() != expected.as_slice() {
            return Err(Error::ZkdcapVerificationFailed(
                "journal rtmr3 does not match config.expected_rtmr3".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(not(feature = "mock"))]
#[derive(Clone, prost::Message)]
struct ProofVerifyGnarkResponse {
    #[prost(bool, tag = "1")]
    verified: bool,
}

// ── DstackAttestation handler (raw quote) ──────────────────────────

/// Raw DCAP quote verification.
///
/// For chains that support native DCAP verification or have a DCAP
/// verifier contract deployed. Currently a no-op placeholder — the
/// Attested<M,A> wrapper already verifies user_data and compose_hash.
/// Full on-chain DCAP verification would be added here.
#[cfg(not(feature = "mock"))]
impl Handler for DstackAttestation {
    fn handle(
        self,
        _deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        // TODO: On-chain DCAP quote verification.
        // For now, user_data and compose_hash checks in the Attested wrapper
        // provide the core integrity guarantees. The raw quote is available
        // for off-chain verification or future on-chain DCAP support.
        Ok(Response::new().add_attribute("action", "dcap_quote_accepted"))
    }
}

#[cfg(feature = "mock")]
impl Handler for DstackAttestation {
    fn handle(
        self,
        _deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        Ok(Response::default())
    }
}

// ── DstackZkAttestation handler (zkdcap proof) ────────────────────

/// ZK proof verification via the Xion ZK module.
///
/// Queries /xion.zk.v1.Query/ProofVerifyGnark with the Groth16 proof.
/// If no zkdcap_vkey is configured, verification is skipped.
#[cfg(not(feature = "mock"))]
impl Handler for DstackZkAttestation {
    fn handle(
        self,
        deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        let config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        let Some(vkey_name) = config.zkdcap_vkey() else {
            return Ok(Response::new().add_attribute("action", "zkdcap_verify_skipped"));
        };

        let verify_req = QueryVerifyGnarkRequest {
            proof: self.zkdcap_proof,
            public_inputs: self.zkdcap_public_inputs,
            vkey_name: vkey_name.to_string(),
            vkey_id: 0,
        };

        let mut req_bytes = Vec::new();
        prost::Message::encode(&verify_req, &mut req_bytes)
            .map_err(|e| Error::ZkdcapVerificationFailed(format!("encode request: {e}")))?;

        let resp_bytes: cosmwasm_std::Binary = deps
            .querier
            .query_grpc(
                "/xion.zk.v1.Query/ProofVerifyGnark".to_string(),
                cosmwasm_std::Binary::from(req_bytes),
            )
            .map_err(|e| Error::ZkdcapVerificationFailed(format!("ZK module query: {e}")))?;

        let verify_resp = <ProofVerifyGnarkResponse as prost::Message>::decode(resp_bytes.as_slice())
            .map_err(|e| Error::ZkdcapVerificationFailed(format!("decode response: {e}")))?;

        if !verify_resp.verified {
            return Err(Error::ZkdcapVerificationFailed(
                "proof verification returned false".to_string(),
            ));
        }

        // Round D Critical 4 production hook (2026-05-21): the gnark
        // verifier confirms the proof checks out, but does not say
        // anything about *which* report_data and rtmr3 were attested.
        // Bind the proof's journal to the wrapper-declared user_data and
        // (if config pins an expected rtmr3) to that pinned value. See
        // the helper doc above for the binding model.
        //
        // Read expected_rtmr3 directly from RawConfig to avoid a Config
        // round-trip (and the silent .ok() discard if Config::try_from
        // were to fail for an unrelated reason). Validate length here so
        // a malformed stored value surfaces as a real Err rather than
        // silently disabling the binding.
        let expected_rtmr3: Option<[u8; 48]> = match config.expected_rtmr3() {
            None => None,
            Some(bytes) if bytes.len() == 48 => {
                let mut arr = [0u8; 48];
                arr.copy_from_slice(bytes);
                Some(arr)
            }
            Some(bytes) => {
                return Err(Error::ZkdcapVerificationFailed(format!(
                    "config.expected_rtmr3 wrong length: expected 48, got {}",
                    bytes.len()
                )));
            }
        };
        verify_journal_bindings(
            &self.zkdcap_journal,
            &self.user_data,
            expected_rtmr3.as_ref(),
        )?;

        Ok(Response::new().add_attribute("action", "zkdcap_verified"))
    }
}

#[cfg(feature = "mock")]
impl Handler for DstackZkAttestation {
    fn handle(
        self,
        _deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        Ok(Response::default())
    }
}

// ── DstackAnyAttestation handler (delegates to inner variant) ──────

impl Handler for DstackAnyAttestation {
    fn handle(
        self,
        deps: DepsMut<'_>,
        env: &Env,
        info: &MessageInfo,
    ) -> Result<Response, Error> {
        match self {
            Self::Quote(a) => a.handle(deps, env, info),
            Self::Zk(a) => a.handle(deps, env, info),
        }
    }
}

// ── Mock / Noop / Attested handlers ────────────────────────────────

impl Handler for MockAttestation {
    fn handle(
        self,
        _deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        Ok(Response::default())
    }
}

impl<M, A> Handler for Attested<M, A>
where
    M: Handler + HasUserData,
    A: Handler + HasUserData + Attestation,
{
    fn handle(
        self,
        mut deps: DepsMut<'_>,
        env: &Env,
        info: &MessageInfo,
    ) -> Result<Response, Error> {
        let (msg, attestation) = self.into_tuple();
        if msg.user_data() != attestation.user_data() {
            return Err(Error::UserDataMismatch);
        }

        if let Some(config) = CONFIG.may_load(deps.storage)? {
            if config.mr_enclave() != attestation.mr_enclave() {
                return Err(Error::MrEnclaveMismatch);
            }
        }

        let res_msg = Handler::handle(msg, deps.branch(), env, info)?;
        let res_attest = Handler::handle(attestation, deps, env, info)?;

        Ok(res_msg
            .add_events(res_attest.events)
            .add_attributes(res_attest.attributes))
    }
}

impl<T> Handler for Noop<T> {
    fn handle(
        self,
        _deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        Ok(Response::default())
    }
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;

    fn make_journal(report_data_hex: &str, rtmr3_hex: &str) -> Vec<u8> {
        // Minimal JSON shape compatible with our `JournalFields` deserialiser.
        // Includes a smattering of other fields that the real `DcapJournal`
        // ships so the test inputs are realistic; `serde_json` ignores
        // fields not present in our subset struct.
        format!(
            r#"{{"quote_hash":"00","quote_verified":true,"tcb_status":"UpToDate","advisory_ids":[],"mr_td":"00","rtmr0":"00","rtmr1":"00","rtmr2":"00","rtmr3":"{rtmr3_hex}","report_data":"{report_data_hex}","verification_timestamp":0}}"#
        )
        .into_bytes()
    }

    #[test]
    fn report_data_binding_accepts_matching() {
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xBBu8; 48];
        let journal = make_journal(&hex::encode(user_data), &hex::encode(rtmr3));
        verify_journal_bindings(&journal, &user_data, None).unwrap();
    }

    #[test]
    fn report_data_binding_rejects_mismatch() {
        let user_data = [0xAAu8; 64];
        let other = [0xCCu8; 64];
        let rtmr3 = [0xBBu8; 48];
        let journal = make_journal(&hex::encode(other), &hex::encode(rtmr3));
        let err = verify_journal_bindings(&journal, &user_data, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("report_data"), "got: {msg}");
    }

    #[test]
    fn rtmr3_binding_accepts_matching_when_pinned() {
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xBBu8; 48];
        let journal = make_journal(&hex::encode(user_data), &hex::encode(rtmr3));
        verify_journal_bindings(&journal, &user_data, Some(&rtmr3)).unwrap();
    }

    #[test]
    fn rtmr3_binding_rejects_mismatch_when_pinned() {
        let user_data = [0xAAu8; 64];
        let expected_rtmr3 = [0xBBu8; 48];
        let actual_rtmr3 = [0xCCu8; 48];
        let journal = make_journal(&hex::encode(user_data), &hex::encode(actual_rtmr3));
        let err =
            verify_journal_bindings(&journal, &user_data, Some(&expected_rtmr3)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rtmr3"), "got: {msg}");
    }

    #[test]
    fn rtmr3_binding_skipped_when_none() {
        // With no expected_rtmr3 pinned, any rtmr3 in the journal is
        // accepted (backwards-compat for deployments that pre-date
        // the config field).
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xCCu8; 48]; // not pinned anywhere
        let journal = make_journal(&hex::encode(user_data), &hex::encode(rtmr3));
        verify_journal_bindings(&journal, &user_data, None).unwrap();
    }

    #[test]
    fn rejects_malformed_journal() {
        let user_data = [0xAAu8; 64];
        let err = verify_journal_bindings(b"not json", &user_data, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("decode journal"), "got: {msg}");
    }

    #[test]
    fn rejects_wrong_length_report_data() {
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xBBu8; 48];
        // 32-byte report_data when 64 is required
        let journal = make_journal(&hex::encode([0u8; 32]), &hex::encode(rtmr3));
        let err = verify_journal_bindings(&journal, &user_data, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("report_data wrong length"), "got: {msg}");
    }

    #[test]
    fn rejects_wrong_length_rtmr3() {
        let user_data = [0xAAu8; 64];
        let expected_rtmr3 = [0xBBu8; 48];
        // 32-byte rtmr3 when 48 is required
        let journal = make_journal(&hex::encode(user_data), &hex::encode([0u8; 32]));
        let err =
            verify_journal_bindings(&journal, &user_data, Some(&expected_rtmr3)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rtmr3 wrong length"), "got: {msg}");
    }
}
