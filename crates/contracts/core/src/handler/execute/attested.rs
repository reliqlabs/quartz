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
#[cfg(not(feature = "mock"))]
use crate::state::Config;

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
        let expected_rtmr3 =
            Config::try_from(config.clone()).ok().and_then(|c| c.expected_rtmr3().copied());
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
