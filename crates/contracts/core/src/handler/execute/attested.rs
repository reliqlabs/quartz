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
// **Compose_hash binding NOT covered here — SECURITY GAP**: this is the
// deferred half of Round D Critical 4. The current wrapper enforces
// `config.mr_enclave == self.compose_hash` (line ~245), but `self.compose_hash`
// is sender-supplied. Nothing in the current verification chain binds the
// proof's attested RTMR3 (which encodes the actual running compose_hash via
// dstack's boot-time TDX extension) back to `self.compose_hash`. An attacker
// holding a valid proof for image Y can submit it with `self.compose_hash =
// config.mr_enclave` (a value for image X) and pass all wrapper checks plus
// the report_data binding above.
//
// To close: one of —
//   (a) Extend `zkdcap_core::DcapJournal` with a `compose_hash: [u8; 32]`
//       field; the sp1-guest reads the dstack-extended compose_hash and
//       commits it to the journal. Cross-repo PR to
//       `/Users/mvid/Development/reliq/zkdcap`. Cleanest end state.
//   (b) Implement an on-chain RTMR3-extension verifier: compute the
//       expected `rtmr3 = sha384_extend(initial_rtmr3, [compose_hash,
//       ...other_events])` from `self.compose_hash` + known dstack
//       boot-time event list, compare against `journal.rtmr3`. Requires
//       SHA-384 on-chain and knowing dstack's extension event ordering;
//       expensive but no cross-repo dep.
//   (c) Add `config.expected_rtmr3: [u8; 48]` and verify-equal directly
//       against `journal.rtmr3`. Loses the indirection through
//       compose_hash but is the cheapest interim binding.
//
// All three paths are out of scope for this hook. The report_data binding
// alone closes the more critical "anybody-can-substitute-the-attested-
// user-data" vector; the compose_hash binding closes the residual
// "wrong-image-attestation" vector. Until one of (a)/(b)/(c) lands, the
// contract should be considered to trust that whoever submitted the
// transaction also faithfully reports compose_hash.

#[cfg(not(feature = "mock"))]
#[derive(serde::Deserialize)]
struct JournalReportData {
    report_data: String,
}

#[cfg(not(feature = "mock"))]
fn verify_journal_binds_report_data(
    journal_bytes: &[u8],
    expected_user_data: &[u8; 64],
) -> Result<(), Error> {
    let journal: JournalReportData = serde_json::from_slice(journal_bytes)
        .map_err(|e| Error::ZkdcapVerificationFailed(format!("decode journal: {e}")))?;
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
        // anything about *which* report_data and compose_hash were
        // attested. Bind the proof's journal to the wrapper-declared
        // user_data; the matching compose_hash binding is queued as a
        // separate Quartz/zkdcap follow-up because DcapJournal does not
        // currently expose compose_hash directly.
        verify_journal_binds_report_data(&self.zkdcap_journal, &self.user_data)?;

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
