//! The [`ProofBackend`] seam and the generic [`verify_quote`] primitive: decode
//! the packed `public_inputs`, range-check recency/validity + independent
//! TCB-Info/QE-Identity floors, and verify the proof. Application-INDEPENDENT — it returns the
//! decoded fields and leaves the `report_data` / measurement comparison to the
//! caller's domain logic.

use crate::{
    layout::{
        extract_cert_serial, extract_fmspc, extract_measurements, extract_qe_eval_num,
        extract_report_data, extract_tcb_eval_num, extract_tcb_status, extract_timestamp,
        extract_valid_from, extract_valid_until, measurement_digest, split_attestation,
        MEASUREMENT_REGS,
    },
    Hash32,
};

/// TCB status severity codes carried in packed `public_inputs` field 13 (lower is
/// better), mirroring the dcap-noir circuit (`crates/dcap/src/tcb.nr`,
/// whose current working tree directionally converges platform and QE status).
/// The circuit asserts the merged status is not `REVOKED` in-circuit, so a valid
/// proof carries `0..=5`; the
/// `max_tcb_status` policy passed to [`verify_quote_parts`] gates the rest.
pub mod tcb_status {
    /// All TCB components at the latest secure level.
    pub const UP_TO_DATE: u8 = 0;
    /// Up to date but SW-side mitigations are recommended.
    pub const SW_HARDENING_NEEDED: u8 = 1;
    /// Up to date but platform configuration changes are recommended.
    pub const CONFIGURATION_NEEDED: u8 = 2;
    /// Both configuration changes and SW hardening are recommended.
    pub const CONFIG_AND_SW_HARDENING_NEEDED: u8 = 3;
    /// The platform TCB is out of date (behind on security updates).
    pub const OUT_OF_DATE: u8 = 4;
    /// Out of date AND configuration changes are recommended.
    pub const OUT_OF_DATE_CONFIG_NEEDED: u8 = 5;
    /// Revoked. Rejected in-circuit, so it never reaches a consumer.
    pub const REVOKED: u8 = 6;
}

/// The one impure edge: UltraHonk proof verification against the
/// currently-governed vkey. The CosmWasm adapter ([`crate::xion`]) queries
/// `/xion.zk.v1.Query/ProofVerifyUltraHonk`.
pub trait ProofBackend {
    fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> bool;
}

/// Independent freshness floors for Intel's two evaluation-data-number
/// namespaces.
///
/// A production caller must select `min_tcb_info` from policy keyed by the
/// proof-bound FMSPC; this value object does not itself own or resolve that map.
/// `min_qe_identity` tracks QE-Identity collateral in its separate policy
/// domain. The two streams advance independently and therefore must not be
/// collapsed into one `min(tcb, qe)` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvalNumberPolicy {
    pub min_tcb_info: u64,
    pub min_qe_identity: u64,
}

impl EvalNumberPolicy {
    pub const fn new(min_tcb_info: u64, min_qe_identity: u64) -> Self {
        Self {
            min_tcb_info,
            min_qe_identity,
        }
    }
}

/// Backend that accepts any proof. For seam/integration tests and devnet only:
/// it exercises the FULL decode + recency/binding path while stubbing only the
/// ZK crypto a real CVM + zkdcap fills in. Gated behind `accepting` so it can
/// never enter a production wasm.
#[cfg(feature = "accepting")]
pub struct AcceptingBackend;

#[cfg(feature = "accepting")]
impl ProofBackend for AcceptingBackend {
    fn verify(&self, _proof: &[u8], _public_inputs: &[u8]) -> bool {
        true
    }
}

/// Why an attestation failed [`verify_quote`]. A `report_data` / measurement
/// mismatch is NOT here — the caller raises that after a successful decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteError {
    /// Wire framing or packed `public_inputs` malformed / wrong length / a
    /// pack_be high-bytes-zero invariant violated.
    Malformed,
    /// Chain time outside the proven `[valid_from, valid_until]` window, or
    /// either evaluation-data number below its independent monotonic floor.
    StaleOrFuture,
    /// The proof's TCB status severity exceeds the configured `max_tcb_status`
    /// (e.g. the platform is `OUT_OF_DATE`, or needs config / SW hardening beyond
    /// policy). `REVOKED` is already rejected in-circuit. See [`tcb_status`].
    TcbStatusUnacceptable,
    /// The UltraHonk proof was rejected by the backend.
    ProofInvalid,
}

/// The decoded, proof-verified, recency-checked contents of an attestation.
/// `measurements` is `[MRTD, RTMR0, RTMR1, RTMR2, RTMR3]`; the caller compares
/// `report_data` and the relevant registers against its own expectations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedQuote {
    pub report_data: [u8; 64],
    pub measurements: [[u8; 48]; MEASUREMENT_REGS],
    pub measurement_digest: Hash32,
    pub tcb_status: u8,
    pub timestamp: u64,
    /// PCK certificate serial number.
    pub cert_serial: [u8; 20],
    /// Proof-bound platform FMSPC, used by the caller to select the applicable
    /// TCB-Info recency policy.
    pub fmspc: [u8; 6],
    /// TCB-Info tcbEvaluationDataNumber.
    pub tcb_eval_num: u64,
    /// QE-Identity tcbEvaluationDataNumber (split from tcb_eval_num by issue #4).
    pub qe_eval_num: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl DecodedQuote {
    /// TDX MRTD (measurement of the initial TD).
    pub fn mrtd(&self) -> &[u8; 48] {
        &self.measurements[0]
    }
    /// TDX RTMR3 (the dstack compose-hash anchor).
    pub fn rtmr3(&self) -> &[u8; 48] {
        &self.measurements[4]
    }
}

/// Verify an UltraHonk attestation framed as `u32_BE(len) || proof || u32_BE(len)
/// || public_inputs` (see [`split_attestation`]). Convenience over
/// [`verify_quote_parts`] for consumers (e.g. dossier) whose on-wire
/// attestation is a single blob; consumers that carry `proof` and
/// `public_inputs` as separate fields (e.g. quartz-contract-core) call
/// [`verify_quote_parts`] directly.
pub fn verify_quote<B: ProofBackend>(
    backend: &B,
    attestation: &[u8],
    now_packed: u64,
    eval_policy: EvalNumberPolicy,
    max_tcb_status: u8,
) -> Result<DecodedQuote, QuoteError> {
    let (proof, pi) = split_attestation(attestation).ok_or(QuoteError::Malformed)?;
    verify_quote_parts(backend, proof, pi, now_packed, eval_policy, max_tcb_status)
}

/// Verify an UltraHonk proof produced by the dcap-noir circuit:
/// 1. decode the packed `public_inputs` (report_data, measurements, recency),
/// 2. range-check chain time against the proven `[valid_from, valid_until]`
///    window, reject either evaluation-data number below its own monotonic
///    floor, and reject a
///    `tcb_status` severity above `max_tcb_status` (see [`tcb_status`]),
/// 3. verify the proof via `backend`.
///
/// Cheap decode + recency checks run before the (on-chain gRPC) proof call. It
/// does NOT compare `report_data` or measurements against any expected value —
/// that binding is application-specific. The caller compares the returned
/// fields against its own recomputed values, so it can distinguish "genuine
/// proof but wrong identity" (Ok here, mismatch raised by the caller) from a
/// bad proof ([`QuoteError::ProofInvalid`]).
pub fn verify_quote_parts<B: ProofBackend>(
    backend: &B,
    proof: &[u8],
    pi: &[u8],
    now_packed: u64,
    eval_policy: EvalNumberPolicy,
    max_tcb_status: u8,
) -> Result<DecodedQuote, QuoteError> {
    let report_data = extract_report_data(pi).ok_or(QuoteError::Malformed)?;
    let measurements = extract_measurements(pi).ok_or(QuoteError::Malformed)?;
    let measurement_digest = measurement_digest(pi).ok_or(QuoteError::Malformed)?;
    let tcb_status = extract_tcb_status(pi).ok_or(QuoteError::Malformed)?;
    let timestamp = extract_timestamp(pi).ok_or(QuoteError::Malformed)?;
    let cert_serial = extract_cert_serial(pi).ok_or(QuoteError::Malformed)?;
    let fmspc = extract_fmspc(pi).ok_or(QuoteError::Malformed)?;
    let tcb_eval_num = extract_tcb_eval_num(pi).ok_or(QuoteError::Malformed)?;
    let qe_eval_num = extract_qe_eval_num(pi).ok_or(QuoteError::Malformed)?;
    let valid_from = extract_valid_from(pi).ok_or(QuoteError::Malformed)?;
    let valid_until = extract_valid_until(pi).ok_or(QuoteError::Malformed)?;

    // O4 (CRL-lag stance): the released v1 21-field journal exposes NO separate
    // CRL identity/recency field, so there is no independent CRL-freshness gate
    // to enforce here. Instead, CRL-lag acceptance is bounded by the
    // authenticated `valid_until` below: `valid_until` is the min of all signed
    // collateral validity upper bounds (which includes the CRL's nextUpdate),
    // proven in-circuit. Rejecting `now_packed > valid_until` therefore rejects
    // any attestation whose underlying CRL (or other collateral) has lapsed.
    // This is the explicit, version-neutral O4 policy: do NOT invent a CRL
    // field; rely on the ValidUntil window. See the `o4_tests` regression.
    if !(valid_from <= now_packed
        && now_packed <= valid_until
        && tcb_eval_num >= eval_policy.min_tcb_info
        && qe_eval_num >= eval_policy.min_qe_identity)
    {
        return Err(QuoteError::StaleOrFuture);
    }

    // TCB-status policy: reject platforms whose status severity exceeds the
    // caller's maximum (lower = better; see `tcb_status`). Revoked is already
    // rejected in-circuit. The caller chooses the threshold (e.g. UP_TO_DATE
    // only, or allow SW_HARDENING_NEEDED).
    if tcb_status > max_tcb_status {
        return Err(QuoteError::TcbStatusUnacceptable);
    }

    if !backend.verify(proof, pi) {
        return Err(QuoteError::ProofInvalid);
    }

    Ok(DecodedQuote {
        report_data,
        measurements,
        measurement_digest,
        tcb_status,
        timestamp,
        cert_serial,
        fmspc,
        tcb_eval_num,
        qe_eval_num,
        valid_from,
        valid_until,
    })
}

#[cfg(test)]
mod o4_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::layout::{build_public_inputs, MEASUREMENT_BYTES};

    struct AlwaysOk;
    impl ProofBackend for AlwaysOk {
        fn verify(&self, _proof: &[u8], _pi: &[u8]) -> bool {
            true
        }
    }

    fn pi(valid_from: u64, valid_until: u64) -> Vec<u8> {
        build_public_inputs(
            &[0u8; MEASUREMENT_BYTES],
            &[0u8; 64],
            0, // tcb_status
            0, // timestamp
            0, // tcb_eval_num
            0, // qe_eval_num
            valid_from,
            valid_until,
        )
    }

    /// O4 regression: a proof whose authenticated validity window has lapsed
    /// (`valid_until` < chain time) is rejected. This is the CRL-lag bound —
    /// there is no separate CRL field in v1, so ValidUntil is the recency gate.
    #[test]
    fn valid_until_lapsed_is_rejected() {
        let pi = pi(100, 200);
        let err = verify_quote_parts(&AlwaysOk, &[], &pi, 300, EvalNumberPolicy::default(), 0)
            .unwrap_err();
        assert_eq!(err, QuoteError::StaleOrFuture);
    }

    /// Control: inside the window the same proof is accepted, proving the
    /// rejection above is specifically the ValidUntil bound and not some other
    /// gate.
    #[test]
    fn within_window_is_accepted() {
        let pi = pi(100, 200);
        let decoded =
            verify_quote_parts(&AlwaysOk, &[], &pi, 150, EvalNumberPolicy::default(), 0).unwrap();
        assert_eq!(decoded.valid_until, 200);
    }

    /// Boundary: chain time exactly at `valid_until` is still accepted
    /// (inclusive upper bound); one tick past is rejected.
    #[test]
    fn valid_until_boundary_is_inclusive() {
        let pi = pi(100, 200);
        assert!(
            verify_quote_parts(&AlwaysOk, &[], &pi, 200, EvalNumberPolicy::default(), 0).is_ok()
        );
        assert_eq!(
            verify_quote_parts(&AlwaysOk, &[], &pi, 201, EvalNumberPolicy::default(), 0)
                .unwrap_err(),
            QuoteError::StaleOrFuture
        );
    }
}
