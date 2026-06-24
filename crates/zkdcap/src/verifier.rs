//! The [`ProofBackend`] seam and the generic [`verify_quote`] primitive: decode
//! the packed `public_inputs`, range-check recency/validity + the tcb-eval
//! floor, and verify the proof. Application-INDEPENDENT — it returns the
//! decoded fields and leaves the `report_data` / measurement comparison to the
//! caller's domain logic.

use crate::layout::{
    extract_measurements, extract_qe_eval_num, extract_report_data, extract_tcb_eval_num,
    extract_tcb_status, extract_timestamp, extract_valid_from, extract_valid_until,
    measurement_digest, split_attestation, MEASUREMENT_REGS,
};
use crate::Hash32;

/// The one impure edge: UltraHonk proof verification against the
/// currently-governed vkey. The CosmWasm adapter ([`crate::xion`]) queries
/// `/xion.zk.v1.Query/ProofVerifyUltraHonk`.
pub trait ProofBackend {
    fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> bool;
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
    /// `min(tcb_eval_num, qe_eval_num)` below the monotonic floor.
    StaleOrFuture,
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
    /// The recency counter the floor is applied to: the smaller of the TCB-Info
    /// and QE-Identity evaluation-data numbers.
    pub fn min_eval_num(&self) -> u64 {
        self.tcb_eval_num.min(self.qe_eval_num)
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
    min_tcb_eval_num: u64,
) -> Result<DecodedQuote, QuoteError> {
    let (proof, pi) = split_attestation(attestation).ok_or(QuoteError::Malformed)?;
    verify_quote_parts(backend, proof, pi, now_packed, min_tcb_eval_num)
}

/// Verify an UltraHonk proof produced by the dcap-noir circuit:
/// 1. decode the packed `public_inputs` (report_data, measurements, recency),
/// 2. range-check chain time against the proven `[valid_from, valid_until]`
///    window and reject `tcb_eval_num` below the monotonic floor,
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
    min_tcb_eval_num: u64,
) -> Result<DecodedQuote, QuoteError> {
    let report_data = extract_report_data(pi).ok_or(QuoteError::Malformed)?;
    let measurements = extract_measurements(pi).ok_or(QuoteError::Malformed)?;
    let measurement_digest = measurement_digest(pi).ok_or(QuoteError::Malformed)?;
    let tcb_status = extract_tcb_status(pi).ok_or(QuoteError::Malformed)?;
    let timestamp = extract_timestamp(pi).ok_or(QuoteError::Malformed)?;
    let tcb_eval_num = extract_tcb_eval_num(pi).ok_or(QuoteError::Malformed)?;
    let qe_eval_num = extract_qe_eval_num(pi).ok_or(QuoteError::Malformed)?;
    let valid_from = extract_valid_from(pi).ok_or(QuoteError::Malformed)?;
    let valid_until = extract_valid_until(pi).ok_or(QuoteError::Malformed)?;

    // Floor on the smaller of the two evaluation-data numbers (preserves the
    // pre-issue-#4 single-counter semantics, where the circuit emitted the min).
    if !(valid_from <= now_packed
        && now_packed <= valid_until
        && tcb_eval_num.min(qe_eval_num) >= min_tcb_eval_num)
    {
        return Err(QuoteError::StaleOrFuture);
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
        tcb_eval_num,
        qe_eval_num,
        valid_from,
        valid_until,
    })
}
