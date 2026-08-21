//! Packed UltraHonk `public_inputs` layout (dcap-noir circuit) and decoders.
//!
//! 21 BN254 field elements, each a 32-byte BIG-ENDIAN element. The Noir circuit
//! packs K (<=31) bytes into one element via pack_be/pack_range (value =
//! sum b[i]*256^(K-1-i)), so a K-byte limb occupies the LOW K bytes of its
//! 32-byte element and the high 32-K bytes are zero. Field order mirrors
//! dcap-noir main.nr's returned `[Field; 21]` (issue #4 split the single
//! tcb_eval_num into the two source counters):
//!   0-1   mr_td        ([0..31],[31..48])
//!   2-3   rtmr0        ([0..31],[31..48])
//!   4-5   rtmr1
//!   6-7   rtmr2
//!   8-9   rtmr3
//!   10-12 report_data  ([0..31],[31..62],[62..64])
//!   13    tcb_status   (low byte)
//!   14    timestamp    (low 8 bytes, u64 BE) -- the in-circuit verification time
//!   15    cert_serial  (20 bytes; not gated here)
//!   16    fmspc        (6 bytes; not gated here)
//!   17    tcb_eval_num TCB-Info tcbEvaluationDataNumber
//!   18    qe_eval_num  QE-Identity tcbEvaluationDataNumber
//!   19    valid_from   max of all signed validity lower bounds (packed date)
//!   20    valid_until  min of all signed validity upper bounds (packed date)
//!
//! Fields 17-20 are the circuit's recency/freshness outputs: a consumer MUST
//! range-check chain time against `[valid_from, valid_until]` and reject when
//! either collateral counter falls below its independent monotonic on-chain
//! floor (the circuit has no clock/counter, so the recency decision is the
//! consumer's).

use sha2::{Digest, Sha256};

use crate::Hash32;

const FR_BYTES: usize = 32;
/// Number of BN254 field elements in the packed `public_inputs`.
pub const ULTRAHONK_PUBLIC_INPUTS_FIELDS: usize = 21;
/// Byte length of the packed `public_inputs` blob (21 * 32 = 672).
pub const ULTRAHONK_PUBLIC_INPUTS_LEN: usize = ULTRAHONK_PUBLIC_INPUTS_FIELDS * FR_BYTES;

/// Number of TDX measurement registers carried: MRTD || RTMR0..3.
pub const MEASUREMENT_REGS: usize = 5;
const MEASUREMENT_ELEMS: usize = MEASUREMENT_REGS * 48; // 240 bytes
/// Number of measurement bytes (MRTD || RTMR0..3) the layout carries.
pub const MEASUREMENT_BYTES: usize = MEASUREMENT_ELEMS;

const F_MEASUREMENTS_START: usize = 0; // 5 regs * 2 limbs => fields 0..=9
const F_REPORTDATA: usize = 10; // 3 limbs => fields 10..=12
const F_TCBSTATUS: usize = 13;
const F_TIMESTAMP: usize = 14;
const F_CERT_SERIAL: usize = 15;
const F_FMSPC: usize = 16;
const F_TCB_EVAL: usize = 17;
const F_QE_EVAL: usize = 18;
const F_VALID_FROM: usize = 19;
const F_VALID_UNTIL: usize = 20;

pub(crate) fn sha256(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// Write a big-endian limb into field `f` (low len(bytes) bytes; high zero).
fn put_limb(out: &mut [u8], f: usize, bytes: &[u8]) {
    let end = f * FR_BYTES + FR_BYTES;
    out[end - bytes.len()..end].copy_from_slice(bytes);
}

// Low `k` bytes of field `f`, asserting the high 32-k bytes are zero (the
// pack_be injectivity invariant; a violation is malformed/adversarial input).
fn read_limb(pi: &[u8], f: usize, k: usize) -> Option<&[u8]> {
    let fb = pi.get(f * FR_BYTES..f * FR_BYTES + FR_BYTES)?;
    if fb[..FR_BYTES - k].iter().any(|b| *b != 0) {
        return None;
    }
    Some(&fb[FR_BYTES - k..])
}

/// Wire format: `u32_BE(len(proof)) || proof || u32_BE(len(pi)) || pi`.
pub fn split_attestation(att: &[u8]) -> Option<(&[u8], &[u8])> {
    let plen = u32::from_be_bytes(att.get(..4)?.try_into().ok()?) as usize;
    let proof = att.get(4..4 + plen)?;
    let rest = att.get(4 + plen..)?;
    let ilen = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    let pi = rest.get(4..4 + ilen)?;
    if rest.len() != 4 + ilen {
        return None;
    }
    Some((proof, pi))
}

/// Frame `(proof, public_inputs)` into the on-wire `attestation` bytes
/// ([`split_attestation`] is the inverse): the shared producer the enclave
/// uses so the framing matches what the contract parses.
pub fn frame_attestation(proof: &[u8], public_inputs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + proof.len() + public_inputs.len());
    out.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    out.extend_from_slice(proof);
    out.extend_from_slice(&(public_inputs.len() as u32).to_be_bytes());
    out.extend_from_slice(public_inputs);
    out
}

/// Build a packed UltraHonk `public_inputs` blob (the decoders' inverse). The
/// enclave simulator + tests use this to CONSTRUCT a chain-shaped blob; the
/// real path takes `public_inputs` straight from the prover (bb emits the
/// circuit's packed outputs). Sharing one builder keeps the sides byte
/// identical: `measurements` is MRTD||RTMR0..3 (240 bytes), `report_data` the
/// 64-byte ReportData, `tcb_status` + the u64 fields ride their own fields.
/// `tcb_eval_num` is the TCB-Info counter, `qe_eval_num` the QE-Identity counter
/// (issue #4). cert_serial (15) + fmspc (16) are left zero. Round-trips:
/// `extract_report_data(build_public_inputs(.., rd, ..)) == Some(rd)`.
#[allow(clippy::too_many_arguments)]
pub fn build_public_inputs(
    measurements: &[u8; MEASUREMENT_BYTES],
    report_data: &[u8; 64],
    tcb_status: u8,
    timestamp: u64,
    tcb_eval_num: u64,
    qe_eval_num: u64,
    valid_from: u64,
    valid_until: u64,
) -> Vec<u8> {
    let mut out = vec![0u8; ULTRAHONK_PUBLIC_INPUTS_LEN];
    // 5 measurement regs (48 bytes each) -> 2 limbs (31 + 17), fields 0..=9.
    for reg in 0..MEASUREMENT_REGS {
        let b = reg * 48;
        put_limb(
            &mut out,
            F_MEASUREMENTS_START + reg * 2,
            &measurements[b..b + 31],
        );
        put_limb(
            &mut out,
            F_MEASUREMENTS_START + reg * 2 + 1,
            &measurements[b + 31..b + 48],
        );
    }
    // report_data (64 bytes) -> 3 limbs (31 + 31 + 2), fields 10..=12.
    put_limb(&mut out, F_REPORTDATA, &report_data[0..31]);
    put_limb(&mut out, F_REPORTDATA + 1, &report_data[31..62]);
    put_limb(&mut out, F_REPORTDATA + 2, &report_data[62..64]);
    // scalar fields: tcb_status (low byte) + the u64 fields (low 8 bytes BE).
    out[F_TCBSTATUS * FR_BYTES + FR_BYTES - 1] = tcb_status;
    put_limb(&mut out, F_TIMESTAMP, &timestamp.to_be_bytes());
    put_limb(&mut out, F_TCB_EVAL, &tcb_eval_num.to_be_bytes());
    put_limb(&mut out, F_QE_EVAL, &qe_eval_num.to_be_bytes());
    put_limb(&mut out, F_VALID_FROM, &valid_from.to_be_bytes());
    put_limb(&mut out, F_VALID_UNTIL, &valid_until.to_be_bytes());
    out
}

/// Extract the 64-byte ReportData from fields 10..=12 (packed limbs; enforces
/// the high-bytes-zero invariant per limb).
pub fn extract_report_data(pi: &[u8]) -> Option<[u8; 64]> {
    if pi.len() != ULTRAHONK_PUBLIC_INPUTS_LEN {
        return None;
    }
    let mut rd = [0u8; 64];
    rd[0..31].copy_from_slice(read_limb(pi, F_REPORTDATA, 31)?);
    rd[31..62].copy_from_slice(read_limb(pi, F_REPORTDATA + 1, 31)?);
    rd[62..64].copy_from_slice(read_limb(pi, F_REPORTDATA + 2, 2)?);
    Some(rd)
}

/// Extract one 48-byte measurement register. `reg`: 0=MRTD, 1=RTMR0, 2=RTMR1,
/// 3=RTMR2, 4=RTMR3. Each register is two packed limbs (31 + 17 bytes).
pub fn extract_measurement_reg(pi: &[u8], reg: usize) -> Option<[u8; 48]> {
    if pi.len() != ULTRAHONK_PUBLIC_INPUTS_LEN || reg >= MEASUREMENT_REGS {
        return None;
    }
    let mut out = [0u8; 48];
    out[0..31].copy_from_slice(read_limb(pi, F_MEASUREMENTS_START + reg * 2, 31)?);
    out[31..48].copy_from_slice(read_limb(pi, F_MEASUREMENTS_START + reg * 2 + 1, 17)?);
    Some(out)
}

/// All five measurement registers in layout order: `[MRTD, RTMR0, RTMR1, RTMR2,
/// RTMR3]`.
pub fn extract_measurements(pi: &[u8]) -> Option<[[u8; 48]; MEASUREMENT_REGS]> {
    let mut regs = [[0u8; 48]; MEASUREMENT_REGS];
    for (reg, slot) in regs.iter_mut().enumerate() {
        *slot = extract_measurement_reg(pi, reg)?;
    }
    Some(regs)
}

/// TDX RTMR3 (48-byte SHA-384 register), the dstack compose-hash anchor.
pub fn extract_rtmr3(pi: &[u8]) -> Option<[u8; 48]> {
    extract_measurement_reg(pi, 4)
}

/// TDX MRTD (48-byte measurement of the initial TD).
pub fn extract_mrtd(pi: &[u8]) -> Option<[u8; 48]> {
    extract_measurement_reg(pi, 0)
}

/// SHA-256 over the measurement bytes (MRTD || RTMR0..3), unpacked from fields
/// 0..=9. A digest for audit/event use, not an allowlist.
pub fn measurement_digest(pi: &[u8]) -> Option<Hash32> {
    let regs = extract_measurements(pi)?;
    let mut bytes = Vec::with_capacity(MEASUREMENT_ELEMS);
    for reg in &regs {
        bytes.extend_from_slice(reg);
    }
    Some(sha256(&bytes))
}

/// TCB status code (low byte of field 13).
pub fn extract_tcb_status(pi: &[u8]) -> Option<u8> {
    if pi.len() != ULTRAHONK_PUBLIC_INPUTS_LEN {
        return None;
    }
    let fb = pi.get(F_TCBSTATUS * FR_BYTES..F_TCBSTATUS * FR_BYTES + FR_BYTES)?;
    // high 31 bytes must be zero (single-byte field).
    if fb[..FR_BYTES - 1].iter().any(|b| *b != 0) {
        return None;
    }
    Some(fb[FR_BYTES - 1])
}

// Read a scalar u64 field (value packed in the low 8 bytes of field `f`).
fn scalar_u64(pi: &[u8], f: usize) -> Option<u64> {
    if pi.len() != ULTRAHONK_PUBLIC_INPUTS_LEN {
        return None;
    }
    let limb = read_limb(pi, f, 8)?;
    Some(u64::from_be_bytes(limb.try_into().ok()?))
}

/// In-circuit verification time (u64 BE in the low 8 bytes of field 14).
pub fn extract_timestamp(pi: &[u8]) -> Option<u64> {
    scalar_u64(pi, F_TIMESTAMP)
}

/// PCK certificate serial number (20 bytes, field 15).
pub fn extract_cert_serial(pi: &[u8]) -> Option<[u8; 20]> {
    if pi.len() != ULTRAHONK_PUBLIC_INPUTS_LEN {
        return None;
    }
    read_limb(pi, F_CERT_SERIAL, 20)?.try_into().ok()
}

/// Platform FMSPC (6 bytes, field 16).
///
/// Consumers use this to select the TCB-Info evaluation-data-number policy for
/// the attested platform family. It must not be confused with the independent
/// QE-Identity evaluation-data-number namespace.
pub fn extract_fmspc(pi: &[u8]) -> Option<[u8; 6]> {
    if pi.len() != ULTRAHONK_PUBLIC_INPUTS_LEN {
        return None;
    }
    read_limb(pi, F_FMSPC, 6)?.try_into().ok()
}

/// TCB-Info evaluation-data number (recency counter, field 17). A consumer
/// rejects values below a monotonic on-chain floor.
pub fn extract_tcb_eval_num(pi: &[u8]) -> Option<u64> {
    scalar_u64(pi, F_TCB_EVAL)
}

/// QE-Identity evaluation-data number (recency counter, field 18). Split from
/// the TCB-Info counter by dcap-noir issue #4.
pub fn extract_qe_eval_num(pi: &[u8]) -> Option<u64> {
    scalar_u64(pi, F_QE_EVAL)
}

/// Lower bound of the circuit-proven validity window (packed YYYYMMDDhhmmss):
/// max of every signed validity lower bound.
pub fn extract_valid_from(pi: &[u8]) -> Option<u64> {
    scalar_u64(pi, F_VALID_FROM)
}

/// Upper bound of the circuit-proven validity window (packed YYYYMMDDhhmmss):
/// min of every signed validity upper bound.
pub fn extract_valid_until(pi: &[u8]) -> Option<u64> {
    scalar_u64(pi, F_VALID_UNTIL)
}

/// Convert a unix timestamp (seconds, UTC) to the packed `YYYYMMDDhhmmss`
/// integer the circuit emits for valid_from/valid_until, so the contract can
/// range-check chain time (`env.block.time`) against the proven window.
/// Proleptic Gregorian (Howard Hinnant's days-from-civil inverse).
pub fn unix_to_packed_datetime(unix_secs: u64) -> u64 {
    let days = (unix_secs / 86_400) as i64;
    let secs = unix_secs % 86_400;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u64; // [1, 12]
    let year = (y + if m <= 2 { 1 } else { 0 }) as u64;
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    year * 10_000_000_000 + m * 100_000_000 + d * 1_000_000 + hh * 10_000 + mm * 100 + ss
}
