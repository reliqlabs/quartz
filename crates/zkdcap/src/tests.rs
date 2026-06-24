use super::*;

struct FakeBackend {
    accept: bool,
}
impl ProofBackend for FakeBackend {
    fn verify(&self, _: &[u8], _: &[u8]) -> bool {
        self.accept
    }
}

fn measurements() -> [u8; MEASUREMENT_BYTES] {
    // Distinct per-register bytes so register extraction is unambiguous.
    let mut m = [0u8; MEASUREMENT_BYTES];
    for (reg, chunk) in m.chunks_mut(48).enumerate() {
        for b in chunk.iter_mut() {
            *b = 0x10 + reg as u8;
        }
    }
    m
}

fn pi_with(rd: [u8; 64], eval: u64, from: u64, until: u64) -> Vec<u8> {
    build_public_inputs(&measurements(), &rd, 7, 1_234, eval, from, until)
}

fn att(rd: [u8; 64], eval: u64, from: u64, until: u64) -> Vec<u8> {
    frame_attestation(b"proof", &pi_with(rd, eval, from, until))
}

#[test]
fn pi_is_640_bytes_and_round_trips() {
    assert_eq!(ULTRAHONK_PUBLIC_INPUTS_LEN, 640);
    let pi = pi_with([7u8; 64], 17, 100, 999);
    assert_eq!(pi.len(), 640);
    assert_eq!(extract_report_data(&pi), Some([7u8; 64]));
    assert_eq!(extract_tcb_status(&pi), Some(7));
    assert_eq!(extract_timestamp(&pi), Some(1_234));
    assert_eq!(extract_tcb_eval_num(&pi), Some(17));
    assert_eq!(extract_valid_from(&pi), Some(100));
    assert_eq!(extract_valid_until(&pi), Some(999));
}

#[test]
fn measurement_registers_round_trip() {
    let pi = pi_with([0u8; 64], 1, 0, u64::MAX);
    let regs = extract_measurements(&pi).unwrap();
    assert_eq!(regs[0], [0x10u8; 48]); // MRTD
    assert_eq!(regs[4], [0x14u8; 48]); // RTMR3
    assert_eq!(extract_rtmr3(&pi), Some([0x14u8; 48]));
    assert_eq!(extract_mrtd(&pi), Some([0x10u8; 48]));
}

#[test]
fn verify_quote_happy_path_returns_decoded() {
    let b = FakeBackend { accept: true };
    let d = verify_quote(&b, &att([9u8; 64], 5, 100, 200), 150, 0).unwrap();
    assert_eq!(d.report_data, [9u8; 64]);
    assert_eq!(d.tcb_eval_num, 5);
    assert_eq!(d.valid_from, 100);
    assert_eq!(d.valid_until, 200);
    assert_eq!(d.rtmr3(), &[0x14u8; 48]);
}

#[test]
fn verify_quote_rejects_bad_proof() {
    let b = FakeBackend { accept: false };
    assert_eq!(
        verify_quote(&b, &att([0u8; 64], 0, 0, u64::MAX), 150, 0),
        Err(QuoteError::ProofInvalid)
    );
}

#[test]
fn verify_quote_validity_window_is_inclusive() {
    let b = FakeBackend { accept: true };
    let a = att([0u8; 64], 0, 100, 200);
    assert_eq!(verify_quote(&b, &a, 50, 0).map(|_| ()), Err(QuoteError::StaleOrFuture));
    assert_eq!(verify_quote(&b, &a, 300, 0).map(|_| ()), Err(QuoteError::StaleOrFuture));
    assert!(verify_quote(&b, &a, 100, 0).is_ok()); // lower boundary inclusive
    assert!(verify_quote(&b, &a, 200, 0).is_ok()); // upper boundary inclusive
    assert!(verify_quote(&b, &a, 150, 0).is_ok());
}

#[test]
fn verify_quote_enforces_eval_floor() {
    let b = FakeBackend { accept: true };
    let a = att([0u8; 64], 5, 0, u64::MAX);
    assert_eq!(verify_quote(&b, &a, 1, 10).map(|_| ()), Err(QuoteError::StaleOrFuture)); // 5 < 10
    assert!(verify_quote(&b, &a, 1, 5).is_ok()); // 5 >= 5
    assert!(verify_quote(&b, &a, 1, 0).is_ok()); // no floor
}

#[test]
fn high_byte_invariant_rejects_poisoned_limb() {
    let mut a = att([1u8; 64], 0, 0, u64::MAX);
    // Poison the high byte of report_data limb 0. The packed pi sits after the
    // 4-byte proof-len + 5-byte "proof" + 4-byte pi-len framing = offset 13.
    let pi_off = 4 + b"proof".len() + 4;
    a[pi_off + 10 * 32] = 1;
    let b = FakeBackend { accept: true };
    assert_eq!(
        verify_quote(&b, &a, 1, 0).map(|_| ()),
        Err(QuoteError::Malformed)
    );
}

#[test]
fn split_rejects_trailing_garbage() {
    let pi = pi_with([0u8; 64], 0, 0, u64::MAX);
    let mut w = frame_attestation(b"proof", &pi);
    assert!(split_attestation(&w).is_some());
    w.push(0xFF);
    assert!(split_attestation(&w).is_none());
}

#[test]
fn measurement_digest_covers_all_registers() {
    let pi = pi_with([0u8; 64], 0, 0, u64::MAX);
    let d1 = measurement_digest(&pi).unwrap();
    let mut pi2 = pi.clone();
    // Flip the last RTMR3 byte: reg 4's second limb is field 9, its low byte.
    pi2[9 * 32 + 31] ^= 1;
    let d2 = measurement_digest(&pi2).unwrap();
    assert_ne!(d1, d2);
}

#[test]
fn unix_to_packed_datetime_known_values() {
    assert_eq!(unix_to_packed_datetime(0), 19_700_101_000_000);
    assert_eq!(unix_to_packed_datetime(90_061), 19_700_102_010_101); // +1d 1h 1m 1s
}
