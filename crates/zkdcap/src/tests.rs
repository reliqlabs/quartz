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

const CERT_SERIAL: [u8; 20] = [0xA5; 20];
const FMSPC: [u8; 6] = [0xB6; 6];

fn floors(min_tcb_info: u64, min_qe_identity: u64) -> EvalNumberPolicy {
    EvalNumberPolicy::new(min_tcb_info, min_qe_identity)
}

fn pi_with(rd: [u8; 64], tcb_eval: u64, qe_eval: u64, from: u64, until: u64) -> Vec<u8> {
    let mut pi = build_public_inputs(
        &measurements(),
        &rd,
        7,
        1_234,
        tcb_eval,
        qe_eval,
        from,
        until,
    );
    pi[15 * 32 + 12..16 * 32].copy_from_slice(&CERT_SERIAL);
    pi[16 * 32 + 26..17 * 32].copy_from_slice(&FMSPC);
    pi
}

fn att(rd: [u8; 64], tcb_eval: u64, qe_eval: u64, from: u64, until: u64) -> Vec<u8> {
    frame_attestation(b"proof", &pi_with(rd, tcb_eval, qe_eval, from, until))
}

#[test]
fn pi_is_672_bytes_and_round_trips() {
    assert_eq!(ULTRAHONK_PUBLIC_INPUTS_FIELDS, 21);
    assert_eq!(ULTRAHONK_PUBLIC_INPUTS_LEN, 672);
    let pi = pi_with([7u8; 64], 17, 23, 100, 999);
    assert_eq!(pi.len(), 672);
    assert_eq!(extract_report_data(&pi), Some([7u8; 64]));
    assert_eq!(extract_tcb_status(&pi), Some(7));
    assert_eq!(extract_timestamp(&pi), Some(1_234));
    assert_eq!(extract_cert_serial(&pi), Some(CERT_SERIAL));
    assert_eq!(extract_fmspc(&pi), Some(FMSPC));
    assert_eq!(extract_tcb_eval_num(&pi), Some(17));
    assert_eq!(extract_qe_eval_num(&pi), Some(23));
    assert_eq!(extract_valid_from(&pi), Some(100));
    assert_eq!(extract_valid_until(&pi), Some(999));
}

#[test]
fn identity_extractors_reject_noncanonical_high_bytes() {
    let pi = pi_with([0u8; 64], 1, 1, 0, u64::MAX);

    let mut bad_serial = pi.clone();
    bad_serial[15 * 32] = 1;
    assert_eq!(extract_cert_serial(&bad_serial), None);

    let mut bad_fmspc = pi;
    bad_fmspc[16 * 32] = 1;
    assert_eq!(extract_fmspc(&bad_fmspc), None);
}

#[test]
fn measurement_registers_round_trip() {
    let pi = pi_with([0u8; 64], 1, 1, 0, u64::MAX);
    let regs = extract_measurements(&pi).unwrap();
    assert_eq!(regs[0], [0x10u8; 48]); // MRTD
    assert_eq!(regs[4], [0x14u8; 48]); // RTMR3
    assert_eq!(extract_rtmr3(&pi), Some([0x14u8; 48]));
    assert_eq!(extract_mrtd(&pi), Some([0x10u8; 48]));
}

#[test]
fn verify_quote_happy_path_returns_decoded() {
    let b = FakeBackend { accept: true };
    let d = verify_quote(
        &b,
        &att([9u8; 64], 5, 8, 100, 200),
        150,
        floors(5, 8),
        u8::MAX,
    )
    .unwrap();
    assert_eq!(d.report_data, [9u8; 64]);
    assert_eq!(d.cert_serial, CERT_SERIAL);
    assert_eq!(d.fmspc, FMSPC);
    assert_eq!(d.tcb_eval_num, 5);
    assert_eq!(d.qe_eval_num, 8);
    assert_eq!(d.valid_from, 100);
    assert_eq!(d.valid_until, 200);
    assert_eq!(d.rtmr3(), &[0x14u8; 48]);
}

#[test]
fn verify_quote_rejects_bad_proof() {
    let b = FakeBackend { accept: false };
    assert_eq!(
        verify_quote(
            &b,
            &att([0u8; 64], 99, 99, 0, u64::MAX),
            150,
            floors(0, 0),
            u8::MAX,
        ),
        Err(QuoteError::ProofInvalid)
    );
}

#[test]
fn verify_quote_validity_window_is_inclusive() {
    let b = FakeBackend { accept: true };
    let a = att([0u8; 64], 99, 99, 100, 200);
    assert_eq!(
        verify_quote(&b, &a, 50, floors(0, 0), u8::MAX).map(|_| ()),
        Err(QuoteError::StaleOrFuture)
    );
    assert_eq!(
        verify_quote(&b, &a, 300, floors(0, 0), u8::MAX).map(|_| ()),
        Err(QuoteError::StaleOrFuture)
    );
    assert!(verify_quote(&b, &a, 100, floors(0, 0), u8::MAX).is_ok()); // lower boundary inclusive
    assert!(verify_quote(&b, &a, 200, floors(0, 0), u8::MAX).is_ok()); // upper boundary inclusive
    assert!(verify_quote(&b, &a, 150, floors(0, 0), u8::MAX).is_ok());
}

#[test]
fn verify_quote_enforces_independent_eval_floors() {
    let b = FakeBackend { accept: true };
    // The collateral streams advance independently. A lower-but-current QE
    // number must not force the TCB floor down (or the QE floor up).
    assert_eq!(
        verify_quote(
            &b,
            &att([0u8; 64], 9, 100, 0, u64::MAX),
            1,
            floors(10, 3),
            u8::MAX,
        )
        .map(|_| ()),
        Err(QuoteError::StaleOrFuture)
    ); // TCB-Info is below its own floor.
    assert_eq!(
        verify_quote(
            &b,
            &att([0u8; 64], 100, 2, 0, u64::MAX),
            1,
            floors(10, 3),
            u8::MAX,
        )
        .map(|_| ()),
        Err(QuoteError::StaleOrFuture)
    ); // QE-Identity is below its own floor.
    assert!(verify_quote(
        &b,
        &att([0u8; 64], 10, 3, 0, u64::MAX),
        1,
        floors(10, 3),
        u8::MAX,
    )
    .is_ok());
    assert!(verify_quote(
        &b,
        &att([0u8; 64], 5, 5, 0, u64::MAX),
        1,
        floors(0, 0),
        u8::MAX,
    )
    .is_ok());
}

#[test]
fn high_byte_invariant_rejects_poisoned_limb() {
    let mut a = att([1u8; 64], 1, 1, 0, u64::MAX);
    // Poison the high byte of report_data limb 0. The packed pi sits after the
    // 4-byte proof-len + 5-byte "proof" + 4-byte pi-len framing = offset 13.
    let pi_off = 4 + b"proof".len() + 4;
    a[pi_off + 10 * 32] = 1;
    let b = FakeBackend { accept: true };
    assert_eq!(
        verify_quote(&b, &a, 1, floors(0, 0), u8::MAX).map(|_| ()),
        Err(QuoteError::Malformed)
    );
}

#[test]
fn verify_quote_enforces_tcb_status_policy() {
    let b = FakeBackend { accept: true };
    // Build an attestation with a specific tcb_status severity.
    let with_status = |s: u8| {
        frame_attestation(
            b"proof",
            &build_public_inputs(&measurements(), &[0u8; 64], s, 1_234, 1, 1, 0, u64::MAX),
        )
    };

    // UpToDate (0) is accepted under the strictest policy.
    assert!(verify_quote(
        &b,
        &with_status(tcb_status::UP_TO_DATE),
        1,
        floors(0, 0),
        tcb_status::UP_TO_DATE,
    )
    .is_ok());

    // OutOfDate (4) is rejected under UpToDate-only AND under a mid policy.
    assert_eq!(
        verify_quote(
            &b,
            &with_status(tcb_status::OUT_OF_DATE),
            1,
            floors(0, 0),
            tcb_status::UP_TO_DATE,
        )
        .map(|_| ()),
        Err(QuoteError::TcbStatusUnacceptable)
    );
    assert_eq!(
        verify_quote(
            &b,
            &with_status(tcb_status::OUT_OF_DATE),
            1,
            floors(0, 0),
            tcb_status::CONFIG_AND_SW_HARDENING_NEEDED,
        )
        .map(|_| ()),
        Err(QuoteError::TcbStatusUnacceptable)
    );

    // SWHardeningNeeded (1) is rejected by default (UpToDate-only) but accepted
    // when the policy is raised to allow it. Threshold is inclusive.
    assert_eq!(
        verify_quote(
            &b,
            &with_status(tcb_status::SW_HARDENING_NEEDED),
            1,
            floors(0, 0),
            tcb_status::UP_TO_DATE,
        )
        .map(|_| ()),
        Err(QuoteError::TcbStatusUnacceptable)
    );
    assert!(verify_quote(
        &b,
        &with_status(tcb_status::SW_HARDENING_NEEDED),
        1,
        floors(0, 0),
        tcb_status::SW_HARDENING_NEEDED,
    )
    .is_ok());
}

#[test]
fn split_rejects_trailing_garbage() {
    let pi = pi_with([0u8; 64], 1, 1, 0, u64::MAX);
    let mut w = frame_attestation(b"proof", &pi);
    assert!(split_attestation(&w).is_some());
    w.push(0xFF);
    assert!(split_attestation(&w).is_none());
}

#[test]
fn measurement_digest_covers_all_registers() {
    let pi = pi_with([0u8; 64], 1, 1, 0, u64::MAX);
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
