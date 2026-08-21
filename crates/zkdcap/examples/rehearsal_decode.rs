//! Decode a real zkdcap statement produced by the release runner and print
//! every published field, then run the full `verify_quote_parts` policy gate
//! against it.
//!
//! This is the consumer half of the testnet rehearsal: the proof these inputs
//! belong to is the one xion-testnet-2 accepts under vkey id 26
//! (`zkdcap-tdx-v4-tdreport10-21-rehearsal-e7002e4`), so what runs here is the
//! exact decode + policy path a deployed contract would run, minus the chain
//! query.
//!
//! Usage:
//!   cargo run -p quartz-zkdcap --features accepting \
//!     --example rehearsal_decode -- <release-run-dir>/proof/public_inputs

use quartz_zkdcap::{
    extract_cert_serial, extract_fmspc, extract_measurements, extract_qe_eval_num,
    extract_report_data, extract_tcb_eval_num, extract_tcb_status, extract_timestamp,
    extract_valid_from, extract_valid_until, frame_attestation, measurement_digest, tcb_status,
    verify_quote_parts, AcceptingBackend, EvalNumberPolicy, QuoteError,
    ULTRAHONK_PUBLIC_INPUTS_LEN,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("pass the public_inputs path");
    let pi = std::fs::read(&path).expect("read public_inputs");
    assert_eq!(
        pi.len(),
        ULTRAHONK_PUBLIC_INPUTS_LEN,
        "expected {} bytes, got {}",
        ULTRAHONK_PUBLIC_INPUTS_LEN,
        pi.len()
    );
    println!("statement: {} bytes / 21 fields", pi.len());

    let rd = extract_report_data(&pi).expect("report_data");
    let m = extract_measurements(&pi).expect("measurements");
    let status = extract_tcb_status(&pi).expect("tcb_status");
    let ts = extract_timestamp(&pi).expect("timestamp");
    let serial = extract_cert_serial(&pi).expect("cert_serial");
    let fmspc = extract_fmspc(&pi).expect("fmspc");
    let tcb_eval = extract_tcb_eval_num(&pi).expect("tcb_eval_num");
    let qe_eval = extract_qe_eval_num(&pi).expect("qe_eval_num");
    let from = extract_valid_from(&pi).expect("valid_from");
    let until = extract_valid_until(&pi).expect("valid_until");

    println!("  report_data   {}", hex(&rd));
    for (i, name) in ["MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"].iter().enumerate() {
        println!("  {name:<13} {}", hex(&m[i]));
    }
    println!("  meas_digest   {}", hex(&measurement_digest(&pi).unwrap()));
    println!(
        "  tcb_status    {status}  ({})",
        match status {
            tcb_status::UP_TO_DATE => "UpToDate",
            tcb_status::SW_HARDENING_NEEDED => "SWHardeningNeeded",
            tcb_status::CONFIGURATION_NEEDED => "ConfigurationNeeded",
            tcb_status::CONFIG_AND_SW_HARDENING_NEEDED => "ConfigAndSWHardeningNeeded",
            tcb_status::OUT_OF_DATE => "OutOfDate",
            tcb_status::OUT_OF_DATE_CONFIG_NEEDED => "OutOfDateConfigurationNeeded",
            _ => "unexpected (Revoked is rejected in-circuit)",
        }
    );
    println!("  fmspc         {}", hex(&fmspc));
    println!("  cert_serial   {}", hex(&serial));
    println!("  tcb_eval_num  {tcb_eval}");
    println!("  qe_eval_num   {qe_eval}");
    println!("  timestamp     {ts}");
    println!("  valid_from    {from}");
    println!("  valid_until   {until}");

    // The framed wire shape a consumer actually receives.
    let att = frame_attestation(b"proof-bytes-elided", &pi);
    println!("framed attestation: {} bytes", att.len());

    // Policy gate. AcceptingBackend stands in for the chain query, which the
    // rehearsal already exercised separately against vkey id 26.
    println!("\npolicy gate (verify_quote_parts):");
    let cases: [(&str, EvalNumberPolicy, u8, bool); 5] = [
        ("floors at 0, ceiling UpToDate", EvalNumberPolicy::new(0, 0), tcb_status::UP_TO_DATE, true),
        ("floors at the proven values", EvalNumberPolicy::new(tcb_eval, qe_eval), tcb_status::UP_TO_DATE, true),
        ("TCB floor one above proven", EvalNumberPolicy::new(tcb_eval + 1, qe_eval), tcb_status::UP_TO_DATE, false),
        ("QE floor one above proven", EvalNumberPolicy::new(tcb_eval, qe_eval + 1), tcb_status::UP_TO_DATE, false),
        ("ceiling below proven status", EvalNumberPolicy::new(0, 0), status.saturating_sub(1), status == 0),
    ];
    let mut failures = 0;
    for (label, policy, ceiling, want_ok) in cases {
        let r = verify_quote_parts(&AcceptingBackend, b"p", &pi, from, policy, ceiling);
        let got_ok = r.is_ok();
        let verdict = match &r {
            Ok(_) => "accept".to_string(),
            Err(QuoteError::StaleOrFuture) => "reject StaleOrFuture".to_string(),
            Err(QuoteError::TcbStatusUnacceptable) => "reject TcbStatusUnacceptable".to_string(),
            Err(e) => format!("reject {e:?}"),
        };
        let mark = if got_ok == want_ok { "ok" } else { "UNEXPECTED" };
        if got_ok != want_ok {
            failures += 1;
        }
        println!("  [{mark}] {label:<32} -> {verdict}");
    }

    // Freshness is the consumer's call against the proven window.
    println!("\nfreshness against the proven window:");
    for (label, now) in [
        ("valid_from", from),
        ("valid_until", until),
        ("one before valid_from", from.saturating_sub(1)),
        ("one after valid_until", until.saturating_add(1)),
    ] {
        let r = verify_quote_parts(
            &AcceptingBackend,
            b"p",
            &pi,
            now,
            EvalNumberPolicy::default(),
            tcb_status::UP_TO_DATE,
        );
        println!("  {label:<24} now={now:<16} -> {}", if r.is_ok() { "accept" } else { "reject" });
    }

    if failures > 0 {
        eprintln!("\n{failures} case(s) behaved unexpectedly");
        std::process::exit(1);
    }
    println!("\nall policy cases behaved as expected");
}
