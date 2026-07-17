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

// ── DstackZkAttestation binding check (Round D Critical 4 production hook) ─────
//
// The Xion ZK module's UltraHonk verifier (queried via
// `quartz_zkdcap::XionUltraHonkBackend`) confirms the proof checks out and that
// chain time sits inside the proven validity window, but it does not say
// anything about *which* report_data and rtmr3 were attested. After a successful
// `verify_quote_parts`, bind the proof's decoded public inputs to the
// wrapper-declared `user_data` and (if config pins an expected rtmr3) to that
// pinned value.
//
// (1) report_data binding: ALWAYS enforced. The public-inputs `report_data` is
//     verified-equal against the wrapper-supplied `self.user_data`. Closes the
//     "anybody-can-substitute-the-attested-user-data" vector.
//
// (2) image binding (per-register TDX measurement pins): for each of
//     MRTD/RTMR0/RTMR1/RTMR2/RTMR3 that the config pins, the proof's decoded
//     register is verified-equal against the pinned value; unset registers are
//     skipped. SECURE-BY-DEFAULT: if a vkey is configured (verification on) and
//     NO register is pinned, verification is REJECTED unless
//     `config.allow_any_image` is set (trust any genuine TDX enclave). This
//     closes the silent "no image binding" footgun. dstack register semantics +
//     the per-instance RTMR3 caveat are documented on `state::Config`.
//
// In the prior gnark design these fields were decoded from a separate
// `zkdcap_journal` blob; under UltraHonk the packed `public_inputs` ARE the
// journal, so the bytes come straight from `quartz_zkdcap`'s decoder.
#[cfg(not(feature = "mock"))]
struct ImagePins<'a> {
    mrtd: Option<&'a [u8]>,
    rtmr0: Option<&'a [u8]>,
    rtmr1: Option<&'a [u8]>,
    rtmr2: Option<&'a [u8]>,
    rtmr3: Option<&'a [u8]>,
    allow_any_image: bool,
}

// Verify one register if pinned. Returns Ok(true) if it was pinned (and matched),
// Ok(false) if unpinned, Err on wrong-length or mismatch.
#[cfg(not(feature = "mock"))]
fn check_reg(actual: &[u8; 48], expected: Option<&[u8]>, name: &str) -> Result<bool, Error> {
    match expected {
        None => Ok(false),
        Some(e) => {
            if e.len() != 48 {
                return Err(Error::ZkdcapVerificationFailed(format!(
                    "config.expected_{name} wrong length: expected 48, got {}",
                    e.len()
                )));
            }
            if actual.as_slice() != e {
                return Err(Error::ZkdcapVerificationFailed(format!(
                    "public_inputs {name} does not match config.expected_{name}"
                )));
            }
            Ok(true)
        }
    }
}

// report_data binding (always) + per-register image pins (enforce-if-set).
// Returns whether at least one register was pinned (feeds the require-one rule,
// which also counts the compose-hash binding done in the handler).
#[cfg(not(feature = "mock"))]
fn check_register_bindings(
    decoded: &quartz_zkdcap::DecodedQuote,
    expected_user_data: &[u8; 64],
    pins: &ImagePins<'_>,
) -> Result<bool, Error> {
    // report_data binding (always enforced)
    if &decoded.report_data != expected_user_data {
        return Err(Error::ZkdcapVerificationFailed(
            "public_inputs report_data does not match user_data".to_string(),
        ));
    }

    // Per-register image pins. measurements order: [MRTD, RTMR0, RTMR1, RTMR2, RTMR3].
    let m = &decoded.measurements;
    let mut any_pinned = false;
    any_pinned |= check_reg(&m[0], pins.mrtd, "mrtd")?;
    any_pinned |= check_reg(&m[1], pins.rtmr0, "rtmr0")?;
    any_pinned |= check_reg(&m[2], pins.rtmr1, "rtmr1")?;
    any_pinned |= check_reg(&m[3], pins.rtmr2, "rtmr2")?;
    any_pinned |= check_reg(&m[4], pins.rtmr3, "rtmr3")?;
    Ok(any_pinned)
}

// Bind the dstack compose-hash via RTMR3 event-log replay: parse the
// host-supplied event log, replay it against the PROOF-BOUND RTMR3, and
// verify-equal the compose-hash event payload to `expected`. Sound because the
// replay anchors on `decoded.rtmr3()` (from the verified proof) — a forged log
// can't replay to the same RTMR3.
#[cfg(not(feature = "mock"))]
fn check_compose_hash(
    decoded: &quartz_zkdcap::DecodedQuote,
    event_log: Option<&str>,
    expected: &[u8],
) -> Result<(), Error> {
    // An empty pin would bind nothing (an empty event payload would match it),
    // yet still satisfy the require-one rule. Reject it as a misconfiguration.
    if expected.is_empty() {
        return Err(Error::ZkdcapVerificationFailed(
            "config.expected_compose_hash is empty".to_string(),
        ));
    }
    let log_json = event_log.ok_or_else(|| {
        Error::ZkdcapVerificationFailed(
            "expected_compose_hash is set but the attestation carries no event_log".to_string(),
        )
    })?;
    let events: Vec<quartz_zkdcap::eventlog::TdxEvent> = serde_json::from_str(log_json)
        .map_err(|e| Error::ZkdcapVerificationFailed(format!("event_log parse: {e}")))?;
    quartz_zkdcap::eventlog::verify_compose_hash(&events, decoded.rtmr3(), expected)
        .map_err(|e| Error::ZkdcapVerificationFailed(format!("compose-hash binding: {e:?}")))
}

// ── DstackAttestation handler (raw quote) ──────────────────────────

/// Raw DCAP quote verification — FAILS CLOSED.
///
/// On-chain DCAP quote verification is not implemented. This handler does NOT
/// verify the raw TDX quote, and the surrounding `Attested<M,A>` wrapper only
/// compares `user_data` and `compose_hash`, both of which are HOST-SUPPLIED
/// fields (not extracted from the quote). Accepting here would let a malicious
/// host forge an attestation with attacker-chosen user_data/compose_hash and,
/// via the untagged `DstackAnyAttestation` fallback, downgrade a
/// zkdcap-configured contract to zero verification. So by default this rejects
/// with `Error::RawDcapUnsupported`; submit a `DstackZkAttestation` (zkdcap
/// UltraHonk proof) instead. A future native on-chain DCAP verifier would
/// replace this body. The `insecure-accept-raw-quote` feature reinstates the
/// old unverified-accept behaviour for dev/test against a trusted host only.
#[cfg(not(feature = "mock"))]
impl Handler for DstackAttestation {
    fn handle(
        self,
        _deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        #[cfg(not(feature = "insecure-accept-raw-quote"))]
        {
            Err(Error::RawDcapUnsupported)
        }
        // DANGER: opt-in, no verification. Never enable in production.
        #[cfg(feature = "insecure-accept-raw-quote")]
        {
            Ok(Response::new().add_attribute("action", "dcap_quote_unverified_accepted"))
        }
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

// ── DstackZkAttestation handler (zkdcap UltraHonk proof) ────────────

/// ZK proof verification via the Xion ZK module.
///
/// Verifies the dcap-noir UltraHonk proof through
/// `quartz_zkdcap::verify_quote_parts`: decode the packed public inputs,
/// range-check chain time against the proven `[valid_from, valid_until]` window,
/// reject either collateral evaluation-data number below its independent
/// configured floor, then verify the proof
/// via `/xion.zk.v1.Query/ProofVerifyUltraHonk`. Finally bind the decoded
/// report_data/rtmr3 to the wrapper. If no `zkdcap_vkey` is configured the
/// handler FAILS CLOSED (it cannot verify, so it must not accept); use a `mock`
/// build for verification-free dev/test.
#[cfg(not(feature = "mock"))]
impl Handler for DstackZkAttestation {
    fn handle(self, deps: DepsMut<'_>, env: &Env, _info: &MessageInfo) -> Result<Response, Error> {
        use quartz_zkdcap::{
            unix_to_packed_datetime, verify_quote_parts, EvalNumberPolicy, QuoteError,
            XionUltraHonkBackend,
        };

        // Read directly from the stored RawConfig — avoids a Config round-trip
        // (and the silent .ok() discard if Config::try_from were to fail for an
        // unrelated reason).
        let config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        // Secure-by-default: a non-mock contract with no vkey configured cannot
        // verify the proof, so it must NOT accept. Failing closed here mirrors
        // the raw-quote path; otherwise the wrapper's host-supplied user_data /
        // compose_hash checks would be the only gates and a forged
        // DstackZkAttestation would be accepted. Use the `mock` build for
        // verification-free dev/test.
        let Some(vkey_name) = config.zkdcap_vkey() else {
            return Err(Error::ZkdcapVerificationFailed(
                "no zkdcap_vkey configured: refusing to accept an unverified attestation"
                    .to_string(),
            ));
        };

        let backend = XionUltraHonkBackend::by_name(deps.querier, vkey_name.to_string());
        let now_packed = unix_to_packed_datetime(env.block.time.seconds());

        let decoded = verify_quote_parts(
            &backend,
            &self.zkdcap_proof,
            &self.zkdcap_public_inputs,
            now_packed,
            EvalNumberPolicy::new(config.min_tcb_eval_num(), config.min_qe_eval_num()),
            config.max_tcb_status(),
        )
        .map_err(|e| {
            Error::ZkdcapVerificationFailed(
                match e {
                    QuoteError::Malformed => "malformed public_inputs",
                    QuoteError::StaleOrFuture => {
                        "attestation outside validity window or collateral eval below floor"
                    }
                    QuoteError::TcbStatusUnacceptable => {
                        "tcb_status severity exceeds config.max_tcb_status"
                    }
                    QuoteError::ProofInvalid => "proof verification returned false",
                }
                .to_string(),
            )
        })?;

        let pins = ImagePins {
            mrtd: config.expected_mrtd(),
            rtmr0: config.expected_rtmr0(),
            rtmr1: config.expected_rtmr1(),
            rtmr2: config.expected_rtmr2(),
            rtmr3: config.expected_rtmr3(),
            allow_any_image: config.allow_any_image(),
        };
        // report_data (always) + per-register pins.
        let mut any_pinned = check_register_bindings(&decoded, &self.user_data, &pins)?;

        // compose-hash binding (preferred app pin) via RTMR3 event-log replay.
        if let Some(expected) = config.expected_compose_hash() {
            check_compose_hash(&decoded, self.event_log.as_deref(), expected)?;
            any_pinned = true;
        }

        // Secure-by-default: verifying without ANY image binding (no register
        // and no compose-hash) requires an explicit opt-in.
        if !any_pinned && !pins.allow_any_image {
            return Err(Error::ZkdcapVerificationFailed(
                "no image binding configured: set expected_compose_hash / expected_mrtd / \
                 expected_rtmr0..3, or allow_any_image"
                    .to_string(),
            ));
        }

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
    fn handle(self, deps: DepsMut<'_>, env: &Env, info: &MessageInfo) -> Result<Response, Error> {
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
    #![allow(clippy::unwrap_used)]
    use super::*;
    use quartz_zkdcap::{DecodedQuote, MEASUREMENT_REGS};

    fn decoded_with(report_data: [u8; 64], rtmr3: [u8; 48]) -> DecodedQuote {
        let mut measurements = [[0u8; 48]; MEASUREMENT_REGS];
        measurements[4] = rtmr3; // RTMR3 is register index 4
        DecodedQuote {
            report_data,
            measurements,
            measurement_digest: [0u8; 32],
            tcb_status: 0,
            timestamp: 0,
            cert_serial: [0u8; 20],
            fmspc: [0u8; 6],
            tcb_eval_num: 0,
            qe_eval_num: 0,
            valid_from: 0,
            valid_until: 0,
        }
    }

    // Full DecodedQuote with explicit per-register measurements.
    fn decoded_full(
        report_data: [u8; 64],
        measurements: [[u8; 48]; MEASUREMENT_REGS],
    ) -> DecodedQuote {
        DecodedQuote {
            report_data,
            measurements,
            measurement_digest: [0u8; 32],
            tcb_status: 0,
            timestamp: 0,
            cert_serial: [0u8; 20],
            fmspc: [0u8; 6],
            tcb_eval_num: 0,
            qe_eval_num: 0,
            valid_from: 0,
            valid_until: 0,
        }
    }

    fn no_pins(allow_any_image: bool) -> ImagePins<'static> {
        ImagePins {
            mrtd: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            allow_any_image,
        }
    }

    #[test]
    fn report_data_binding_accepts_matching() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        // allow_any_image so the require-one rule doesn't fire for this case.
        check_register_bindings(&d, &user_data, &no_pins(true)).unwrap();
    }

    #[test]
    fn report_data_binding_rejects_mismatch() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with([0xCCu8; 64], [0xBBu8; 48]);
        let err = check_register_bindings(&d, &user_data, &no_pins(true)).unwrap_err();
        assert!(format!("{err}").contains("report_data"));
    }

    #[test]
    fn rtmr3_binding_accepts_matching_when_pinned() {
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xBBu8; 48];
        let d = decoded_with(user_data, rtmr3);
        let mut p = no_pins(false);
        p.rtmr3 = Some(&rtmr3);
        check_register_bindings(&d, &user_data, &p).unwrap();
    }

    #[test]
    fn rtmr3_binding_rejects_mismatch_when_pinned() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xCCu8; 48]);
        let want = [0xBBu8; 48];
        let mut p = no_pins(false);
        p.rtmr3 = Some(&want);
        let err = check_register_bindings(&d, &user_data, &p).unwrap_err();
        assert!(format!("{err}").contains("rtmr3"));
    }

    #[test]
    fn mrtd_and_rtmr1_pins_enforced() {
        let user_data = [0xAAu8; 64];
        let mut m = [[0u8; 48]; MEASUREMENT_REGS];
        m[0] = [0x11; 48]; // MRTD
        m[2] = [0x22; 48]; // RTMR1
        let d = decoded_full(user_data, m);
        // both match -> ok
        let mrtd = [0x11u8; 48];
        let rtmr1 = [0x22u8; 48];
        let mut p = no_pins(false);
        p.mrtd = Some(&mrtd);
        p.rtmr1 = Some(&rtmr1);
        check_register_bindings(&d, &user_data, &p).unwrap();
        // mrtd mismatch -> err naming mrtd
        let bad = [0x99u8; 48];
        let mut p2 = no_pins(false);
        p2.mrtd = Some(&bad);
        let err = check_register_bindings(&d, &user_data, &p2).unwrap_err();
        assert!(format!("{err}").contains("mrtd"));
    }

    #[test]
    fn any_pinned_flag_reflects_register_pins() {
        // The require-one rule is applied in the handler off this bool; here we
        // verify the bool: false when nothing is pinned, true when a register is.
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        assert!(!check_register_bindings(&d, &user_data, &no_pins(false)).unwrap());
        let rtmr3 = [0xBBu8; 48];
        let mut p = no_pins(false);
        p.rtmr3 = Some(&rtmr3);
        assert!(check_register_bindings(&d, &user_data, &p).unwrap());
    }

    #[test]
    fn rejects_wrong_length_pin() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        // 32-byte rtmr3 pin when 48 is required
        let short = [0u8; 32];
        let mut p = no_pins(false);
        p.rtmr3 = Some(&short);
        let err = check_register_bindings(&d, &user_data, &p).unwrap_err();
        assert!(format!("{err}").contains("wrong length"));
    }

    // ── compose-hash binding (RTMR3 event-log replay) ──────────────────

    // Build a dstack-shaped event log JSON + the RTMR3 it replays to.
    fn compose_log_and_rtmr3(compose_hex: &str) -> (String, [u8; 48]) {
        use quartz_zkdcap::eventlog::{replay_rtmr3, TdxEvent, DSTACK_RUNTIME_EVENT_TYPE};
        let json = format!(
            r#"[{{"imr":3,"event_type":{t},"digest":"","event":"compose-hash","event_payload":"{c}"}},
                {{"imr":3,"event_type":{t},"digest":"","event":"app-id","event_payload":"00"}}]"#,
            t = DSTACK_RUNTIME_EVENT_TYPE,
            c = compose_hex
        );
        let events: Vec<TdxEvent> = serde_json::from_str(&json).unwrap();
        (json, replay_rtmr3(&events))
    }

    fn decoded_rtmr3(rtmr3: [u8; 48]) -> DecodedQuote {
        decoded_with([0xAAu8; 64], rtmr3)
    }

    #[test]
    fn compose_hash_binding_accepts_matching() {
        let (log, rtmr3) = compose_log_and_rtmr3("abcd");
        let d = decoded_rtmr3(rtmr3);
        check_compose_hash(&d, Some(&log), &[0xAB, 0xCD]).unwrap();
    }

    #[test]
    fn compose_hash_binding_rejects_wrong_expected() {
        let (log, rtmr3) = compose_log_and_rtmr3("abcd");
        let d = decoded_rtmr3(rtmr3);
        let err = check_compose_hash(&d, Some(&log), &[0x00, 0x11]).unwrap_err();
        assert!(format!("{err}").contains("compose-hash"));
    }

    #[test]
    fn compose_hash_binding_rejects_log_not_matching_rtmr3() {
        // event log replays to a different RTMR3 than the (proof-bound) one.
        let (log, _rtmr3) = compose_log_and_rtmr3("abcd");
        let d = decoded_rtmr3([0x77u8; 48]); // wrong anchor
        let err = check_compose_hash(&d, Some(&log), &[0xAB, 0xCD]).unwrap_err();
        assert!(
            format!("{err}").contains("Rtmr3Mismatch") || format!("{err}").contains("compose-hash")
        );
    }

    #[test]
    fn compose_hash_binding_requires_event_log() {
        let d = decoded_rtmr3([0u8; 48]);
        let err = check_compose_hash(&d, None, &[0xAB]).unwrap_err();
        assert!(format!("{err}").contains("event_log"));
    }

    // ── raw DstackAttestation handler fails closed ─────────────────────

    // The raw-quote path does zero TDX verification; by default (no
    // `insecure-accept-raw-quote` feature) it must reject so a host cannot
    // submit a forged/unverified quote, nor downgrade a zkdcap-configured
    // contract via the untagged DstackAnyAttestation fallback.
    #[cfg(not(feature = "insecure-accept-raw-quote"))]
    #[test]
    fn raw_dstack_handler_fails_closed() {
        use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
        let mut deps = mock_dependencies();
        let env = mock_env();
        let sender = deps.api.addr_make("sender");
        let info = message_info(&sender, &[]);
        let att = DstackAttestation::new([0u8; 64], [0u8; 32], vec![1, 2, 3], None);
        let err = Handler::handle(att, deps.as_mut(), &env, &info).unwrap_err();
        assert!(matches!(err, Error::RawDcapUnsupported));
    }

    // ── DstackZkAttestation handler fails closed when no vkey is configured ──

    // A non-mock contract with zkdcap_vkey=None cannot verify the proof; it must
    // reject rather than skip (the old fail-open path accepted any forged
    // DstackZkAttestation because the only other gates compare host-supplied
    // fields).
    #[test]
    fn zk_handler_no_vkey_fails_closed() {
        use crate::state::{Config, LightClientOpts, RawConfig, CONFIG};
        use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

        let mut deps = mock_dependencies();
        let env = mock_env();
        let sender = deps.api.addr_make("sender");
        let info = message_info(&sender, &[]);

        let lco = LightClientOpts::new(
            "testing".to_string(),
            1,
            [0u8; 32],
            (2, 3),
            1209600,
            300,
            600,
        )
        .unwrap();
        // zkdcap_vkey = None
        let cfg: RawConfig = Config::new([0u8; 32], lco, None).into();
        CONFIG.save(deps.as_mut().storage, &cfg).unwrap();

        let att =
            DstackZkAttestation::new([0u8; 64], [0u8; 32], vec![1, 2, 3], vec![0u8; 672], None);
        let err = Handler::handle(att, deps.as_mut(), &env, &info).unwrap_err();
        assert!(matches!(err, Error::ZkdcapVerificationFailed(_)));
    }
}
