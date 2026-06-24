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

#[cfg(not(feature = "mock"))]
fn check_zk_bindings(
    decoded: &quartz_zkdcap::DecodedQuote,
    expected_user_data: &[u8; 64],
    pins: &ImagePins<'_>,
) -> Result<(), Error> {
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

    // Secure-by-default: verifying without any image pin requires an explicit
    // opt-in (the image is then unbound — trust any genuine TDX enclave).
    if !any_pinned && !pins.allow_any_image {
        return Err(Error::ZkdcapVerificationFailed(
            "no image register pinned: set expected_mrtd/rtmr0/rtmr1/rtmr2/rtmr3 or allow_any_image".to_string(),
        ));
    }

    Ok(())
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

// ── DstackZkAttestation handler (zkdcap UltraHonk proof) ────────────

/// ZK proof verification via the Xion ZK module.
///
/// Verifies the dcap-noir UltraHonk proof through
/// `quartz_zkdcap::verify_quote_parts`: decode the packed public inputs,
/// range-check chain time against the proven `[valid_from, valid_until]` window,
/// reject `tcb_eval_num` below `config.min_tcb_eval_num`, then verify the proof
/// via `/xion.zk.v1.Query/ProofVerifyUltraHonk`. Finally bind the decoded
/// report_data/rtmr3 to the wrapper. If no `zkdcap_vkey` is configured,
/// verification is skipped.
#[cfg(not(feature = "mock"))]
impl Handler for DstackZkAttestation {
    fn handle(
        self,
        deps: DepsMut<'_>,
        env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        use quartz_zkdcap::{
            unix_to_packed_datetime, verify_quote_parts, QuoteError, XionUltraHonkBackend,
        };

        // Read directly from the stored RawConfig — avoids a Config round-trip
        // (and the silent .ok() discard if Config::try_from were to fail for an
        // unrelated reason).
        let config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        let Some(vkey_name) = config.zkdcap_vkey() else {
            return Ok(Response::new().add_attribute("action", "zkdcap_verify_skipped"));
        };

        let backend = XionUltraHonkBackend::by_name(deps.querier, vkey_name.to_string());
        let now_packed = unix_to_packed_datetime(env.block.time.seconds());

        let decoded = verify_quote_parts(
            &backend,
            &self.zkdcap_proof,
            &self.zkdcap_public_inputs,
            now_packed,
            config.min_tcb_eval_num(),
        )
        .map_err(|e| {
            Error::ZkdcapVerificationFailed(
                match e {
                    QuoteError::Malformed => "malformed public_inputs",
                    QuoteError::StaleOrFuture => {
                        "attestation outside validity window or tcb_eval below floor"
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
        check_zk_bindings(&decoded, &self.user_data, &pins)?;

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
            tcb_eval_num: 0,
            qe_eval_num: 0,
            valid_from: 0,
            valid_until: 0,
        }
    }

    // Full DecodedQuote with explicit per-register measurements.
    fn decoded_full(report_data: [u8; 64], measurements: [[u8; 48]; MEASUREMENT_REGS]) -> DecodedQuote {
        DecodedQuote {
            report_data,
            measurements,
            measurement_digest: [0u8; 32],
            tcb_status: 0,
            timestamp: 0,
            tcb_eval_num: 0,
            qe_eval_num: 0,
            valid_from: 0,
            valid_until: 0,
        }
    }

    fn no_pins(allow_any_image: bool) -> ImagePins<'static> {
        ImagePins { mrtd: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None, allow_any_image }
    }

    #[test]
    fn report_data_binding_accepts_matching() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        // allow_any_image so the require-one rule doesn't fire for this case.
        check_zk_bindings(&d, &user_data, &no_pins(true)).unwrap();
    }

    #[test]
    fn report_data_binding_rejects_mismatch() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with([0xCCu8; 64], [0xBBu8; 48]);
        let err = check_zk_bindings(&d, &user_data, &no_pins(true)).unwrap_err();
        assert!(format!("{err}").contains("report_data"));
    }

    #[test]
    fn rtmr3_binding_accepts_matching_when_pinned() {
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xBBu8; 48];
        let d = decoded_with(user_data, rtmr3);
        let mut p = no_pins(false);
        p.rtmr3 = Some(&rtmr3);
        check_zk_bindings(&d, &user_data, &p).unwrap();
    }

    #[test]
    fn rtmr3_binding_rejects_mismatch_when_pinned() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xCCu8; 48]);
        let want = [0xBBu8; 48];
        let mut p = no_pins(false);
        p.rtmr3 = Some(&want);
        let err = check_zk_bindings(&d, &user_data, &p).unwrap_err();
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
        check_zk_bindings(&d, &user_data, &p).unwrap();
        // mrtd mismatch -> err naming mrtd
        let bad = [0x99u8; 48];
        let mut p2 = no_pins(false);
        p2.mrtd = Some(&bad);
        let err = check_zk_bindings(&d, &user_data, &p2).unwrap_err();
        assert!(format!("{err}").contains("mrtd"));
    }

    #[test]
    fn secure_by_default_rejects_when_no_pin_and_not_allowed() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xCCu8; 48]);
        let err = check_zk_bindings(&d, &user_data, &no_pins(false)).unwrap_err();
        assert!(format!("{err}").contains("no image register pinned"));
    }

    #[test]
    fn allow_any_image_permits_no_pin() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xCCu8; 48]);
        check_zk_bindings(&d, &user_data, &no_pins(true)).unwrap();
    }

    #[test]
    fn rejects_wrong_length_pin() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        // 32-byte rtmr3 pin when 48 is required
        let short = [0u8; 32];
        let mut p = no_pins(false);
        p.rtmr3 = Some(&short);
        let err = check_zk_bindings(&d, &user_data, &p).unwrap_err();
        assert!(format!("{err}").contains("wrong length"));
    }
}
