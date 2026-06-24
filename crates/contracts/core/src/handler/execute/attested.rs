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
// (2) rtmr3 binding (compose_hash transitive): enforced when
//     `config.expected_rtmr3` is set. The public-inputs `rtmr3` (48-byte
//     SHA-384 TDX measurement register) is verified-equal against the
//     on-chain-pinned value. When `None`, skipped (backwards-compat); the
//     residual "wrong-image-attestation" vector remains open until pinned.
//
// In the prior gnark design these fields were decoded from a separate
// `zkdcap_journal` blob; under UltraHonk the packed `public_inputs` ARE the
// journal, so the bytes come straight from `quartz_zkdcap`'s decoder.
#[cfg(not(feature = "mock"))]
fn check_zk_bindings(
    decoded: &quartz_zkdcap::DecodedQuote,
    expected_user_data: &[u8; 64],
    expected_rtmr3: Option<&[u8]>,
) -> Result<(), Error> {
    // report_data binding (always enforced)
    if &decoded.report_data != expected_user_data {
        return Err(Error::ZkdcapVerificationFailed(
            "public_inputs report_data does not match user_data".to_string(),
        ));
    }

    // rtmr3 binding (conditional on config.expected_rtmr3 being set)
    if let Some(expected) = expected_rtmr3 {
        if expected.len() != 48 {
            return Err(Error::ZkdcapVerificationFailed(format!(
                "config.expected_rtmr3 wrong length: expected 48, got {}",
                expected.len()
            )));
        }
        if decoded.rtmr3().as_slice() != expected {
            return Err(Error::ZkdcapVerificationFailed(
                "public_inputs rtmr3 does not match config.expected_rtmr3".to_string(),
            ));
        }
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

        check_zk_bindings(&decoded, &self.user_data, config.expected_rtmr3())?;

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
            valid_from: 0,
            valid_until: 0,
        }
    }

    #[test]
    fn report_data_binding_accepts_matching() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        check_zk_bindings(&d, &user_data, None).unwrap();
    }

    #[test]
    fn report_data_binding_rejects_mismatch() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with([0xCCu8; 64], [0xBBu8; 48]);
        let err = check_zk_bindings(&d, &user_data, None).unwrap_err();
        assert!(format!("{err}").contains("report_data"));
    }

    #[test]
    fn rtmr3_binding_accepts_matching_when_pinned() {
        let user_data = [0xAAu8; 64];
        let rtmr3 = [0xBBu8; 48];
        let d = decoded_with(user_data, rtmr3);
        check_zk_bindings(&d, &user_data, Some(&rtmr3)).unwrap();
    }

    #[test]
    fn rtmr3_binding_rejects_mismatch_when_pinned() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xCCu8; 48]);
        let err = check_zk_bindings(&d, &user_data, Some(&[0xBBu8; 48])).unwrap_err();
        assert!(format!("{err}").contains("rtmr3"));
    }

    #[test]
    fn rtmr3_binding_skipped_when_none() {
        // With no expected_rtmr3 pinned, any rtmr3 is accepted (backwards-compat
        // for deployments that pre-date the config field).
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xCCu8; 48]);
        check_zk_bindings(&d, &user_data, None).unwrap();
    }

    #[test]
    fn rejects_wrong_length_expected_rtmr3() {
        let user_data = [0xAAu8; 64];
        let d = decoded_with(user_data, [0xBBu8; 48]);
        // 32-byte expected_rtmr3 when 48 is required
        let err = check_zk_bindings(&d, &user_data, Some(&[0u8; 32])).unwrap_err();
        assert!(format!("{err}").contains("wrong length"));
    }
}
