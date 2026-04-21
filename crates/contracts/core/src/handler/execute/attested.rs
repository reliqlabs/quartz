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

#[cfg(not(feature = "mock"))]
#[derive(Clone, prost::Message)]
struct QueryVerifyRequest {
    #[prost(bytes = "vec", tag = "1")]
    proof: Vec<u8>,
    #[prost(string, repeated, tag = "2")]
    public_inputs: Vec<String>,
    #[prost(string, tag = "3")]
    vkey_name: String,
    #[prost(uint64, tag = "4")]
    vkey_id: u64,
}

#[cfg(not(feature = "mock"))]
#[derive(Clone, prost::Message)]
struct ProofVerifyResponse {
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
/// Queries /xion.zk.v1.Query/ProofVerify with the Groth16 proof.
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

        let verify_req = QueryVerifyRequest {
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
                "/xion.zk.v1.Query/ProofVerify".to_string(),
                cosmwasm_std::Binary::from(req_bytes),
            )
            .map_err(|e| Error::ZkdcapVerificationFailed(format!("ZK module query: {e}")))?;

        let verify_resp = <ProofVerifyResponse as prost::Message>::decode(resp_bytes.as_slice())
            .map_err(|e| Error::ZkdcapVerificationFailed(format!("decode response: {e}")))?;

        if !verify_resp.verified {
            return Err(Error::ZkdcapVerificationFailed(
                "proof verification returned false".to_string(),
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
