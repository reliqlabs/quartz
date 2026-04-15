use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::attested::{
        Attestation, Attested, DstackAttestation, HasUserData, MockAttestation, Noop,
    },
    state::CONFIG,
};

/// Protobuf: xion.zk.v1.QueryVerifyRequest
#[cfg(not(feature = "mock-sgx"))]
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

/// Protobuf: xion.zk.v1.ProofVerifyResponse
#[cfg(not(feature = "mock-sgx"))]
#[derive(Clone, prost::Message)]
struct ProofVerifyResponse {
    #[prost(bool, tag = "1")]
    verified: bool,
}

#[cfg(not(feature = "mock-sgx"))]
impl Handler for DstackAttestation {
    fn handle(
        self,
        deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        let config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        // If no vkey is configured, skip on-chain verification.
        let Some(vkey_name) = config.zkdcap_vkey() else {
            return Ok(Response::new()
                .add_attribute("action", "zkdcap_verify_skipped"));
        };

        // Query Xion's ZK module directly
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

#[cfg(feature = "mock-sgx")]
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
            // if we weren't able to load then the context was from InstantiateMsg so we don't fail
            // in such cases, the InstantiateMsg handler will verify that the mr_enclave matches
            if config.mr_enclave() != attestation.mr_enclave() {
                return Err(Error::MrEnclaveMismatch);
            }
        }

        // handle message first, this has 2 benefits -
        // 1. we avoid (the more expensive) attestation verification if the message handler fails
        // 2. we allow the message handler to make changes to the config so that the attestation
        //    handler can use those changes, e.g. InstantiateMsg
        // return response from msg handle to include pub_key attribute
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
