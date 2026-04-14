use cosmwasm_std::{to_json_binary, CosmosMsg, DepsMut, Env, MessageInfo, Response, WasmMsg};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::attested::{
        Attestation, Attested, DstackAttestation, HasUserData, MockAttestation, Noop,
    },
    state::CONFIG,
};

/// zkdcap verifier ExecuteMsg (subset — only what we need to call)
#[cosmwasm_schema::cw_serde]
enum ZkdcapExecuteMsg {
    VerifyAttestation {
        proof: cosmwasm_std::Binary,
        public_inputs: Vec<String>,
        journal: cosmwasm_std::Binary,
    },
}

impl Handler for DstackAttestation {
    fn handle(
        self,
        deps: DepsMut<'_>,
        _env: &Env,
        _info: &MessageInfo,
    ) -> Result<Response, Error> {
        let config = CONFIG.load(deps.storage).map_err(Error::Std)?;
        let verifier_addr = config
            .zkdcap_verifier()
            .ok_or(Error::ZkdcapVerifierNotConfigured)?
            .to_string();

        // Build the cross-contract call to the zkdcap verifier.
        // If verification fails, the submessage reverts the entire tx.
        let verify_msg = ZkdcapExecuteMsg::VerifyAttestation {
            proof: self.zkdcap_proof.into(),
            public_inputs: self.zkdcap_public_inputs,
            journal: self.zkdcap_journal.into(),
        };

        let msg = CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: verifier_addr,
            msg: to_json_binary(&verify_msg).map_err(Error::Std)?,
            funds: vec![],
        });

        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "zkdcap_verify"))
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
