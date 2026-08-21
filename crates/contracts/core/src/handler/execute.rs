pub mod attested;
pub mod sequenced;
pub mod session_create;
pub mod session_set_pub_key;
pub mod set_fmspc_policy;
pub mod set_qe_eval_floor;
pub mod set_tcb_eval_floor;
pub mod signed;

use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::{
        attested::{Attestation, HasUserData},
        Execute,
    },
};

impl<A> Handler for Execute<A>
where
    A: Handler + HasUserData + Attestation,
{
    fn handle(self, deps: DepsMut<'_>, env: &Env, info: &MessageInfo) -> Result<Response, Error> {
        match self {
            Execute::SessionCreate(msg) => msg.handle(deps, env, info),
            Execute::SessionSetPubKey(msg) => msg.handle(deps, env, info),
            Execute::SetTcbEvalFloor(msg) => msg.handle(deps, env, info),
            Execute::SetQeEvalFloor(msg) => msg.handle(deps, env, info),
            Execute::SetFmspcPolicy(msg) => msg.handle(deps, env, info),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

    use crate::{
        handler::RawHandler,
        msg::execute::{attested::RawDefaultAttestation, RawExecute},
        state::{Config, LightClientOpts, RawConfig, CONFIG},
    };

    /// Wire-level path the deployed contract actually takes: JSON body ->
    /// `RawExecute` -> `Execute` -> dispatch -> handler. The per-handler tests
    /// call `handle` directly, so they cannot catch a wrong serde rename or a
    /// missing dispatch arm.
    #[test]
    fn set_qe_eval_floor_raises_through_raw_dispatch() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        let lco = LightClientOpts::new(
            "testing".to_string(),
            1,
            [0u8; 32],
            (2, 3),
            1_209_600,
            300,
            600,
        )
        .unwrap();
        let raw: RawConfig = Config::new([0u8; 32], lco, None)
            .with_eval_num_floors(15, 17)
            .with_admin(admin.clone())
            .into();
        CONFIG.save(deps.as_mut().storage, &raw).unwrap();

        let msg: RawExecute<RawDefaultAttestation> =
            serde_json::from_str(r#"{"set_qe_eval_floor":{"min_qe_eval_num":21}}"#).unwrap();
        let info = message_info(&admin, &[]);
        let res = msg.handle_raw(deps.as_mut(), &mock_env(), &info).unwrap();

        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "action" && a.value == "set_qe_eval_floor"));
        let stored = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(stored.min_qe_eval_num(), 21);
        assert_eq!(stored.min_tcb_eval_num(), 15);
    }

    /// Same wire-level path for the FMSPC-authorization policy. Its handler tests
    /// construct the message in Rust, so only this one pins the JSON key and the
    /// dispatch arm.
    #[test]
    fn set_fmspc_policy_tightens_through_raw_dispatch() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        let lco = LightClientOpts::new(
            "testing".to_string(),
            1,
            [0u8; 32],
            (2, 3),
            1_209_600,
            300,
            600,
        )
        .unwrap();
        let raw: RawConfig = Config::new([0u8; 32], lco, None)
            .with_admin(admin.clone())
            .into();
        CONFIG.save(deps.as_mut().storage, &raw).unwrap();
        assert!(!CONFIG
            .load(deps.as_ref().storage)
            .unwrap()
            .require_registered_fmspc());

        let msg: RawExecute<RawDefaultAttestation> =
            serde_json::from_str(r#"{"set_fmspc_policy":{"require_registered_fmspc":true}}"#)
                .unwrap();
        let info = message_info(&admin, &[]);
        let res = msg.handle_raw(deps.as_mut(), &mock_env(), &info).unwrap();

        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "action" && a.value == "set_fmspc_policy"));
        assert!(CONFIG
            .load(deps.as_ref().storage)
            .unwrap()
            .require_registered_fmspc());
    }
}
