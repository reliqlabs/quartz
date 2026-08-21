use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdError};

use crate::{error::Error, handler::Handler, msg::execute::SetFmspcPolicy, state::CONFIG};

impl Handler for SetFmspcPolicy {
    // O3 companion to the eval-number floors: governed, tighten-only
    // FMSPC-authorization update.
    //
    // Same authority rule as both floors: only the configured `config.admin` may
    // change it, and the update FAILS CLOSED when no admin is configured (legacy
    // / unset state).
    //
    // Direction is enforced by `RawConfig::tighten_require_registered_fmspc`, not
    // by this handler: turning the requirement on restricts which platform
    // families may attest, and turning it back off would silently re-admit every
    // unenumerated platform. That is a downgrade an admin key should not be able
    // to perform by accident, so the type refuses it and the correct way to admit
    // another family is `SetTcbEvalFloor` on that FMSPC.
    //
    // The flag lives on the stored config rather than in a `Map`, for the same
    // reason as the QE floor: it is a contract-wide policy with no platform key
    // to shard on, and keeping it there means every existing `Config` query
    // already exposes the policy in force.
    fn handle(self, deps: DepsMut<'_>, _env: &Env, info: &MessageInfo) -> Result<Response, Error> {
        let mut config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        let Some(admin) = config.admin() else {
            return Err(Error::Std(StdError::msg(
                "unauthorized: no admin configured; FMSPC policy updates are governed",
            )));
        };
        if info.sender.as_str() != admin {
            return Err(Error::Std(StdError::msg(
                "unauthorized: only the configured admin may update the FMSPC policy",
            )));
        }

        if !self.require_registered_fmspc {
            return Err(Error::Std(StdError::msg(
                "require_registered_fmspc may only be set to true; \
                 to admit another platform family register its FMSPC with SetTcbEvalFloor",
            )));
        }

        let previous = config.tighten_require_registered_fmspc().map_err(|_| {
            Error::Std(StdError::msg(
                "require_registered_fmspc is already enabled; it cannot be disabled",
            ))
        })?;
        CONFIG.save(deps.storage, &config).map_err(Error::Std)?;

        Ok(Response::new()
            .add_attribute("action", "set_fmspc_policy")
            .add_attribute("previous_require_registered_fmspc", previous.to_string())
            .add_attribute("require_registered_fmspc", "true"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use cosmwasm_std::{
        testing::{message_info, mock_dependencies, mock_env},
        Addr,
    };

    use super::*;
    use crate::state::RawConfig;

    fn light_client_opts() -> crate::state::LightClientOpts {
        crate::state::LightClientOpts::new(
            "testing".to_string(),
            1,
            [0u8; 32],
            (2, 3),
            1_209_600,
            300,
            600,
        )
        .unwrap()
    }

    fn save_config(deps: DepsMut<'_>, admin: Option<Addr>, require: bool) {
        let mut cfg = crate::state::Config::new([0u8; 32], light_client_opts(), None)
            .with_require_registered_fmspc(require);
        if let Some(admin) = admin {
            cfg = cfg.with_admin(admin);
        }
        let raw: RawConfig = cfg.into();
        CONFIG.save(deps.storage, &raw).unwrap();
    }

    fn stored(deps: &DepsMut<'_>) -> bool {
        CONFIG
            .load(deps.storage)
            .unwrap()
            .require_registered_fmspc()
    }

    fn msg(require: bool) -> SetFmspcPolicy {
        SetFmspcPolicy {
            require_registered_fmspc: require,
        }
    }

    #[test]
    fn fails_closed_without_admin() {
        let mut deps = mock_dependencies();
        save_config(deps.as_mut(), None, false);
        let sender = deps.api.addr_make("anyone");
        let err = msg(true)
            .handle(deps.as_mut(), &mock_env(), &message_info(&sender, &[]))
            .unwrap_err();
        assert!(err.to_string().contains("no admin configured"));
        assert!(!stored(&deps.as_mut()), "policy must not change");
    }

    #[test]
    fn rejects_non_admin() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin), false);
        let sender = deps.api.addr_make("intruder");
        let err = msg(true)
            .handle(deps.as_mut(), &mock_env(), &message_info(&sender, &[]))
            .unwrap_err();
        assert!(err.to_string().contains("only the configured admin"));
        assert!(!stored(&deps.as_mut()), "policy must not change");
    }

    #[test]
    fn admin_can_tighten() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), false);
        let res = msg(true)
            .handle(deps.as_mut(), &mock_env(), &message_info(&admin, &[]))
            .unwrap();
        assert!(stored(&deps.as_mut()), "policy must be enabled");
        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "require_registered_fmspc" && a.value == "true"));
        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "previous_require_registered_fmspc" && a.value == "false"));
    }

    #[test]
    fn admin_cannot_loosen() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), true);
        let err = msg(false)
            .handle(deps.as_mut(), &mock_env(), &message_info(&admin, &[]))
            .unwrap_err();
        assert!(err.to_string().contains("may only be set to true"));
        assert!(stored(&deps.as_mut()), "policy must stay enabled");
    }

    #[test]
    fn re_enabling_is_rejected_rather_than_silently_ok() {
        // Guards the type-level refusal: an already-tightened policy reports the
        // conflict instead of pretending the write happened.
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), true);
        let err = msg(true)
            .handle(deps.as_mut(), &mock_env(), &message_info(&admin, &[]))
            .unwrap_err();
        assert!(err.to_string().contains("already enabled"));
        assert!(stored(&deps.as_mut()));
    }
}
