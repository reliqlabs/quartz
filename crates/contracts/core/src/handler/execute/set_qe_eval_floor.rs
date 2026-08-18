use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdError};

use crate::{error::Error, handler::Handler, msg::execute::SetQeEvalFloor, state::CONFIG};

impl Handler for SetQeEvalFloor {
    // O3 companion to `SetTcbEvalFloor`: governed, raise-only QE-Identity floor
    // update.
    //
    // Same authority rule as the TCB floor: only the configured `config.admin`
    // may raise it, and the update FAILS CLOSED when no admin is configured
    // (legacy / unset state). Monotonicity is enforced by
    // `RawConfig::raise_min_qe_eval_num` against the floor currently in force,
    // which for legacy state is the inherited TCB floor rather than zero.
    //
    // The floor lives on the stored config, not in a `Map`: Intel serves one QE
    // Identity per TEE type, so there is no platform key to shard on, and the
    // attestation path already reads `RawConfig::min_qe_eval_num`. That means
    // this handler needs no change in `attested.rs` and the raised floor stays
    // visible to every existing `Config` query.
    fn handle(self, deps: DepsMut<'_>, _env: &Env, info: &MessageInfo) -> Result<Response, Error> {
        let mut config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        let Some(admin) = config.admin() else {
            return Err(Error::Std(StdError::msg(
                "unauthorized: no admin configured; QE floor updates are governed",
            )));
        };
        if info.sender.as_str() != admin {
            return Err(Error::Std(StdError::msg(
                "unauthorized: only the configured admin may update QE floors",
            )));
        }

        let previous = config
            .raise_min_qe_eval_num(self.min_qe_eval_num)
            .map_err(|current| {
                Error::Std(StdError::msg(format!(
                    "raise-only violation: new QE floor {} is below current floor {current}",
                    self.min_qe_eval_num
                )))
            })?;

        CONFIG.save(deps.storage, &config).map_err(Error::Std)?;

        Ok(Response::new()
            .add_attribute("action", "set_qe_eval_floor")
            .add_attribute("previous_min_qe_eval_num", previous.to_string())
            .add_attribute("min_qe_eval_num", self.min_qe_eval_num.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::Addr;

    use crate::state::{Config, LightClientOpts, RawConfig, TCB_FLOORS};

    const FMSPC: [u8; 6] = [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00];

    fn light_client_opts() -> LightClientOpts {
        LightClientOpts::new(
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

    /// Stores a config with independent TCB and QE floors, so every test can
    /// assert that moving one leaves the other alone.
    fn save_config(deps: DepsMut<'_>, admin: Option<Addr>, tcb_floor: u64, qe_floor: u64) {
        let mut config = Config::new([0u8; 32], light_client_opts(), None)
            .with_eval_num_floors(tcb_floor, qe_floor);
        if let Some(admin) = admin {
            config = config.with_admin(admin);
        }
        let raw: RawConfig = config.into();
        CONFIG.save(deps.storage, &raw).unwrap();
    }

    fn stored_qe_floor(deps: &DepsMut<'_>) -> u64 {
        CONFIG.load(deps.storage).unwrap().min_qe_eval_num()
    }

    fn msg(min_qe_eval_num: u64) -> SetQeEvalFloor {
        SetQeEvalFloor { min_qe_eval_num }
    }

    #[test]
    fn fails_closed_when_no_admin_configured() {
        let mut deps = mock_dependencies();
        let sender = deps.api.addr_make("anyone");
        save_config(deps.as_mut(), None, 15, 15);
        let info = message_info(&sender, &[]);
        let err = msg(20)
            .handle(deps.as_mut(), &mock_env(), &info)
            .unwrap_err();
        assert!(format!("{err}").contains("no admin configured"));
        assert_eq!(stored_qe_floor(&deps.as_mut()), 15);
    }

    #[test]
    fn rejects_non_admin_sender() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        let attacker = deps.api.addr_make("attacker");
        save_config(deps.as_mut(), Some(admin), 15, 15);
        let info = message_info(&attacker, &[]);
        let err = msg(20)
            .handle(deps.as_mut(), &mock_env(), &info)
            .unwrap_err();
        assert!(format!("{err}").contains("only the configured admin"));
        assert_eq!(stored_qe_floor(&deps.as_mut()), 15);
    }

    #[test]
    fn admin_can_raise_floor_and_it_is_stored() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 15, 15);
        let info = message_info(&admin, &[]);
        let res = msg(21).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "action" && a.value == "set_qe_eval_floor"));
        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "min_qe_eval_num" && a.value == "21"));
        assert!(res
            .attributes
            .iter()
            .any(|a| a.key == "previous_min_qe_eval_num" && a.value == "15"));
        assert_eq!(stored_qe_floor(&deps.as_mut()), 21);
    }

    #[test]
    fn raise_only_rejects_lowering() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 15, 21);
        let info = message_info(&admin, &[]);
        let err = msg(20)
            .handle(deps.as_mut(), &mock_env(), &info)
            .unwrap_err();
        assert!(format!("{err}").contains("raise-only violation"));
        assert_eq!(stored_qe_floor(&deps.as_mut()), 21);
    }

    #[test]
    fn equal_floor_is_allowed_idempotent() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 15, 21);
        let info = message_info(&admin, &[]);
        msg(21).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert_eq!(stored_qe_floor(&deps.as_mut()), 21);
    }

    /// Legacy state (pre-split) carries no `min_qe_eval_num`, so the effective
    /// QE floor is the TCB floor. The raise must be checked against that
    /// inherited value, not against zero.
    #[test]
    fn raise_only_is_enforced_against_inherited_legacy_floor() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 15, 15);
        let mut json = serde_json::to_value(CONFIG.load(deps.as_ref().storage).unwrap()).unwrap();
        json.as_object_mut().unwrap().remove("min_qe_eval_num");
        let legacy: RawConfig = serde_json::from_value(json).unwrap();
        CONFIG.save(deps.as_mut().storage, &legacy).unwrap();
        assert_eq!(stored_qe_floor(&deps.as_mut()), 15);

        let info = message_info(&admin, &[]);
        let err = msg(14)
            .handle(deps.as_mut(), &mock_env(), &info)
            .unwrap_err();
        assert!(format!("{err}").contains("below current floor 15"));

        msg(16).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert_eq!(stored_qe_floor(&deps.as_mut()), 16);
    }

    /// The two collateral streams are governed independently: raising QE must
    /// not move the global TCB default or any per-FMSPC entry.
    #[test]
    fn raising_qe_floor_leaves_tcb_floors_untouched() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 15, 15);
        TCB_FLOORS.save(deps.as_mut().storage, &FMSPC, &18).unwrap();

        let info = message_info(&admin, &[]);
        msg(30).handle(deps.as_mut(), &mock_env(), &info).unwrap();

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.min_qe_eval_num(), 30);
        assert_eq!(config.min_tcb_eval_num(), 15);
        assert_eq!(
            TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(),
            Some(18)
        );
    }
}
