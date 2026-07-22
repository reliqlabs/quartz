use cosmwasm_std::{DepsMut, Env, HexBinary, MessageInfo, Response, StdError};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::SetTcbEvalFloor,
    state::{CONFIG, TCB_FLOORS},
};

impl Handler for SetTcbEvalFloor {
    // O3: governed, raise-only per-FMSPC TCB-Info floor update.
    //
    // Authority reuses the repo's `config.admin` pattern (see
    // examples/sealed-auction, examples/ranked-choice): only the configured
    // admin may raise a floor. FAILS CLOSED when no admin is configured
    // (legacy / unset state), so a floor cannot be moved by an unprivileged
    // caller. Enforced monotonic: the new floor must be >= the current
    // *effective* floor (the per-FMSPC entry if present, else the global
    // default `Config::min_tcb_eval_num`), so a floor can only ever go up.
    fn handle(self, deps: DepsMut<'_>, _env: &Env, info: &MessageInfo) -> Result<Response, Error> {
        // Read directly from the stored RawConfig — mirrors the zkdcap handler
        // and avoids a Config round-trip.
        let config = CONFIG.load(deps.storage).map_err(Error::Std)?;

        let Some(admin) = config.admin() else {
            return Err(Error::Std(StdError::msg(
                "unauthorized: no admin configured; TCB floor updates are governed",
            )));
        };
        if info.sender.as_str() != admin {
            return Err(Error::Std(StdError::msg(
                "unauthorized: only the configured admin may update TCB floors",
            )));
        }

        // Current effective floor: per-FMSPC entry takes precedence over the
        // global default. Raise-only is enforced against this baseline so a
        // per-FMSPC entry can never be set below the global default either.
        let baseline = TCB_FLOORS
            .may_load(deps.storage, &self.fmspc)
            .map_err(Error::Std)?
            .unwrap_or_else(|| config.min_tcb_eval_num());
        if self.min_tcb_eval_num < baseline {
            return Err(Error::Std(StdError::msg(format!(
                "raise-only violation: new TCB floor {} is below current floor {}",
                self.min_tcb_eval_num, baseline
            ))));
        }

        TCB_FLOORS
            .save(deps.storage, &self.fmspc, &self.min_tcb_eval_num)
            .map_err(Error::Std)?;

        Ok(Response::new()
            .add_attribute("action", "set_tcb_eval_floor")
            .add_attribute("fmspc", HexBinary::from(self.fmspc.as_slice()).to_hex())
            .add_attribute("min_tcb_eval_num", self.min_tcb_eval_num.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::Addr;

    use crate::state::{Config, LightClientOpts, RawConfig};

    const FMSPC: [u8; 6] = [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00];

    fn light_client_opts() -> LightClientOpts {
        LightClientOpts::new("testing".to_string(), 1, [0u8; 32], (2, 3), 1_209_600, 300, 600)
            .unwrap()
    }

    fn save_config(deps: DepsMut<'_>, admin: Option<Addr>, global_default: u64) {
        let mut config = Config::new([0u8; 32], light_client_opts(), None)
            .with_min_tcb_eval_num(global_default);
        if let Some(admin) = admin {
            config = config.with_admin(admin);
        }
        let raw: RawConfig = config.into();
        CONFIG.save(deps.storage, &raw).unwrap();
    }

    fn msg(min_tcb_eval_num: u64) -> SetTcbEvalFloor {
        SetTcbEvalFloor {
            fmspc: FMSPC,
            min_tcb_eval_num,
        }
    }

    #[test]
    fn fails_closed_when_no_admin_configured() {
        let mut deps = mock_dependencies();
        let sender = deps.api.addr_make("anyone");
        save_config(deps.as_mut(), None, 0);
        let info = message_info(&sender, &[]);
        let err = msg(10).handle(deps.as_mut(), &mock_env(), &info).unwrap_err();
        assert!(matches!(err, Error::Std(_)));
        assert!(format!("{err}").contains("no admin configured"));
        // nothing stored
        assert_eq!(TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(), None);
    }

    #[test]
    fn rejects_non_admin_sender() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        let attacker = deps.api.addr_make("attacker");
        save_config(deps.as_mut(), Some(admin), 0);
        let info = message_info(&attacker, &[]);
        let err = msg(10).handle(deps.as_mut(), &mock_env(), &info).unwrap_err();
        assert!(format!("{err}").contains("only the configured admin"));
        assert_eq!(TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(), None);
    }

    #[test]
    fn admin_can_raise_floor_and_it_is_stored() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 0);
        let info = message_info(&admin, &[]);
        msg(19).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert_eq!(
            TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(),
            Some(19)
        );
        // raise again to a higher value
        msg(23).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert_eq!(
            TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(),
            Some(23)
        );
    }

    #[test]
    fn raise_only_rejects_lowering_existing_entry() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 0);
        let info = message_info(&admin, &[]);
        msg(20).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        let err = msg(19).handle(deps.as_mut(), &mock_env(), &info).unwrap_err();
        assert!(format!("{err}").contains("raise-only violation"));
        // unchanged
        assert_eq!(
            TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(),
            Some(20)
        );
    }

    #[test]
    fn raise_only_rejects_below_global_default_when_no_entry() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        // global default floor is 15; a first per-FMSPC set below it lowers the
        // effective floor and must be rejected.
        save_config(deps.as_mut(), Some(admin.clone()), 15);
        let info = message_info(&admin, &[]);
        let err = msg(10).handle(deps.as_mut(), &mock_env(), &info).unwrap_err();
        assert!(format!("{err}").contains("raise-only violation"));
        // setting at the default is allowed (not a lowering)
        msg(15).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert_eq!(
            TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(),
            Some(15)
        );
    }

    #[test]
    fn equal_floor_is_allowed_idempotent() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        save_config(deps.as_mut(), Some(admin.clone()), 0);
        let info = message_info(&admin, &[]);
        msg(12).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        msg(12).handle(deps.as_mut(), &mock_env(), &info).unwrap();
        assert_eq!(
            TCB_FLOORS.may_load(deps.as_ref().storage, &FMSPC).unwrap(),
            Some(12)
        );
    }
}
