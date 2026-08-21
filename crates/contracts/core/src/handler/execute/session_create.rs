use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::session_create::SessionCreate,
    state::{Session, SESSION},
};

impl Handler for SessionCreate {
    // Create new SESSION with msg.nonce and no pubkey.
    fn handle(self, deps: DepsMut<'_>, env: &Env, _info: &MessageInfo) -> Result<Response, Error> {
        // Fail closed against session rollback. A SESSION may be created at
        // most once: overwriting a live session would reset it to
        // `pub_key: None`, letting an attacker re-run SessionSetPubKey to
        // install a fresh key AND wipe SEQUENCE_NUM back to 0 (a
        // replay-protection rollback). A deliberate re-handshake is
        // intentionally NOT opened here; it would require its own explicitly
        // guarded message rather than being reachable implicitly.
        if SESSION
            .may_load(deps.storage)
            .map_err(Error::Std)?
            .is_some()
        {
            return Err(Error::BadSessionTransition);
        }

        // ASSERT msg.contract == env.contract.address
        let addr = deps.api.addr_validate(self.contract())?;
        if addr != env.contract.address {
            return Err(Error::ContractAddrMismatch);
        }

        // STORE in SESSION: (msg.nonce, None)
        SESSION
            .save(deps.storage, &Session::create(self.nonce()))
            .map_err(Error::Std)?;

        Ok(Response::new().add_attribute("action", "session_create"))
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

    use super::*;

    fn make_msg(nonce: [u8; 32], contract: &str) -> SessionCreate {
        SessionCreate::new(nonce, contract.to_string())
    }

    /// The first SessionCreate against an empty store succeeds and stores the
    /// session; a second SessionCreate is rejected with BadSessionTransition
    /// (session rollback is fail-closed).
    #[test]
    fn second_session_create_is_rejected() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        let contract = deps.api.addr_make("contract");
        env.contract.address = contract.clone();
        let info = message_info(&deps.api.addr_make("creator"), &[]);

        // First create: legitimate handshake start.
        make_msg([7u8; 32], contract.as_str())
            .handle(deps.as_mut(), &env, &info)
            .expect("first session_create must succeed");
        assert!(
            SESSION.may_load(&deps.storage).unwrap().is_some(),
            "session must be stored after first create"
        );

        // Second create (rollback attempt), even with a different nonce, is
        // rejected before any state is touched.
        let err = make_msg([9u8; 32], contract.as_str())
            .handle(deps.as_mut(), &env, &info)
            .expect_err("duplicate session_create must be rejected");
        assert!(
            matches!(err, Error::BadSessionTransition),
            "duplicate create must fail with BadSessionTransition, got {err:?}"
        );

        // The original session (nonce 7) is untouched by the rejected create.
        let session = SESSION.load(&deps.storage).unwrap();
        assert_eq!(
            session.nonce(),
            [7u8; 32],
            "session must not be overwritten"
        );
    }

    /// A contract-address mismatch on the first create still fails closed and
    /// leaves the store empty (the rollback guard does not mask this check).
    #[test]
    fn first_create_wrong_contract_is_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("creator"), &[]);

        let wrong = deps.api.addr_make("not-this-contract");
        let err = make_msg([7u8; 32], wrong.as_str())
            .handle(deps.as_mut(), &env, &info)
            .expect_err("wrong contract address must be rejected");
        assert!(matches!(err, Error::ContractAddrMismatch), "got {err:?}");
        assert!(
            SESSION.may_load(&deps.storage).unwrap().is_none(),
            "no session must be stored on rejected create"
        );
    }
}
