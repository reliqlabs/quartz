use cosmwasm_std::{DepsMut, Env, HexBinary, MessageInfo, Response, Uint64};

use crate::{
    error::Error,
    handler::Handler,
    msg::execute::session_set_pub_key::SessionSetPubKey,
    state::{SEQUENCE_NUM, SESSION},
};

impl Handler for SessionSetPubKey {
    // Add msg.pub_key to SESSION and initialize SEQUENCE_NUM.
    fn handle(self, deps: DepsMut<'_>, _env: &Env, _info: &MessageInfo) -> Result<Response, Error> {
        let session = SESSION.load(deps.storage).map_err(Error::Std)?;

        // Fail closed: SEQUENCE_NUM is initialised exactly once, when a
        // session's pub_key is first set. Its presence means a key was already
        // installed, so refuse rather than re-install a key and reset the
        // replay counter to 0. `Session::with_pub_key` already rejects the
        // double-set on a live session; this is the belt-and-suspenders half
        // that, together with the `session_create` rollback guard, closes the
        // create->set replay-reset path even if a future refactor loosens one
        // of the other checks.
        if SEQUENCE_NUM
            .may_load(deps.storage)
            .map_err(Error::Std)?
            .is_some()
        {
            return Err(Error::BadSessionTransition);
        }
        let (nonce, pub_key) = self.into_tuple();

        // ASSERT SESSION.nonce == msg.nonce, SESSION.pubkey == None
        // STORE SESSION: (SESSION.nonce, msg.pubkey)
        let session = session
            .with_pub_key(nonce, pub_key.clone())
            .ok_or(Error::BadSessionTransition)?;
        SESSION.save(deps.storage, &session).map_err(Error::Std)?;

        // STORE SEQUENCE_NUM: 0
        let sequence_num = Uint64::new(0);
        SEQUENCE_NUM
            .save(deps.storage, &sequence_num)
            .map_err(Error::Std)?;

        Ok(Response::new()
            .add_attribute("action", "session_set_pub_key")
            .add_attribute("pub_key", HexBinary::from(pub_key).to_hex()))
    }
}
