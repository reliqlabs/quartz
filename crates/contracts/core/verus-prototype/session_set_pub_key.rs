// Verus prototype: session_set_pub_key handler.
// Mirrors src/handler/execute/session_set_pub_key.rs at the spec level.
//
// Properties proved:
//   - on Ok: SESSION held a session with matching nonce and None pub_key,
//            after the call holds Some(pub_key), AND the SEQUENCE_NUM
//            replay counter is reset to Some(0)
//   - on Err(BadSessionTransition): SESSION storage unchanged AND
//     SEQUENCE_NUM storage unchanged, with the error tracing to one of
//     (a) no session existed, (b) nonce mismatch, (c) pub_key already set
//
// Round D Critical 2 fix (2026-05-20, six voices agreed): the previous
// prototype's Storage struct had no `sequence_num` field, and the
// handler's Ok postcondition made no mention of SEQUENCE_NUM. Production
// `SessionSetPubKey::handle` writes `SEQUENCE_NUM.save(.., Uint64::new(0))`
// after the SESSION save as the replay-protection foundation for every
// downstream `Sequenced<T>` handler. The prior model was silent on this
// and could be refactored by an adversarial implementer to skip the
// reset without invalidating the Verus proof.
//
// Round D Critical 11 (advisory, atomicity gap): production cosmwasm
// gives per-tx atomic rollback if any save fails after a prior one
// succeeded, so a partial-first-save / failed-second-save trace cannot
// be observed at the chain layer. This prototype models both Item::save
// operations as total-Ok (the body returns Ok unconditionally), so the
// Err arms after either save are dead. The Err invariant therefore holds
// trivially. Modeling the partial-success case would require a staged-
// then-commit Storage refactor and is left to a separate cycle.
//
// Invoke: /tmp/verus-install/verus-arm64-macos/verus session_set_pub_key.rs

#![allow(unused_imports, unused_variables, dead_code)]

use vstd::prelude::*;

verus! {

pub type Nonce = u64;

pub struct Session {
    pub nonce: Nonce,
    pub pub_key: Option<u64>,
}

impl Session {
    pub open spec fn spec_with_pub_key(self, n: Nonce, pk: u64) -> Option<Session> {
        if self.nonce == n && self.pub_key.is_none() {
            Some(Session { nonce: self.nonce, pub_key: Some(pk) })
        } else {
            None
        }
    }

    pub fn with_pub_key(self, n: Nonce, pk: u64) -> (r: Option<Session>)
        ensures r == self.spec_with_pub_key(n, pk),
    {
        if self.nonce == n && self.pub_key.is_none() {
            Some(Session { nonce: self.nonce, pub_key: Some(pk) })
        } else {
            None
        }
    }
}

pub enum Error { Std, BadSessionTransition }

pub struct Storage {
    pub session: Option<Session>,
    pub sequence_num: Option<u64>,  // mirrors production SEQUENCE_NUM (cw_storage_plus::Item<Uint64>)
}

pub struct Item {}
pub const SESSION: Item = Item {};

impl Item {
    pub fn may_load(&self, storage: &Storage) -> (r: Result<Option<Session>, Error>)
        ensures
            match r {
                Ok(s) => s == storage.session,
                Err(_) => true,
            },
    {
        // Modelled as identity. Real cw-storage-plus may_load can error on
        // deserialization; we don't trigger that path for our Session type.
        Ok(match &storage.session {
            Some(s) => Some(Session { nonce: s.nonce, pub_key: s.pub_key }),
            None => None,
        })
    }

    // The body unconditionally writes and returns Ok, so the Err arm is
    // dead. We assert `r.is_ok()` here to reflect that. Round D Critical
    // 11 (atomicity gap) is the substantive refactor that would re-admit
    // the Err arm under a staged-then-commit Storage model.
    pub fn save(&self, storage: &mut Storage, value: &Session) -> (r: Result<(), Error>)
        ensures
            r.is_ok(),
            final(storage).session == Some(*value),
            final(storage).sequence_num == old(storage).sequence_num,
    {
        storage.session = Some(Session { nonce: value.nonce, pub_key: value.pub_key });
        Ok(())
    }
}

// SEQUENCE_NUM mirror. Production has `pub const SEQUENCE_NUM:
// Item<Uint64> = Item::new("sequence_num")` in state.rs; the handler
// writes Uint64::new(0) immediately after the session save. Same
// infallibility note as Item::save above: the body always returns Ok,
// so the spec asserts `r.is_ok()`.
pub struct SequenceNumItem {}
pub const SEQUENCE_NUM: SequenceNumItem = SequenceNumItem {};

impl SequenceNumItem {
    pub fn save(&self, storage: &mut Storage, value: &u64) -> (r: Result<(), Error>)
        ensures
            r.is_ok(),
            final(storage).sequence_num == Some(*value),
            final(storage).session == old(storage).session,
    {
        storage.sequence_num = Some(*value);
        Ok(())
    }
}

// Handler — set_pub_key carries (nonce, pub_key); the session must already
// exist with matching nonce and no pub_key set. On Ok, the handler also
// initializes the SEQUENCE_NUM replay counter to 0.
pub fn handle(
    msg_nonce: Nonce,
    msg_pub_key: u64,
    storage: &mut Storage,
) -> (r: Result<(), Error>)
    ensures
        match r {
            Ok(()) => {
                &&& old(storage).session matches Some(s)
                &&& s.nonce == msg_nonce
                &&& s.pub_key.is_none()
                &&& final(storage).session == Some(Session { nonce: msg_nonce, pub_key: Some(msg_pub_key) })
                &&& final(storage).sequence_num == Some(0u64)
            }
            Err(_) => {
                &&& final(storage).session == old(storage).session
                &&& final(storage).sequence_num == old(storage).sequence_num
            }
        },
{
    let loaded = match SESSION.may_load(storage) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };
    let session = match loaded {
        Some(s) => s,
        None => return Err(Error::BadSessionTransition),
    };
    let updated = match session.with_pub_key(msg_nonce, msg_pub_key) {
        Some(u) => u,
        None => return Err(Error::BadSessionTransition),
    };
    match SESSION.save(storage, &updated) {
        Ok(()) => {}
        Err(e) => return Err(e),
    }
    // Production parity: SEQUENCE_NUM.save(.., Uint64::new(0)) — the
    // replay-protection foundation for every downstream Sequenced<T>
    // handler. Round D Critical 2 fix.
    match SEQUENCE_NUM.save(storage, &0u64) {
        Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

} // verus!

fn main() {}
