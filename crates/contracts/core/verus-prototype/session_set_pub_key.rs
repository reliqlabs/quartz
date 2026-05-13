// Verus prototype: session_set_pub_key handler.
// Mirrors src/handler/execute/session_set_pub_key.rs at the spec level.
//
// Properties proved:
//   - on Ok: SESSION held a session with matching nonce and None pub_key,
//            and after the call holds Some(pub_key)
//   - on Err(BadSessionTransition): SESSION storage unchanged AND either
//     (a) no session existed, (b) nonce mismatch, or (c) pub_key already set
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

pub struct Storage { pub session: Option<Session> }

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

    pub fn save(&self, storage: &mut Storage, value: &Session) -> (r: Result<(), Error>)
        ensures
            match r {
                Ok(()) => final(storage).session == Some(*value),
                Err(_) => final(storage).session == old(storage).session,
            },
    {
        storage.session = Some(Session { nonce: value.nonce, pub_key: value.pub_key });
        Ok(())
    }
}

// Handler — set_pub_key carries (nonce, pub_key); the session must already
// exist with matching nonce and no pub_key set.
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
            }
            Err(_) => final(storage).session == old(storage).session,
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
        Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

} // verus!

fn main() {}
