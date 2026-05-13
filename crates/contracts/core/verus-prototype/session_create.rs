// Verus prototype: feasibility study for proving the `session_create` handler
// in `quartz-contract-core`. This file is intentionally standalone — Verus
// cannot consume the full quartz-contract-core crate (cosmwasm-std,
// cw-storage-plus, k256, thiserror, sha2 et al. are not Verus-aware), so the
// dependencies are modelled here as `#[verifier::external_body]` stubs with
// `requires`/`ensures` contracts that capture the semantics we rely on.
//
// Invoke: /tmp/verus-install/verus-arm64-macos/verus session_create.rs
//
// Phase: feasibility evaluation (not production). The point of this file is to
// answer: "can Verus reason about Quartz's handler logic at all, given the
// cosmwasm-std/cw-storage-plus generic surface?"

#![allow(unused_imports, unused_variables, dead_code)]

use vstd::prelude::*;

verus! {

// ── Stubs for the external surface ─────────────────────────────────────────
//
// We model the minimum the handler touches:
//   - A 32-byte nonce (Nonce)
//   - A Session value (nonce, optional pub_key)
//   - A `SessionCreate` message (nonce + claimed contract address)
//   - A storage model: `Storage` carrying the current `Option<Session>`
//   - An `Api::addr_validate` stub
//   - An `Env` with `contract.address`
//   - `Item<Session>` with `save` (external_body, with a written-out spec)

pub type Nonce = u64;  // Modelled as u64 for verifier tractability;
                      // the production type is [u8; 32]. We're proving the
                      // control-flow, not the byte layout.

pub struct Session {
    pub nonce: Nonce,
    pub pub_key: Option<u64>,  // u64 here stands in for Vec<u8>
}

impl Session {
    pub open spec fn spec_create(nonce: Nonce) -> Session {
        Session { nonce, pub_key: None }
    }

    pub fn create(nonce: Nonce) -> (s: Session)
        ensures s == Self::spec_create(nonce),
    {
        Session { nonce, pub_key: None }
    }
}

pub struct SessionCreate {
    pub nonce: Nonce,
    pub contract: u64,  // Address modelled as u64 (interned string id)
}

impl SessionCreate {
    pub open spec fn spec_nonce(&self) -> Nonce { self.nonce }
    pub open spec fn spec_contract(&self) -> u64 { self.contract }

    pub fn nonce(&self) -> (n: Nonce)
        ensures n == self.spec_nonce(),
    { self.nonce }

    pub fn contract(&self) -> (c: u64)
        ensures c == self.spec_contract(),
    { self.contract }
}

// ── Error type (simplified) ────────────────────────────────────────────────

pub enum Error {
    Std,
    ContractAddrMismatch,
}

// ── Env / Api / Storage stubs ──────────────────────────────────────────────

pub struct ContractInfo { pub address: u64 }
pub struct Env { pub contract: ContractInfo }

pub struct Api {}

impl Api {
    // addr_validate: returns the address if valid. We model "valid" as
    // identity for now — the contract's threat model is that addr_validate
    // is a trusted black box implemented by the chain.
    #[verifier::external_body]
    pub fn addr_validate(&self, s: u64) -> (r: Result<u64, Error>)
        ensures
            // Validation is deterministic; the result is fixed by the
            // spec-level oracle. We also know Ok preserves identity (the
            // chain's addr_validate either rejects or returns the canonical
            // form, which for our purposes equals the input).
            match (r, addr_oracle(s)) {
                (Ok(a), Ok(b)) => a == s && a == b,
                (Err(_), Err(_)) => true,
                _ => false,
            },
    {
        Ok(s)
    }
}

// Storage abstracts cosmwasm_std::Storage and cw_storage_plus::Item<Session>
// together. The Item<Session> API in cw-storage-plus is:
//     fn save(&self, storage: &mut dyn Storage, value: &T) -> StdResult<()>
//     fn may_load(&self, storage: &dyn Storage) -> StdResult<Option<T>>
// We collapse this to a single mutable Option<Session> field for verification.
pub struct Storage {
    pub session: Option<Session>,
}

// Spec-level oracle for what `Api::addr_validate` *would* return on a given
// input. In production this is the chain's bech32 validator; we treat it as
// an uninterpreted total function with a deterministic result.
pub uninterp spec fn addr_oracle(s: u64) -> Result<u64, ()>;

pub struct DepsMut<'a> {
    pub storage: &'a mut Storage,
    pub api: &'a Api,
}

// ── Item stub with documented spec contract ────────────────────────────────
//
// In cw-storage-plus, `Item<T>` is a typed key into the KV store. The two
// operations the handler uses are `save` and (transitively, on read paths)
// `may_load`. We model the SESSION item as a singleton: there is exactly one
// Item<Session> for the entire contract, namespaced by SESSION_KEY.
//
// SPEC CONTRACT for SESSION.save (external_body):
//   PRE: deps.storage.session can be any Option<Session>
//   POST on Ok: deps.storage.session == Some(*value)
//   POST on Err: deps.storage unchanged (cosmwasm/cw-storage-plus only errs
//                on serialization, which is total for our types, so in
//                practice the Err arm is unreachable for `Session`)
//
// This is the kind of "trust gap" we'd carry in production: the spec is
// only as good as our claim about cw-storage-plus's behaviour. We could
// shrink it further with a dynamic-tracking ghost variable, but it would
// not change the trust story.

pub struct Item { /* zero-sized; the storage location is implicit */ }

pub const SESSION: Item = Item {};

impl Item {
    // Variant A (used): body-verified save. With our model of Storage as a
    // single Option<Session>, Verus can prove the post-condition from the
    // body. This is *not* representative of the real cw-storage-plus
    // Item<T>::save which is generic over Serialize/Borsh and goes through
    // a dyn Storage trait — see Variant B below for the production stub.
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

    // Variant B (commented out — for documentation): what the *real*
    // production stub would look like. cw-storage-plus's Item<T>::save is
    //   pub fn save(&self, store: &mut dyn Storage, data: &T) -> StdResult<()>
    //       where T: Serialize + DeserializeOwned
    // Verus does not currently support `dyn Trait` arguments or trait
    // generics over `Serialize`/`DeserializeOwned`. The only viable path
    // is to mark this `external_body` and trust the spec contract:
    //
    // #[verifier::external_body]
    // pub fn save<T>(&self, storage: &mut dyn Storage, value: &T)
    //     -> Result<(), StdError>
    //     ensures
    //         match return_value {
    //             Ok(()) => /* item slot now holds serde-encoded value */,
    //             Err(_) => /* storage unchanged */,
    //         },
    // {
    //     unreachable!()
    // }
}

// Response is opaque — the handler returns it but no caller logic depends
// on its shape for the invariants we care about.
pub struct Response {}

impl Response {
    #[verifier::external_body]
    pub fn new() -> Response { Response {} }
    #[verifier::external_body]
    pub fn add_attribute(self, _k: &str, _v: &str) -> Response { self }
}

// ── The handler under verification ─────────────────────────────────────────
//
// This mirrors the body of
//   impl Handler for SessionCreate {
//       fn handle(self, deps: DepsMut, env: &Env, _info: &MessageInfo)
//           -> Result<Response, Error>
//   }
// from crates/contracts/core/src/handler/execute/session_create.rs.
//
// Properties proved:
//   1. On Ok, SESSION storage holds Session { nonce: msg.nonce, pub_key: None }.
//   2. On Err, SESSION storage is unchanged from its pre-state.

// `deps` is split into its two fields here so Verus can track the pre-state
// of `storage` directly (Verus's `old()` requires a `&mut` parameter).
// This is a cosmetic deviation from the production handler — the property
// proved is identical.
pub fn handle(
    msg: SessionCreate,
    storage: &mut Storage,
    api: &Api,
    env: &Env,
) -> (r: Result<Response, Error>)
    ensures
        match r {
            Ok(_) => {
                // The Ok branch only fires when both validation succeeded
                // and the validated address equals the contract address.
                // This pins the input space of the success branch and
                // catches inverted-comparison bugs.
                &&& final(storage).session == Some(Session::spec_create(msg.spec_nonce()))
                &&& addr_oracle(msg.spec_contract()) == Result::<u64, ()>::Ok(env.contract.address)
            }
            Err(_) => final(storage).session == old(storage).session,
        },
{
    let addr = match api.addr_validate(msg.contract()) {
        Ok(a) => a,
        Err(e) => return Err(e),
    };
    if addr != env.contract.address {
        return Err(Error::ContractAddrMismatch);
    }
    match SESSION.save(storage, &Session::create(msg.nonce())) {
        Ok(()) => Ok(Response::new().add_attribute("action", "session_create")),
        Err(e) => Err(e),
    }
}

} // verus!

fn main() {}
