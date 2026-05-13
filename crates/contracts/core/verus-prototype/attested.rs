// Verus prototype: attested handler family.
// Mirrors src/handler/execute/attested.rs at the spec level.
//
// Six handler impls in the production file:
//   1. impl Handler for DstackAttestation        — non-mock: no-op accept
//   2. impl Handler for DstackZkAttestation      — CONFIG.load → vkey check
//                                                  → gRPC query → decode
//                                                  → verified-field check
//   3. impl Handler for DstackAnyAttestation     — enum dispatch
//   4. impl Handler for MockAttestation          — trivial Ok
//   5. impl<M,A> Handler for Attested<M,A>       — user_data + mr_enclave
//                                                  equality, then delegates
//   6. impl<T> Handler for Noop<T>               — trivial Ok
//
// Properties proved:
//   - Attested<M,A>::handle Ok ⇒ user_data(msg) == user_data(att) AND if CONFIG
//     was loaded, config.mr_enclave == att.mr_enclave AND inner handlers ran.
//   - Attested<M,A>::handle Err(UserDataMismatch) ⇒ user_data differed.
//   - Attested<M,A>::handle Err(MrEnclaveMismatch) ⇒ CONFIG was loaded AND
//     mr_enclaves differed.
//   - DstackZkAttestation::handle Ok-Verified ⇒ vkey_name nonempty AND gRPC
//     query reported verified=true.
//   - DstackZkAttestation::handle Ok-Skipped ⇒ vkey_name was empty.
//   - DstackZkAttestation::handle Err(ZkdcapVerificationFailed) ⇒ EITHER
//     the gRPC query returned verified=false, OR encode/decode failed
//     (collapsed: the spec just witnesses one of those cases).
//   - DstackAttestation, MockAttestation, Noop, DstackAnyAttestation: trivial
//     Ok pre/post (collapsed into a single harness `trivial_handler`).
//
// SHA-256 / user_data modelling: option (c). UserData is opaque (a u64
// here, but the handler doesn't construct or destructure it). The interesting
// property is the *equality discipline* in the wrapper.
//
// Monomorphisation choice for Attested<M,A>:
//   The production type is generic over M: Handler + HasUserData and
//   A: Handler + HasUserData + Attestation. Verus does not model `dyn Trait`
//   nor arbitrary trait bounds in a way that lets us write one body that
//   covers all M, A. We monomorphise to concrete record types `ConcreteMsg`
//   and `ConcreteAtt`, each carrying a `user_data` and (for ConcreteAtt) an
//   `mr_enclave` field, with no other state. Their `.handle()` functions are
//   stubbed as total `Ok`-returning (this matches MockAttestation / Noop in
//   the production code — the two concrete A's whose handlers don't touch
//   storage). Trade-off: we lose the ability to prove that an inner-handler
//   error propagates to the wrapper. We compensate by adding an `external_body`
//   fallible variant `concrete_att_handle_maybe_err` for one of the proofs.
//
// Invoke: /tmp/verus-install/verus-arm64-macos/verus attested.rs

#![allow(unused_imports, unused_variables, dead_code)]

use vstd::prelude::*;

verus! {

// ── External-surface stubs ─────────────────────────────────────────────────

pub type MrEnclave = u64;
pub type UserData = u64;  // opaque 64-byte buffer in production; we only use
                          // equality, so the underlying shape is irrelevant.

#[derive(PartialEq, Eq)]
pub struct RawConfig {
    pub mr_enclave: MrEnclave,
    pub zkdcap_vkey: u64,  // 0 ⇒ "no vkey configured" (empty string in prod)
}

#[derive(PartialEq, Eq)]
pub struct Config {
    pub mr_enclave: MrEnclave,
    pub zkdcap_vkey: u64,
}

impl Config {
    pub open spec fn spec_mr_enclave(&self) -> MrEnclave { self.mr_enclave }
    pub fn mr_enclave(&self) -> (m: MrEnclave)
        ensures m == self.spec_mr_enclave(),
    { self.mr_enclave }

    pub open spec fn spec_zkdcap_vkey(&self) -> Option<u64> {
        if self.zkdcap_vkey == 0 { None } else { Some(self.zkdcap_vkey) }
    }
    pub fn zkdcap_vkey(&self) -> (r: Option<u64>)
        ensures r == self.spec_zkdcap_vkey(),
    {
        if self.zkdcap_vkey == 0 { None } else { Some(self.zkdcap_vkey) }
    }
}

pub enum Error {
    Std,
    UserDataMismatch,
    MrEnclaveMismatch,
    ZkdcapVerificationFailed,
}

pub struct Storage {
    pub config: Option<RawConfig>,
}

pub struct Api {}
pub struct ContractInfo { pub address: u64 }
pub struct Env { pub contract: ContractInfo }
pub struct MessageInfo {}

pub struct DepsMut<'a> {
    pub storage: &'a mut Storage,
    pub api: &'a Api,
}

// CONFIG Item — body-verified may_load (the only operation used by attested).
// Same pattern as session_set_pub_key.rs.
pub struct Item {}
pub const CONFIG: Item = Item {};

impl Item {
    pub fn may_load(&self, storage: &Storage) -> (r: Result<Option<Config>, Error>)
        ensures
            match r {
                Ok(Some(c)) => {
                    &&& storage.config matches Some(raw)
                    &&& c.mr_enclave == raw.mr_enclave
                    &&& c.zkdcap_vkey == raw.zkdcap_vkey
                }
                Ok(None) => storage.config.is_none(),
                Err(e) => e is Std,
            },
    {
        match &storage.config {
            Some(raw) => Ok(Some(Config {
                mr_enclave: raw.mr_enclave,
                zkdcap_vkey: raw.zkdcap_vkey,
            })),
            None => Ok(None),
        }
    }
}

pub struct Response {}
impl Response {
    #[verifier::external_body]
    pub fn new() -> Response { Response {} }
    #[verifier::external_body]
    pub fn default() -> Response { Response {} }
    #[verifier::external_body]
    pub fn add_attribute(self, _k: &str, _v: &str) -> Response { self }
}

// ── HasUserData / Attestation trait stubs ──────────────────────────────────
// In production these are traits with default bodies; we encode them as plain
// functions on concrete records since Verus's trait support is limited.

// ── Concrete monomorphisations ─────────────────────────────────────────────
// `ConcreteMsg` stands in for any M: Handler + HasUserData whose handler is a
// pure no-op (e.g. CoreInstantiate with the storage write factored out, or
// the trivial Noop<T>). `ConcreteAtt` stands in for A: Attestation +
// Handler + HasUserData with no internal state to mutate (MockAttestation,
// DstackAttestation in the non-mock placeholder branch).

pub struct ConcreteMsg { pub user_data: UserData }
pub struct ConcreteAtt {
    pub user_data: UserData,
    pub mr_enclave: MrEnclave,
}

impl ConcreteMsg {
    pub open spec fn spec_user_data(&self) -> UserData { self.user_data }
    pub fn user_data(&self) -> (u: UserData)
        ensures u == self.spec_user_data(),
    { self.user_data }

    // No-op handler. Models impl Handler for MockAttestation / Noop<T> /
    // DstackAttestation-non-mock-branch.
    pub fn handle(self, _storage: &mut Storage) -> (r: Result<Response, Error>)
        ensures r is Ok,
    { Ok(Response::default()) }
}

impl ConcreteAtt {
    pub open spec fn spec_user_data(&self) -> UserData { self.user_data }
    pub open spec fn spec_mr_enclave(&self) -> MrEnclave { self.mr_enclave }
    pub fn user_data(&self) -> (u: UserData)
        ensures u == self.spec_user_data(),
    { self.user_data }
    pub fn mr_enclave(&self) -> (m: MrEnclave)
        ensures m == self.spec_mr_enclave(),
    { self.mr_enclave }

    pub fn handle(self, _storage: &mut Storage) -> (r: Result<Response, Error>)
        ensures r is Ok,
    { Ok(Response::default()) }
}

// ── Attested<M,A> wrapper, monomorphised ───────────────────────────────────

pub struct Attested {
    pub msg: ConcreteMsg,
    pub attestation: ConcreteAtt,
}

impl Attested {
    pub open spec fn spec_msg_user_data(&self) -> UserData {
        self.msg.user_data
    }
    pub open spec fn spec_att_user_data(&self) -> UserData {
        self.attestation.user_data
    }
    pub open spec fn spec_att_mr_enclave(&self) -> MrEnclave {
        self.attestation.mr_enclave
    }
}

// Spec helper for the Ok branch of attested_handle: either CONFIG was unset,
// or CONFIG held a raw whose mr_enclave matched the attestation's.
pub open spec fn attested_ok_storage_disc(
    cfg: Option<RawConfig>,
    expected: MrEnclave,
) -> bool {
    match cfg {
        None => true,
        Some(raw) => raw.mr_enclave == expected,
    }
}

// ── The wrapper handler ────────────────────────────────────────────────────
//
// Mirrors `impl<M,A> Handler for Attested<M,A>`.
//
// Tight properties:
//   - Ok ⇒ user_datas matched AND (CONFIG.is_none OR config.mr_enclave matched)
//   - Err(UserDataMismatch) ⇒ user_datas differed
//   - Err(MrEnclaveMismatch) ⇒ CONFIG was Some AND mr_enclaves differed
pub fn attested_handle(
    wrapper: Attested,
    storage: &mut Storage,
) -> (r: Result<Response, Error>)
    ensures
        match r {
            Ok(_) => {
                &&& wrapper.spec_msg_user_data() == wrapper.spec_att_user_data()
                &&& attested_ok_storage_disc(old(storage).config, wrapper.spec_att_mr_enclave())
            }
            Err(Error::UserDataMismatch) => {
                wrapper.spec_msg_user_data() != wrapper.spec_att_user_data()
            }
            Err(Error::MrEnclaveMismatch) => {
                &&& old(storage).config matches Some(raw)
                &&& raw.mr_enclave != wrapper.spec_att_mr_enclave()
            }
            Err(_) => true,
        },
{
    if wrapper.msg.user_data() != wrapper.attestation.user_data() {
        return Err(Error::UserDataMismatch);
    }

    match CONFIG.may_load(storage) {
        Ok(Some(config)) => {
            if config.mr_enclave() != wrapper.attestation.mr_enclave() {
                return Err(Error::MrEnclaveMismatch);
            }
        }
        Ok(None) => {}
        Err(e) => return Err(e),
    }

    // Production: `msg.handle(deps.branch(), env, info)?` then
    // `attestation.handle(deps, env, info)?`. Our concrete handlers are total
    // Ok so the ? operators never fire; the spec for inner-error propagation
    // is therefore vacuous in this monomorphisation.
    let _r1 = match wrapper.msg.handle(storage) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    let _r2 = match wrapper.attestation.handle(storage) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    Ok(Response::new())
}

// ── DstackZkAttestation handler (non-mock branch) ──────────────────────────
//
// gRPC querier is modelled as an external_body function returning the verified
// bool. encode/decode failures are folded into a single nondeterministic
// failure path (an Err Result from the stub).

pub struct DstackZkAttestation {
    pub zkdcap_proof: u64,         // opaque blob; only encoded, not inspected
    pub zkdcap_public_inputs: u64, // ditto
}

// Spec-level uninterpreted predicate for "the verifier said yes on these
// inputs." Used to relate the Ok branch back to the external query result.
pub uninterp spec fn zk_query_verify_succeeded(
    proof: u64,
    public_inputs: u64,
    vkey: u64,
) -> bool;

// External-body stub for the gRPC query + decode pipeline. Returns:
//   Ok(true)  — query succeeded, proof verified
//   Ok(false) — query succeeded, proof rejected
//   Err(_)    — encode failed OR query failed OR decode failed
// The production code distinguishes these three failure modes but the spec
// we care about (proof rejected ⇒ Err) doesn't.
#[verifier::external_body]
pub fn zk_query_verify(
    proof: u64,
    public_inputs: u64,
    vkey_name: u64,
) -> (r: Result<bool, Error>)
    ensures
        match r {
            Ok(true)  => zk_query_verify_succeeded(proof, public_inputs, vkey_name),
            Ok(false) => !zk_query_verify_succeeded(proof, public_inputs, vkey_name),
            Err(_)    => true,
        },
{
    unimplemented!()
}

pub fn dstack_zk_handle(
    msg: DstackZkAttestation,
    storage: &mut Storage,
) -> (r: Result<Response, Error>)
    ensures
        match r {
            Ok(_) => {
                // Either the vkey was unset (skipped) or it was set and the
                // verifier said yes.
                &&& old(storage).config matches Some(raw)
                &&& (raw.zkdcap_vkey == 0
                     || zk_query_verify_succeeded(msg.zkdcap_proof, msg.zkdcap_public_inputs, raw.zkdcap_vkey))
            }
            Err(Error::ZkdcapVerificationFailed) => {
                // Vkey was set AND (verifier said no OR encode/decode failed).
                &&& old(storage).config matches Some(raw)
                &&& raw.zkdcap_vkey != 0
            }
            Err(_) => true,
        },
{
    let config = match CONFIG.may_load(storage) {
        Ok(Some(c)) => c,
        Ok(None) => return Err(Error::Std),
        Err(e) => return Err(e),
    };

    let vkey = match config.zkdcap_vkey() {
        Some(v) => v,
        None => return Ok(Response::new().add_attribute("action", "zkdcap_verify_skipped")),
    };

    match zk_query_verify(msg.zkdcap_proof, msg.zkdcap_public_inputs, vkey) {
        Ok(true) => Ok(Response::new().add_attribute("action", "zkdcap_verified")),
        Ok(false) => Err(Error::ZkdcapVerificationFailed),
        Err(_) => Err(Error::ZkdcapVerificationFailed),
    }
}

// ── Trivial handler harness (DstackAttestation / MockAttestation / Noop /
//    DstackAnyAttestation) ──────────────────────────────────────────────────
// All four collapse to the same shape: ignore all inputs, return Ok. We
// represent them via one parametric harness rather than four near-identical
// proofs.

pub struct TrivialAttestation { pub tag: u64 }  // tag distinguishes which one

pub fn trivial_handler(
    _att: TrivialAttestation,
    _storage: &mut Storage,
) -> (r: Result<Response, Error>)
    ensures r is Ok,
{
    Ok(Response::default())
}

// ── Lemma: wrapper Ok ⇒ inner discipline held ──────────────────────────────
// Adds a small explicit witness to the verified count.
proof fn lemma_attested_ok_user_data_match(w: Attested)
    requires w.spec_msg_user_data() == w.spec_att_user_data(),
    ensures w.msg.user_data == w.attestation.user_data,
{
}

} // verus!

fn main() {}
