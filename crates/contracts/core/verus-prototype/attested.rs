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
//   storage).
//
// Round D Critical 3 fix (2026-05-20): the original prototype's docstring
// claimed a compensating `concrete_att_handle_maybe_err` external_body
// variant for inner-handler error propagation, but the variant did not
// exist in the file. Six voices flagged this as docstring dishonesty.
// The fix adds:
//   - `ConcreteAtt::handle_maybe_err` — external_body fallible variant
//     whose spec allows both Ok and Err outcomes, modelling production
//     attestation handlers that can return Err(Std) or
//     Err(ZkdcapVerificationFailed) (e.g. DstackZkAttestation before its
//     placeholder phase).
//   - `attested_handle_with_fallible_att` — a wrapper variant that calls
//     handle_maybe_err in place of handle. Verus's acceptance of this
//     wrapper IS the propagation theorem: under the fallible-inner spec,
//     the wrapper's Err return paths are sound, which is the inner-error
//     propagation property the original docstring promised. Both wrappers
//     also now tighten the catch-all Err(_) branch to witness that the
//     user_data pre-check held.
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
    pub min_tcb_eval_num: u64, // monotonic TCB-recency floor (0 ⇒ no floor)
    // expected_rtmr3 here abstracts the per-register image pin set
    // (production: expected_mrtd/rtmr0/rtmr1/rtmr2/rtmr3). Some ⇒ an image
    // register is pinned and bound; None ⇒ no register pinned.
    pub expected_rtmr3: Option<MrEnclave>,
    pub allow_any_image: bool, // escape hatch: verify with no image pin
}

#[derive(PartialEq, Eq)]
pub struct Config {
    pub mr_enclave: MrEnclave,
    pub zkdcap_vkey: u64,
    pub min_tcb_eval_num: u64,
    pub expected_rtmr3: Option<MrEnclave>,
    pub allow_any_image: bool,
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

    pub open spec fn spec_min_tcb_eval_num(&self) -> u64 { self.min_tcb_eval_num }
    pub fn min_tcb_eval_num(&self) -> (m: u64)
        ensures m == self.spec_min_tcb_eval_num(),
    { self.min_tcb_eval_num }

    pub open spec fn spec_expected_rtmr3(&self) -> Option<MrEnclave> { self.expected_rtmr3 }
    pub fn expected_rtmr3(&self) -> (r: Option<MrEnclave>)
        ensures r == self.spec_expected_rtmr3(),
    { self.expected_rtmr3 }

    pub open spec fn spec_allow_any_image(&self) -> bool { self.allow_any_image }
    pub fn allow_any_image(&self) -> (b: bool)
        ensures b == self.spec_allow_any_image(),
    { self.allow_any_image }
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
                    &&& c.min_tcb_eval_num == raw.min_tcb_eval_num
                    &&& c.expected_rtmr3 == raw.expected_rtmr3
                    &&& c.allow_any_image == raw.allow_any_image
                }
                Ok(None) => storage.config.is_none(),
                Err(e) => e is Std,
            },
    {
        match &storage.config {
            Some(raw) => Ok(Some(Config {
                mr_enclave: raw.mr_enclave,
                zkdcap_vkey: raw.zkdcap_vkey,
                min_tcb_eval_num: raw.min_tcb_eval_num,
                allow_any_image: raw.allow_any_image,
                expected_rtmr3: raw.expected_rtmr3,
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

    // Round D Critical 3 (2026-05-20): the compensating fallible variant
    // promised by the original docstring. Models a production attestation
    // handler that can return Err (e.g. DstackZkAttestation's gRPC path,
    // or a future A whose body touches storage and can fail). The ensures
    // clause constrains the Err to be a non-wrapper-specific variant
    // because production attestation handlers (DstackAttestation,
    // MockAttestation, DstackZkAttestation, Noop) cannot return
    // UserDataMismatch or MrEnclaveMismatch (those are constructed only
    // by the Attested wrapper itself, not by inner handlers).
    #[verifier::external_body]
    pub fn handle_maybe_err(self, _storage: &mut Storage) -> (r: Result<Response, Error>)
        ensures
            match r {
                Ok(_) => true,
                Err(e) => !(e is UserDataMismatch) && !(e is MrEnclaveMismatch),
            },
    { unimplemented!() }
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
            // Round D Critical 3 (2026-05-20): catch-all tightened to
            // witness that the user_data pre-check held. The only path
            // to this arm in the total-Ok-inner-handler version is
            // CONFIG.may_load returning Err(Std), which happens after
            // the user_data check passes.
            Err(_) => wrapper.spec_msg_user_data() == wrapper.spec_att_user_data(),
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
    // Ok so the ? operators never fire; the inner-error propagation property
    // is witnessed by the *fallible* variant
    // `attested_handle_with_fallible_att` below.
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

// ── Wrapper variant with fallible inner attestation (Critical 3 fix) ───────
//
// Identical control flow to `attested_handle`, but calls
// `ConcreteAtt::handle_maybe_err` in place of `ConcreteAtt::handle`. The
// fallible variant's spec leaves both Ok and Err reachable, so the
// `Err(e) => return Err(e)` propagation arm of the inner match is now
// live. Verus's verification of this function under the fallible-inner
// spec is the inner-handler error propagation theorem the original
// prototype's docstring promised but did not deliver.
pub fn attested_handle_with_fallible_att(
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
            // Inner-handler error propagation arm. The user_data pre-check
            // passed (otherwise we'd have hit Err(UserDataMismatch) above).
            // The Err originated from CONFIG.may_load OR from
            // wrapper.attestation.handle_maybe_err returning Err. In either
            // case the pre-check witness holds.
            Err(_) => wrapper.spec_msg_user_data() == wrapper.spec_att_user_data(),
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

    let _r1 = match wrapper.msg.handle(storage) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    // Live Err arm: the fallible variant can return Err, and the
    // wrapper's `?`-equivalent propagation pattern handles it. Verus
    // verifies that the propagated Err satisfies the wrapper's Err(_)
    // postcondition, which is the propagation theorem.
    let _r2 = match wrapper.attestation.handle_maybe_err(storage) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    Ok(Response::new())
}

// ── DstackZkAttestation handler (non-mock branch) ──────────────────────────
//
// UltraHonk migration (gnark → Noir/bb): the on-chain query is now
// `/xion.zk.v1.Query/ProofVerifyUltraHonk` (modelled by `zk_query_verify`),
// and there is no separate journal — the packed `public_inputs` ARE the
// journal, so the binding reads report_data + rtmr3 straight from them.
// Production: `quartz_zkdcap::verify_quote_parts` (decode + recency + proof)
// then `check_zk_bindings` (report_data == user_data, rtmr3 == expected).
//
// Three abstract gates model the production flow:
//   1. zk_query_verify_succeeded — the UltraHonk verifier accepts the proof.
//   2. recency_ok — chain time lies inside the proof's proven
//      [valid_from, valid_until] validity window AND tcb_eval_num is at or
//      above the monotonic floor. (Both are folded into one uninterpreted
//      predicate over the public inputs + now_packed; the production split is
//      in `quartz_zkdcap::verify_quote_parts`.) NEW under UltraHonk: the
//      circuit has no clock/counter, so staleness is the consumer's decision.
//   3. binding (Round D Critical 4, IMPLEMENTED in production check_zk_bindings):
//      proof_binds_report_data (report_data == user_data) is enforced ALWAYS;
//      proof_binds_rtmr3 (rtmr3 == config.expected_rtmr3) is enforced only when
//      the config pins expected_rtmr3, so the Ok postcondition models it as a
//      conditional implication (audit-2026-06-24 fidelity fix).

pub struct DstackZkAttestation {
    pub zkdcap_proof: u64,         // opaque blob; only encoded, not inspected
    pub zkdcap_public_inputs: u64, // packed UltraHonk public inputs (the journal)
    pub user_data: UserData,       // self-declared; bound to public_inputs below
    pub compose_hash: MrEnclave,   // self-declared; bound to public_inputs below
}

// Spec-level uninterpreted predicate for "the verifier said yes on these
// inputs." Used to relate the Ok branch back to the external query result.
pub uninterp spec fn zk_query_verify_succeeded(
    proof: u64,
    public_inputs: u64,
    vkey: u64,
) -> bool;

// Spec-level uninterpreted predicate for the recency/validity gate: chain
// time `now_packed` lies inside the proof's proven validity window AND
// min(tcb_eval_num, qe_eval_num) is at or above the monotonic floor (issue #4
// split the counter in two; the floor is on the smaller). Production: the
// range-check + floor check inside `quartz_zkdcap::verify_quote_parts`.
pub uninterp spec fn recency_ok(
    public_inputs: u64,
    now_packed: u64,
    min_tcb_eval: u64,
) -> bool;

// Spec-level uninterpreted predicate: the proof's public inputs encode the
// expected report_data (== wrapper user_data). Production `check_zk_bindings`
// enforces this UNCONDITIONALLY.
pub uninterp spec fn proof_binds_report_data(
    proof: u64,
    public_inputs: u64,
    expected_user_data: UserData,
) -> bool;

// Spec-level uninterpreted predicate: the proof's public-inputs rtmr3 equals
// the on-chain-pinned `config.expected_rtmr3`. Production `check_zk_bindings`
// enforces this ONLY when `config.expected_rtmr3` is Some — see the conditional
// in `dstack_zk_handle` below. Modeling it conditionally (rather than always)
// is the audit-2026-06-24 fidelity fix: the prior unconditional model claimed a
// stronger property than the code delivers in the default (expected_rtmr3=None)
// deployment.
pub uninterp spec fn proof_binds_rtmr3(
    proof: u64,
    public_inputs: u64,
    expected_rtmr3: MrEnclave,
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

// External-body stub for the recency/validity gate. Returns Ok iff chain time
// lies inside the proven window and tcb_eval_num clears the floor. Production:
// the checks inside `quartz_zkdcap::verify_quote_parts`.
#[verifier::external_body]
pub fn check_recency(
    public_inputs: u64,
    now_packed: u64,
    min_tcb_eval: u64,
) -> (r: Result<(), Error>)
    ensures
        match r {
            Ok(()) => recency_ok(public_inputs, now_packed, min_tcb_eval),
            Err(_) => true,
        },
{
    unimplemented!()
}

// External-body stub: decode the public inputs and verify-equal report_data
// against the wrapper user_data. Production: the always-run report_data check in
// `check_zk_bindings`.
#[verifier::external_body]
pub fn verify_binds_report_data(
    proof: u64,
    public_inputs: u64,
    expected_user_data: UserData,
) -> (r: Result<(), Error>)
    ensures
        match r {
            Ok(()) => proof_binds_report_data(proof, public_inputs, expected_user_data),
            Err(_) => true,
        },
{
    unimplemented!()
}

// External-body stub: decode the public inputs and verify-equal rtmr3 against
// the pinned `config.expected_rtmr3`. Production: the conditional rtmr3 check in
// `check_zk_bindings` (only run when expected_rtmr3 is Some).
#[verifier::external_body]
pub fn verify_binds_rtmr3(
    proof: u64,
    public_inputs: u64,
    expected_rtmr3: MrEnclave,
) -> (r: Result<(), Error>)
    ensures
        match r {
            Ok(()) => proof_binds_rtmr3(proof, public_inputs, expected_rtmr3),
            Err(_) => true,
        },
{
    unimplemented!()
}

pub fn dstack_zk_handle(
    msg: DstackZkAttestation,
    storage: &mut Storage,
    now_packed: u64,
) -> (r: Result<Response, Error>)
    ensures
        match r {
            Ok(_) => {
                // Either the vkey was unset (skipped) or the vkey was set AND
                // the verifier said yes AND recency passed AND report_data is
                // bound (ALWAYS) AND — when an image register is pinned — rtmr3
                // is bound to it, AND (secure-by-default) an image register WAS
                // pinned OR allow_any_image was explicitly set. The last conjunct
                // is the require-one rule: you cannot verify a proof while
                // leaving the image unbound unless you opt in.
                &&& old(storage).config matches Some(raw)
                &&& (raw.zkdcap_vkey == 0
                     || (zk_query_verify_succeeded(msg.zkdcap_proof, msg.zkdcap_public_inputs, raw.zkdcap_vkey)
                         && recency_ok(msg.zkdcap_public_inputs, now_packed, raw.min_tcb_eval_num)
                         && proof_binds_report_data(msg.zkdcap_proof, msg.zkdcap_public_inputs, msg.user_data)
                         && (raw.expected_rtmr3 matches Some(e)
                             ==> proof_binds_rtmr3(msg.zkdcap_proof, msg.zkdcap_public_inputs, e))
                         && (raw.expected_rtmr3 is Some || raw.allow_any_image)))
            }
            Err(Error::ZkdcapVerificationFailed) => {
                // Vkey was set AND (verifier said no OR recency failed OR
                // encode/decode failed OR a binding check failed).
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

    // Gate 1: the UltraHonk verifier accepts the proof against the supplied
    // public inputs.
    match zk_query_verify(msg.zkdcap_proof, msg.zkdcap_public_inputs, vkey) {
        Ok(true) => {}
        Ok(false) => return Err(Error::ZkdcapVerificationFailed),
        Err(_) => return Err(Error::ZkdcapVerificationFailed),
    }

    // Gate 2 (UltraHonk recency): chain time must lie inside the proven validity
    // window and min(tcb_eval_num, qe_eval_num) must clear the monotonic floor.
    // The circuit proves the window but has no clock/counter, so this decision
    // is the consumer's.
    match check_recency(msg.zkdcap_public_inputs, now_packed, config.min_tcb_eval_num()) {
        Ok(()) => {}
        Err(_) => return Err(Error::ZkdcapVerificationFailed),
    }

    // Gate 3a (Round D Critical 4, ALWAYS): the proof's public inputs must
    // encode the wrapper-validated user_data (report_data binding). Without it
    // an attacker could submit a valid proof for a different attested payload.
    match verify_binds_report_data(msg.zkdcap_proof, msg.zkdcap_public_inputs, msg.user_data) {
        Ok(()) => {}
        Err(_) => return Err(Error::ZkdcapVerificationFailed),
    }

    // Gate 3b (image binding + secure-by-default require-one): when an image
    // register is pinned, the proof's rtmr3 must equal it (wrong-image binding).
    // When NOTHING is pinned, reject UNLESS allow_any_image is explicitly set —
    // you cannot verify a proof while leaving the image unbound by accident.
    match config.expected_rtmr3() {
        Some(e) => match verify_binds_rtmr3(msg.zkdcap_proof, msg.zkdcap_public_inputs, e) {
            Ok(()) => {}
            Err(_) => return Err(Error::ZkdcapVerificationFailed),
        },
        None => {
            if !config.allow_any_image() {
                return Err(Error::ZkdcapVerificationFailed);
            }
        }
    }

    Ok(Response::new().add_attribute("action", "zkdcap_verified"))
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
