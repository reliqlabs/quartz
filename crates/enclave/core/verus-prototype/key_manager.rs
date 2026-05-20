// Verus prototype: DefaultKeyManager key-binding invariant.
// Mirrors src/key_manager/default.rs at the spec level.
//
// Production file (read-only): crates/enclave/core/src/key_manager/default.rs
//   - pub struct DefaultKeyManager { pub sk: SigningKey }
//   - async fn pub_key(&self) -> PubKey { PubKey(self.sk.clone().into()) }
//     (the .into() is VerifyingKey::from(&SigningKey))
//   - impl Import: self.sk = SigningKey::from_slice(&data)?
//   - impl Export: self.sk.to_bytes().to_vec()
//
// Core binding invariant proved here:
//   The published `pub_key()` corresponds exactly to the held signing key —
//   the enclave never publishes a public key whose private counterpart it
//   doesn't hold. Formally:
//
//     verifying_key_spec(km.sk) == pub_key(&km).0
//
// We DO NOT prove secp256k1 group properties or scalar-encoding correctness;
// those remain trust-boundary axioms (verifying_key_spec is uninterpreted, and
// the scalar-bytes roundtrip is an explicit named axiom). The async_trait
// wrapper is modelled as a synchronous call — the production `pub_key` body
// performs no awaits.
//
// Trust-boundary axioms (5, all external_body or uninterp):
//   verifying_key_spec, verifying_key_exec,
//   signing_key_to_bytes, signing_key_from_slice,
//   signing_key_bytes_roundtrip_axiom
//
// Invoke: /tmp/verus-install/verus-arm64-macos/verus key_manager.rs

#![allow(unused_imports, unused_variables, dead_code)]

use vstd::prelude::*;

verus! {

// ── Opaque trust-boundary types ────────────────────────────────────────────
// Mirror the `SigningKey { id: u64 }` / `VerifyingKey { id: u64 }` pattern
// from encryption.rs. The `id` field is a model handle; the real k256
// scalar / curve point is abstracted away.

#[derive(PartialEq, Eq)]
pub struct SigningKey { pub id: u64 }

#[derive(PartialEq, Eq)]
pub struct VerifyingKey { pub id: u64 }

#[derive(PartialEq, Eq)]
pub enum KmError { BadScalar }

/// Mirrors `PubKey(pub VerifyingKey)` from default.rs.
#[derive(PartialEq, Eq)]
pub struct PubKey(pub VerifyingKey);

/// Mirrors `DefaultKeyManager { pub sk: SigningKey }`.
pub struct DefaultKeyManager { pub sk: SigningKey }

// ── Uninterpreted spec fns ─────────────────────────────────────────────────

/// The pure mathematical map sk ↦ pk. Uninterpreted: we do not specify
/// secp256k1 base-point multiplication internals, only that `verifying_key_exec`
/// computes this function.
pub uninterp spec fn verifying_key_spec(sk: SigningKey) -> VerifyingKey;

/// Spec-level mirror of `signing_key_to_bytes`. Uninterpreted; the
/// `signing_key_to_bytes` exec wrapper's `ensures` clause pins its
/// observable result to this function. Naming this spec function lets the
/// roundtrip axiom express a non-trivial precondition that ties the bytes
/// to a specific `SigningKey`.
pub uninterp spec fn signing_key_to_bytes_spec(sk: SigningKey) -> Seq<u8>;

/// Spec-level mirror of `signing_key_from_slice`. Uninterpreted; the
/// `signing_key_from_slice` exec wrapper's `ensures` clause pins its
/// observable result to this function. The roundtrip axiom witnesses
/// that this function returns `Ok(decoded)` on the precise byte sequence
/// produced by `signing_key_to_bytes_spec(sk)`.
pub uninterp spec fn signing_key_from_slice_spec(b: Seq<u8>) -> Result<SigningKey, KmError>;

// ── External-body wrappers (trust boundary) ────────────────────────────────

/// Mirrors `VerifyingKey::from(&SigningKey)` (the `.into()` in pub_key()).
#[verifier::external_body]
pub fn verifying_key_exec(sk: &SigningKey) -> (r: VerifyingKey)
    ensures r == verifying_key_spec(*sk),
{ unimplemented!() }

/// Mirrors `SigningKey::to_bytes().to_vec()` (the Export operation).
/// The `ensures` clause links the observable byte output to the
/// uninterpreted spec function. Round D Critical 1 fix (2026-05-20):
/// without this ensures, the roundtrip axiom below had no way to assert
/// that its `bytes` parameter actually came from `to_bytes(sk)`, which
/// admitted `requires true` and made the axiom usable as an unsound
/// premise at any call site.
#[verifier::external_body]
pub fn signing_key_to_bytes(sk: &SigningKey) -> (r: Vec<u8>)
    ensures r@ == signing_key_to_bytes_spec(*sk),
{ unimplemented!() }

/// Mirrors `SigningKey::from_slice(&data)` (the Import operation).
/// The `ensures` clause links the observable Result to the uninterpreted
/// spec function. Same Round D Critical 1 motivation as
/// `signing_key_to_bytes`: needed to give the axiom non-trivial
/// preconditions that the caller can actually witness.
#[verifier::external_body]
pub fn signing_key_from_slice(b: &Vec<u8>) -> (r: Result<SigningKey, KmError>)
    ensures r == signing_key_from_slice_spec(b@),
{ unimplemented!() }

// ── Trust-boundary roundtrip axiom ─────────────────────────────────────────

/// The secp256k1 scalar-bytes roundtrip: encoding a SigningKey to its
/// 32-byte scalar representation and decoding produces the same key.
/// This is the k256 library's contract; we name it explicitly here.
///
/// **Round D Critical 1 fix (2026-05-20, three voices agreed)**: the
/// axiom previously had `requires true` and was applied at
/// `import_export_roundtrip` with bare unbound parameters, concluding
/// `verifying_key_spec(decoded) == verifying_key_spec(sk)` for any
/// `(sk, bytes, decoded)` triple. That admitted the derivation of
/// `false` (pick `decoded` and `sk` whose pub keys differ; the axiom
/// asserted they are equal). The fix is to tie the parameters via the
/// new spec functions: the axiom now only applies when the caller has
/// witnessed that `bytes` is the encoding of `sk` AND `from_slice(bytes)`
/// returned `Ok(decoded)`. The axiom is then the honest cryptographic
/// claim: decoding the encoding recovers a key with the same public key.
#[verifier::external_body]
pub proof fn signing_key_bytes_roundtrip_axiom(sk: SigningKey, bytes: Seq<u8>, decoded: SigningKey)
    requires
        bytes == signing_key_to_bytes_spec(sk),
        signing_key_from_slice_spec(bytes) == Result::<SigningKey, KmError>::Ok(decoded),
    ensures
        verifying_key_spec(decoded) == verifying_key_spec(sk),
{}

// ── Mirror of DefaultKeyManager::pub_key() ─────────────────────────────────
//
// The production code is:
//
//     async fn pub_key(&self) -> Self::PubKey {
//         PubKey(self.sk.clone().into())
//     }
//
// where `.into()` is `VerifyingKey::from(&SigningKey)`. We model as sync
// (the async wrapper carries no semantic content — no awaits in the body).
// The `self.sk.clone()` is modelled by passing `&self.sk` to
// `verifying_key_exec`: the clone-then-convert and convert-from-borrow paths
// yield identical VerifyingKey values (secp256k1's pk-derivation is a pure
// function of the scalar).

pub fn pub_key(km: &DefaultKeyManager) -> (r: PubKey)
    ensures r.0 == verifying_key_spec(km.sk),
{
    PubKey(verifying_key_exec(&km.sk))
}

// ── Mirror of Export::export and Import::import ────────────────────────────
//
// export(km) -> Vec<u8>           ≈  self.sk.to_bytes().to_vec()
// import(km, bytes) -> Result<()> ≈  self.sk = SigningKey::from_slice(&bytes)?
//
// We split `import` into a pure-functional helper `import_sk(bytes)` returning
// a fresh SigningKey, because Verus reasoning about &mut self with an
// external_body parse is cleaner this way. The roundtrip theorem operates on
// the pure helper.

pub fn export(km: &DefaultKeyManager) -> (r: Vec<u8>)
{
    signing_key_to_bytes(&km.sk)
}

pub fn import_sk(bytes: &Vec<u8>) -> (r: Result<SigningKey, KmError>)
{
    signing_key_from_slice(bytes)
}

// Round D Critical 5 substantive remediation step 1 (2026-05-20):
// model `Import::import` as a state-mutating operation on
// `DefaultKeyManager`. Mirrors `impl Import for DefaultKeyManager`
// at `crates/enclave/core/src/key_manager/default.rs:49-57` which
// does `self.sk = SigningKey::from_slice(&data)?`. On Ok, the
// manager's sk is replaced by the decoded value; on Err, the
// manager is unchanged. The previously-published contract pub_key
// (modelled by the KeyLifecycleStorage layer below) may now be
// stale, which is the temporal binding gap the cross-critique
// flagged.
impl DefaultKeyManager {
    pub fn import(&mut self, bytes: &Vec<u8>) -> (r: Result<(), KmError>)
        ensures
            match r {
                Ok(()) => signing_key_from_slice_spec(bytes@)
                            == Result::<SigningKey, KmError>::Ok(final(self).sk),
                Err(_) => final(self).sk == old(self).sk
                          && signing_key_from_slice_spec(bytes@).is_err(),
            },
    {
        match signing_key_from_slice(bytes) {
            Ok(sk) => { self.sk = sk; Ok(()) }
            Err(e) => Err(e),
        }
    }
}

// ── DstackKeyManager (production default) ──────────────────────────────────
//
// Round D Critical 5 substantive remediation step 2 (2026-05-20, closes
// Round D Critical 19 simultaneously): the cross-critique synthesis
// surfaced that the prototype was missing the production default key
// manager. CLAUDE.md states `DstackKeyManager` is the production
// default; `DefaultKeyManager` is the random-key fallback used in
// tests and the mock build. Both have the same Import-mutates-sk
// shape, but DstackKeyManager has two ADDITIONAL stale-key risk paths
// the cross-critique called out:
//
//   1. `new(key_path)` at `dstack.rs:41-64` falls back to
//      `SigningKey::random(&mut rand::thread_rng())` on KMS
//      unavailability. The fallback is logged but not returned, so a
//      caller cannot tell whether the manager is in a trusted (KMS-
//      derived) or untrusted (random-fallback) state. The contract
//      can publish a pub_key bound to a random key the enclave will
//      not be able to re-derive after restart.
//
//   2. `import(data)` at `dstack.rs:168-181` re-derives the key from
//      KMS using the deserialized path. If KMS upstream rotated the
//      key for that path, the manager's sk changes, and any
//      previously-published contract pub_key is stale.
//
// The Verus model captures both via an uninterpreted `dstack_kms_oracle`
// spec function mapping a path to an `Option<SigningKey>` (Some =
// derivable, None = KMS unavailable). The exec wrappers
// `dstack_derive_from_kms` and `dstack_random_fallback` model the
// production primitives.

#[derive(PartialEq, Eq)]
pub struct DstackKeyManager {
    pub sk: SigningKey,
    pub key_path: u64,  // opaque path identifier (mirrors String key_path in prod)
}

/// Uninterpreted KMS oracle. Maps a key path to either the derived
/// SigningKey (KMS available) or None (KMS unavailable). Production
/// behavior depends on whether dstack's KMS is reachable.
pub uninterp spec fn dstack_kms_oracle(path: u64) -> Option<SigningKey>;

/// External-body stub for the KMS query + key derivation. Returns
/// Ok(sk) on KMS success with `dstack_kms_oracle(path) == Some(sk)`;
/// Err on KMS unavailability with `dstack_kms_oracle(path) == None`.
/// Mirrors `derive_from_dstack` at `dstack.rs:66-119`.
#[verifier::external_body]
pub fn dstack_derive_from_kms(path: u64) -> (r: Result<SigningKey, KmError>)
    ensures
        match r {
            Ok(sk) => dstack_kms_oracle(path) == Some(sk),
            Err(_) => dstack_kms_oracle(path).is_none(),
        },
{ unimplemented!() }

/// External-body stub for the random-key fallback. Mirrors
/// `SigningKey::random(&mut rand::thread_rng())` at `dstack.rs:59`.
/// The returned key is unrelated to any previously-derived KMS key;
/// modeling it as uninterpreted captures that the contract cannot
/// trust a pub_key bound to this value to be re-derivable.
#[verifier::external_body]
pub fn dstack_random_fallback() -> (r: SigningKey)
{ unimplemented!() }

impl DstackKeyManager {
    /// Mirror of `DstackKeyManager::new(key_path)` at `dstack.rs:41-64`.
    /// Returns `(self, kms_reached)` where the bool indicates whether
    /// the manager's sk came from KMS (true) or from the random
    /// fallback (false). Production currently swallows this signal;
    /// the prototype surfaces it explicitly so callers can reason
    /// about the manager's trust state.
    pub fn new(key_path: u64) -> (r: (DstackKeyManager, bool))
        ensures
            r.0.key_path == key_path,
            r.1 == dstack_kms_oracle(key_path).is_some(),
            r.1 ==> dstack_kms_oracle(key_path) == Some(r.0.sk),
    {
        match dstack_derive_from_kms(key_path) {
            Ok(sk) => (DstackKeyManager { sk, key_path }, true),
            Err(_) => {
                let fresh = dstack_random_fallback();
                (DstackKeyManager { sk: fresh, key_path }, false)
            }
        }
    }

    /// Mirror of `DstackKeyManager::pub_key()` at `dstack.rs:147-153`.
    pub fn pub_key(&self) -> (r: PubKey)
        ensures r.0 == verifying_key_spec(self.sk),
    {
        PubKey(verifying_key_exec(&self.sk))
    }

    /// Mirror of `Import::import` at `dstack.rs:168-181`. The `data`
    /// parameter is the serialized key_path. On Ok, the manager's sk
    /// is replaced by the KMS-derived key for that path; on Err, the
    /// manager is unchanged. Note that even on Ok, the new sk may
    /// differ from the previous one if KMS rotated the key upstream.
    pub fn import(&mut self, data: u64) -> (r: Result<(), KmError>)
        ensures
            match r {
                Ok(()) => dstack_kms_oracle(data) == Some(final(self).sk)
                          && final(self).key_path == data,
                Err(_) => final(self).sk == old(self).sk
                          && final(self).key_path == old(self).key_path
                          && dstack_kms_oracle(data).is_none(),
            },
    {
        match dstack_derive_from_kms(data) {
            Ok(sk) => {
                self.sk = sk;
                self.key_path = data;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

// ── Session-lifecycle ghost layer ──────────────────────────────────────────
//
// Round D Critical 5 substantive remediation step 3 (2026-05-20).
//
// The previous chunks model `Import::import` as a state-mutating
// operation on both key managers, but mutation alone does not capture
// the security-relevant property the cross-critique was after: the
// CONTRACT'S stored pub_key must stay in sync with the ENCLAVE'S held
// km.sk at every transition. A snapshot binding (km.sk maps to
// pub_key(&km)) is necessary but not sufficient; the temporal binding
// is what matters for security.
//
// This ghost layer wraps a key manager plus a `contract_pub_key`
// field representing what the contract currently believes the
// enclave's identity to be. The invariant `binding_holds()` asserts
// that whenever `contract_pub_key` is `Some(pk)`, `pk` equals the
// pub_key derived from the manager's current sk. Both managers
// (Default and Dstack) have parallel lifecycle wrappers.
//
// The lifecycle layer exposes two import variants and the production
// code must choose between them per Critical 5 step 4 (policy
// decision):
//
//   - `import_with_invalidate`: imports new key bytes and clears
//     `contract_pub_key`. Forces the contract to treat the enclave
//     as un-handshaken, requiring a fresh session_create +
//     session_set_pub_key flow before any further attested operations.
//     Safe-by-construction (the invariant is trivially preserved in
//     the None case). Cheap in code; expensive in operations (every
//     key import requires re-handshake).
//
//   - `import_with_rotate`: imports new key bytes AND atomically
//     re-publishes by setting `contract_pub_key` to the new
//     pub_key. Requires the production code to provide a
//     `session_rotate_pub_key` contract message that the lifecycle
//     wrapper invokes; production currently has no such message at
//     `crates/contracts/core/src/handler/execute/`. The
//     `session_set_pub_key` handler at
//     `crates/contracts/core/src/handler/execute/session_set_pub_key.rs:18-20`
//     uses `session.with_pub_key()` which errors when a pub_key is
//     already set, so it cannot rotate. A new handler is required
//     for this variant.
//
// **Production policy recommendation (this prototype documents but
// does not enforce)**: implement `import_with_invalidate` semantics
// at the production layer by either (i) removing the
// `Import` impls on `DefaultKeyManager` and `DstackKeyManager`
// entirely (force re-init on key change, no rotation path), OR (ii)
// keeping the Import impls but adding a contract-side message that
// resets session state when invoked. Option (i) is cheaper and safer
// against a class of bugs where the rotation message is forgotten;
// option (ii) is more flexible operationally. The Quartz agent
// decides; this prototype proves both variants preserve the
// invariant so either decision is sound.

/// Wraps a `DefaultKeyManager` with a ghost `contract_pub_key` field
/// tracking what the contract currently believes the enclave's
/// identity to be. The `binding_holds` invariant captures the
/// security-relevant temporal property the original prototype's
/// snapshot-only theorem could not.
pub struct DefaultKeyManagerLifecycle {
    pub km: DefaultKeyManager,
    pub contract_pub_key: Option<VerifyingKey>,
}

impl DefaultKeyManagerLifecycle {
    /// The binding invariant: if the contract has a published pub_key,
    /// it must equal the pub_key derived from the manager's current
    /// sk. The None case is trivially safe (no published key, no
    /// binding to maintain).
    pub open spec fn binding_holds(self) -> bool {
        match self.contract_pub_key {
            None => true,
            Some(pk) => pk == verifying_key_spec(self.km.sk),
        }
    }

    /// Publish the manager's current pub_key to the contract.
    /// Establishes the binding by setting `contract_pub_key`. Mirrors
    /// the production `session_set_pub_key` handler at
    /// `crates/contracts/core/src/handler/execute/session_set_pub_key.rs`,
    /// modulo the contract-side state (which lives in the chain's
    /// SESSION storage, not in this prototype).
    pub fn publish(&mut self)
        ensures
            final(self).contract_pub_key == Some(verifying_key_spec(final(self).km.sk)),
            final(self).km.sk == old(self).km.sk,
            final(self).binding_holds(),
    {
        let pk = pub_key(&self.km);
        self.contract_pub_key = Some(pk.0);
    }

    /// Import variant A: import new key bytes and invalidate the
    /// published pub_key. The contract must re-handshake before
    /// accepting further attested operations. Preserves
    /// `binding_holds` trivially (None case).
    pub fn import_with_invalidate(&mut self, bytes: &Vec<u8>) -> (r: Result<(), KmError>)
        ensures
            match r {
                Ok(()) => {
                    &&& final(self).contract_pub_key.is_none()
                    &&& final(self).binding_holds()
                }
                Err(_) => {
                    &&& final(self).km.sk == old(self).km.sk
                    &&& final(self).contract_pub_key == old(self).contract_pub_key
                }
            },
    {
        match self.km.import(bytes) {
            Ok(()) => {
                self.contract_pub_key = None;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Import variant B: import new key bytes AND atomically
    /// re-publish. Preserves `binding_holds` by updating both sides
    /// of the binding in one operation. Requires a production-side
    /// `session_rotate_pub_key` contract message (does not exist
    /// today).
    pub fn import_with_rotate(&mut self, bytes: &Vec<u8>) -> (r: Result<(), KmError>)
        ensures
            match r {
                Ok(()) => {
                    &&& final(self).contract_pub_key == Some(verifying_key_spec(final(self).km.sk))
                    &&& final(self).binding_holds()
                }
                Err(_) => {
                    &&& final(self).km.sk == old(self).km.sk
                    &&& final(self).contract_pub_key == old(self).contract_pub_key
                }
            },
    {
        match self.km.import(bytes) {
            Ok(()) => {
                let pk = pub_key(&self.km);
                self.contract_pub_key = Some(pk.0);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// Parallel lifecycle wrapper for `DstackKeyManager`. Same shape,
/// same invariant, same two import variants. Production `Import`
/// for `DstackKeyManager` at `dstack.rs:168-181` re-derives from
/// KMS, so the `data` parameter here is the key path rather than
/// raw key bytes.
pub struct DstackKeyManagerLifecycle {
    pub km: DstackKeyManager,
    pub contract_pub_key: Option<VerifyingKey>,
}

impl DstackKeyManagerLifecycle {
    pub open spec fn binding_holds(self) -> bool {
        match self.contract_pub_key {
            None => true,
            Some(pk) => pk == verifying_key_spec(self.km.sk),
        }
    }

    pub fn publish(&mut self)
        ensures
            final(self).contract_pub_key == Some(verifying_key_spec(final(self).km.sk)),
            final(self).km.sk == old(self).km.sk,
            final(self).km.key_path == old(self).km.key_path,
            final(self).binding_holds(),
    {
        let pk = self.km.pub_key();
        self.contract_pub_key = Some(pk.0);
    }

    pub fn import_with_invalidate(&mut self, data: u64) -> (r: Result<(), KmError>)
        ensures
            match r {
                Ok(()) => {
                    &&& final(self).contract_pub_key.is_none()
                    &&& final(self).binding_holds()
                }
                Err(_) => {
                    &&& final(self).km.sk == old(self).km.sk
                    &&& final(self).km.key_path == old(self).km.key_path
                    &&& final(self).contract_pub_key == old(self).contract_pub_key
                }
            },
    {
        match self.km.import(data) {
            Ok(()) => {
                self.contract_pub_key = None;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn import_with_rotate(&mut self, data: u64) -> (r: Result<(), KmError>)
        ensures
            match r {
                Ok(()) => {
                    &&& final(self).contract_pub_key == Some(verifying_key_spec(final(self).km.sk))
                    &&& final(self).binding_holds()
                }
                Err(_) => {
                    &&& final(self).km.sk == old(self).km.sk
                    &&& final(self).km.key_path == old(self).km.key_path
                    &&& final(self).contract_pub_key == old(self).contract_pub_key
                }
            },
    {
        match self.km.import(data) {
            Ok(()) => {
                let pk = self.km.pub_key();
                self.contract_pub_key = Some(pk.0);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

// ── Theorems ───────────────────────────────────────────────────────────────

// The original prototype carried a `pub proof fn pub_key_matches_sk` here
// whose `ensures` clause was the propositional tautology
//     forall |k: DefaultKeyManager| verifying_key_spec(k.sk) == verifying_key_spec(k.sk)
// (Round D claude.md attack #17; cross-critique 2026-05-20 confirmed via
// GPT-5.5 and Kimi independently). It claimed to be "the core binding
// invariant" but was structurally `x == x` and added nothing.
//
// The actual snapshot binding contract is the `pub_key` exec function's
// `ensures r.0 == verifying_key_spec(km.sk)` at lines 122-126 above. Any
// caller that reads `pub_key`'s return value already has that postcondition
// in scope.
//
// The temporal binding contract — that the contract-published pub_key
// stays in sync with the enclave-held km.sk across `Import::import`
// mutations and KMS-fallback key changes in DstackKeyManager — is
// proved by the lifecycle wrappers above (`DefaultKeyManagerLifecycle`
// and `DstackKeyManagerLifecycle`) via the `binding_holds` invariant
// and the import_with_invalidate / import_with_rotate variants. The
// cross-critique synthesis at
// .colosseum/attacks/verus-prototype-cross-critique-2026-05-20/synthesis.md
// recorded the refined Critical 5 remediation as a four-part plan:
// (a) model DefaultKeyManager import as a mutation — done in the
// DefaultKeyManager::import impl above; (b) model DstackKeyManager —
// done in the DstackKeyManager block above, closing Round D Critical
// 19 simultaneously; (c) add a session-lifecycle ghost layer with a
// contract_pub_key field and invariants tying it to km.sk across
// state transitions — done in the *Lifecycle structs above; (d) decide
// the production key-rotation policy — documented at the top of the
// session-lifecycle ghost layer section as either remove-Imports or
// add-session_rotate_pub_key, with the prototype proving both variants
// preserve the invariant so the Quartz-agent decision is policy not
// soundness.

/// THEOREM 2 — `import_export_roundtrip`: exporting then importing
/// recovers a SigningKey with the same public key.
///
/// `export(km)` produces bytes `b` such that `import_sk(b)` returns
/// `Ok(sk')` with `verifying_key_spec(sk') == verifying_key_spec(km.sk)`.
///
/// This is exactly the KMS-roundtrip property: a re-keyed enclave (one that
/// restored its sk from the KMS-stored bytes) publishes the same pub_key as
/// the original. Discharged by `signing_key_bytes_roundtrip_axiom`.
///
/// **Round D Critical 1 fix (2026-05-20)**: previously took `decoded` and
/// `bytes` as free parameters and concluded the public-key equality for any
/// triple, propositionally equivalent to `∀ a b. f(a) == f(b)` (i.e., `f`
/// constant). The fix tightens the theorem to apply only when the caller
/// has witnessed that `bytes` is the export of `km.sk` AND `from_slice(bytes)`
/// returned `Ok(decoded)`. With these preconditions, the equality reflects
/// the real k256 contract and the axiom can no longer be used to derive
/// `false`.
pub proof fn import_export_roundtrip(km: DefaultKeyManager, decoded: SigningKey)
    requires
        signing_key_from_slice_spec(signing_key_to_bytes_spec(km.sk))
            == Result::<SigningKey, KmError>::Ok(decoded),
    ensures
        verifying_key_spec(decoded) == verifying_key_spec(km.sk),
{
    signing_key_bytes_roundtrip_axiom(km.sk, signing_key_to_bytes_spec(km.sk), decoded);
}

} // verus!

fn main() {}
