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
// mutations and KMS-fallback key changes in DstackKeyManager — is NOT
// proved by this prototype. The cross-critique synthesis at
// .colosseum/attacks/verus-prototype-cross-critique-2026-05-20/synthesis.md
// records the refined Critical 5 remediation: (a) model DefaultKeyManager
// import as a mutation, (b) model DstackKeyManager (currently unmodeled),
// (c) add a session-lifecycle ghost layer with a contract_pub_key field
// and invariants tying it to km.sk across state transitions, (d) decide
// the production key-rotation policy. That work is a follow-up cycle.

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
