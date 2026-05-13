// Verus prototype: ECIES encryption wrappers.
// Mirrors src/encryption.rs at the spec level.
//
// Production file (read-only): crates/enclave/core/src/encryption.rs
//   - encrypt(pubkey, plaintext)        delegates to ecies::encrypt
//   - decrypt(privkey, ciphertext)      delegates to ecies::decrypt
//   - encrypt_json<T>(pubkey, value)    serde_json::to_vec + encrypt
//   - decrypt_json<T>(privkey, ct)      decrypt + serde_json::from_slice
//
// Discharges what Specs/Quartz/Crypto/Ecies.lean axiomatizes as `roundtrip`,
// at the COMPOSITION level: the four wrappers preserve the roundtrip given
// that the underlying ECIES primitive and serde_json honour their contracts.
// We do NOT prove secp256k1 hardness, AES-GCM/HKDF correctness, or any
// byte-level serde_json behaviour — those remain trust-boundary axioms.
//
// Monomorphisation for serde-generic `T`: Verus cannot quantify over
// `T: Serialize + DeserializeOwned`, so we pin `T = Message` (a small record).
// The wrappers' correctness does not inspect T's internals, so the proof
// composes by parametricity at the meta-level for any other concrete payload.
//
// Trust-boundary axioms (6, all external_body):
//   verifying_key, ecies_encrypt, ecies_decrypt, serde_to_vec, serde_from_slice
//   ecies_roundtrip_axiom, serde_roundtrip_axiom
//
// Invoke: /tmp/verus-install/verus-arm64-macos/verus encryption.rs

#![allow(unused_imports, unused_variables, dead_code)]

use vstd::prelude::*;

verus! {

// ── Opaque trust-boundary types ────────────────────────────────────────────

#[derive(PartialEq, Eq)]
pub struct SigningKey { pub id: u64 }

#[derive(PartialEq, Eq)]
pub struct VerifyingKey { pub id: u64 }

#[derive(PartialEq, Eq)]
pub enum CryptoError { Ecies, Serde }

// Monomorphised JSON payload. Stands in for any T: Serialize + Deserialize.
#[derive(PartialEq, Eq)]
pub struct Message { pub a: u64, pub b: u64 }

// ── Uninterpreted spec fns ─────────────────────────────────────────────────

pub uninterp spec fn verifying_key_spec(sk: SigningKey) -> VerifyingKey;
pub uninterp spec fn ecies_encrypt_spec(pk: VerifyingKey, pt: Seq<u8>) -> Result<Seq<u8>, CryptoError>;
pub uninterp spec fn ecies_decrypt_spec(sk: SigningKey, ct: Seq<u8>) -> Result<Seq<u8>, CryptoError>;
pub uninterp spec fn serde_to_vec_spec(v: Message) -> Result<Seq<u8>, CryptoError>;
pub uninterp spec fn serde_from_slice_spec(b: Seq<u8>) -> Result<Message, CryptoError>;

// ── External-body wrappers (trust boundary) ────────────────────────────────

#[verifier::external_body]
pub fn verifying_key(sk: &SigningKey) -> (r: VerifyingKey)
    ensures r == verifying_key_spec(*sk),
{ unimplemented!() }

#[verifier::external_body]
pub fn ecies_encrypt(pk: &VerifyingKey, pt: &Vec<u8>) -> (r: Result<Vec<u8>, CryptoError>)
    ensures
        match r {
            Ok(c)  => ecies_encrypt_spec(*pk, pt@) == Result::<Seq<u8>, CryptoError>::Ok(c@),
            Err(e) => ecies_encrypt_spec(*pk, pt@) == Result::<Seq<u8>, CryptoError>::Err(e),
        },
{ unimplemented!() }

#[verifier::external_body]
pub fn ecies_decrypt(sk: &SigningKey, ct: &Vec<u8>) -> (r: Result<Vec<u8>, CryptoError>)
    ensures
        match r {
            Ok(p)  => ecies_decrypt_spec(*sk, ct@) == Result::<Seq<u8>, CryptoError>::Ok(p@),
            Err(e) => ecies_decrypt_spec(*sk, ct@) == Result::<Seq<u8>, CryptoError>::Err(e),
        },
{ unimplemented!() }

#[verifier::external_body]
pub fn serde_to_vec(v: &Message) -> (r: Result<Vec<u8>, CryptoError>)
    ensures
        match r {
            Ok(b)  => serde_to_vec_spec(*v) == Result::<Seq<u8>, CryptoError>::Ok(b@),
            Err(e) => serde_to_vec_spec(*v) == Result::<Seq<u8>, CryptoError>::Err(e),
        },
{ unimplemented!() }

#[verifier::external_body]
pub fn serde_from_slice(b: &Vec<u8>) -> (r: Result<Message, CryptoError>)
    ensures
        match r {
            Ok(v)  => serde_from_slice_spec(b@) == Result::<Message, CryptoError>::Ok(v),
            Err(e) => serde_from_slice_spec(b@) == Result::<Message, CryptoError>::Err(e),
        },
{ unimplemented!() }

// ── Trust-boundary roundtrip axioms ────────────────────────────────────────
// Match Lean's `roundtrip` axiom (total: encrypt succeeds and decrypt
// recovers the plaintext). serde_json is similarly assumed total on Message
// (no NaN floats, no nonstring map keys — the discipline serde_json honours
// on small records of primitives).

#[verifier::external_body]
pub proof fn ecies_roundtrip_axiom(sk: SigningKey, pt: Seq<u8>)
    ensures
        ecies_encrypt_spec(verifying_key_spec(sk), pt) is Ok,
        match ecies_encrypt_spec(verifying_key_spec(sk), pt) {
            Ok(bytes) => ecies_decrypt_spec(sk, bytes) == Result::<Seq<u8>, CryptoError>::Ok(pt),
            Err(_)    => false,
        },
{}

#[verifier::external_body]
pub proof fn serde_roundtrip_axiom(v: Message)
    ensures
        serde_to_vec_spec(v) is Ok,
        match serde_to_vec_spec(v) {
            Ok(bytes) => serde_from_slice_spec(bytes) == Result::<Message, CryptoError>::Ok(v),
            Err(_)    => false,
        },
{}

// ── Production-mirror wrappers ─────────────────────────────────────────────
// Mirror src/encryption.rs exactly, swapping `String` errors for `CryptoError`
// (Verus handles enums cleanly; format!() strings less so).

/// Mirrors `encrypt(pubkey, plaintext)`.
pub fn encrypt(pubkey: &VerifyingKey, plaintext: &Vec<u8>) -> (r: Result<Vec<u8>, CryptoError>)
    ensures
        match r {
            Ok(c)  => ecies_encrypt_spec(*pubkey, plaintext@) == Result::<Seq<u8>, CryptoError>::Ok(c@),
            Err(e) => ecies_encrypt_spec(*pubkey, plaintext@) == Result::<Seq<u8>, CryptoError>::Err(e),
        },
{
    ecies_encrypt(pubkey, plaintext)
}

/// Mirrors `decrypt(privkey, ciphertext)`.
pub fn decrypt(privkey: &SigningKey, ciphertext: &Vec<u8>) -> (r: Result<Vec<u8>, CryptoError>)
    ensures
        match r {
            Ok(p)  => ecies_decrypt_spec(*privkey, ciphertext@) == Result::<Seq<u8>, CryptoError>::Ok(p@),
            Err(e) => ecies_decrypt_spec(*privkey, ciphertext@) == Result::<Seq<u8>, CryptoError>::Err(e),
        },
{
    ecies_decrypt(privkey, ciphertext)
}

/// Mirrors `encrypt_json::<Message>(pubkey, value)`.
pub fn encrypt_json(pubkey: &VerifyingKey, value: &Message) -> (r: Result<Vec<u8>, CryptoError>)
    ensures
        match r {
            Ok(c) => exists |bytes: Seq<u8>| #![auto]
                serde_to_vec_spec(*value) == Result::<Seq<u8>, CryptoError>::Ok(bytes)
                && ecies_encrypt_spec(*pubkey, bytes) == Result::<Seq<u8>, CryptoError>::Ok(c@),
            Err(_) => true,
        },
{
    let serialized = match serde_to_vec(value) {
        Ok(b)  => b,
        Err(_) => return Err(CryptoError::Serde),
    };
    encrypt(pubkey, &serialized)
}

/// Mirrors `decrypt_json::<Message>(privkey, ciphertext)`.
pub fn decrypt_json(privkey: &SigningKey, ciphertext: &Vec<u8>) -> (r: Result<Message, CryptoError>)
    ensures
        match r {
            Ok(v) => exists |bytes: Seq<u8>| #![auto]
                ecies_decrypt_spec(*privkey, ciphertext@) == Result::<Seq<u8>, CryptoError>::Ok(bytes)
                && serde_from_slice_spec(bytes) == Result::<Message, CryptoError>::Ok(v),
            Err(_) => true,
        },
{
    let plaintext = match decrypt(privkey, ciphertext) {
        Ok(p)  => p,
        Err(_) => return Err(CryptoError::Ecies),
    };
    serde_from_slice(&plaintext)
}

// ── Roundtrip theorems ─────────────────────────────────────────────────────

/// Property 1: `decrypt(sk, encrypt(verifying_key(sk), pt)) == Ok(pt)`.
/// Direct corollary of the ECIES-roundtrip axiom — pins that the
/// encrypt/decrypt wrappers are pure delegation (no pre/post mangling).
pub proof fn encrypt_decrypt_roundtrip(sk: SigningKey, pt: Seq<u8>)
    ensures
        ecies_encrypt_spec(verifying_key_spec(sk), pt) is Ok,
        match ecies_encrypt_spec(verifying_key_spec(sk), pt) {
            Ok(bytes) => ecies_decrypt_spec(sk, bytes) == Result::<Seq<u8>, CryptoError>::Ok(pt),
            Err(_)    => false,
        },
{
    ecies_roundtrip_axiom(sk, pt);
}

/// Property 2: `decrypt_json(sk, encrypt_json(verifying_key(sk), msg)) == Ok(msg)`.
/// Chains the serde-roundtrip and ECIES-roundtrip axioms.
pub proof fn encrypt_json_decrypt_json_roundtrip(sk: SigningKey, msg: Message)
    ensures
        serde_to_vec_spec(msg) is Ok,
        match serde_to_vec_spec(msg) {
            Ok(bytes) => {
                &&& ecies_encrypt_spec(verifying_key_spec(sk), bytes) is Ok
                &&& (match ecies_encrypt_spec(verifying_key_spec(sk), bytes) {
                    Ok(ct) => ecies_decrypt_spec(sk, ct) == Result::<Seq<u8>, CryptoError>::Ok(bytes),
                    Err(_) => false,
                })
                &&& serde_from_slice_spec(bytes) == Result::<Message, CryptoError>::Ok(msg)
            }
            Err(_) => false,
        },
{
    serde_roundtrip_axiom(msg);
    let bytes: Seq<u8> = match serde_to_vec_spec(msg) {
        Ok(b)  => b,
        Err(_) => Seq::<u8>::empty(),
    };
    ecies_roundtrip_axiom(sk, bytes);
}

} // verus!

fn main() {}
