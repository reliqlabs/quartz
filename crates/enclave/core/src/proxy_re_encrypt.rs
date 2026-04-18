//! Proxy Re-Encryption for Quartz enclaves.
//!
//! Allows data encrypted to the enclave's session key to be re-encrypted
//! for an authorized third party. The enclave decrypts and re-encrypts
//! internally — the plaintext exists momentarily in TEE memory only.
//!
//! # Why not "true" PRE?
//!
//! True proxy re-encryption (where a public re-encryption key allows
//! anyone to transform ciphertexts without seeing the plaintext) requires
//! pairing-based cryptography (BLS12-381). The secp256k1 curve used by
//! Quartz session keys does not support pairings.
//!
//! In the TEE context, the enclave already holds the private key, so
//! decrypt-and-re-encrypt achieves the same result: the caller provides
//! a ciphertext encrypted to the enclave and receives a ciphertext
//! encrypted to the recipient. The enclave is the "proxy" and it's
//! trusted by design (TDX hardware isolation).
//!
//! For public-safe re-encryption keys (storable on-chain, usable by
//! untrusted parties), use pairing-based AFGH PRE over BLS12-381 — see
//! the IBE module in commonware's crypto crate.
//!
//! # Security
//!
//! - CPA-secure ElGamal encryption over secp256k1
//! - 32-byte message limit (use as KEM for larger payloads)
//! - Randomized: encrypting the same message twice produces different ciphertexts

use k256::{
    ecdsa::SigningKey,
    elliptic_curve::{
        group::GroupEncoding,
        ops::MulByGenerator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};

/// An encrypted 32-byte message.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Ciphertext {
    /// Ephemeral public point: k * G
    pub c1: Vec<u8>,
    /// Encrypted data: msg XOR H(k * pk)
    pub c2: Vec<u8>,
}

/// Derive a symmetric key from a curve point.
fn kdf(point: &ProjectivePoint) -> [u8; 32] {
    let encoded = point.to_encoded_point(true);
    let mut hasher = Sha256::new();
    hasher.update(b"quartz_pre_kdf");
    hasher.update(encoded.as_bytes());
    hasher.finalize().into()
}

/// XOR two 32-byte arrays.
fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Encrypt a 32-byte message to a public key.
///
/// For messages longer than 32 bytes, encrypt a random symmetric key
/// with this function, then use that key with AES-GCM for the payload.
pub fn encrypt(recipient_pk: &k256::PublicKey, message: &[u8; 32]) -> Ciphertext {
    let k = Scalar::random(&mut rand::thread_rng());
    let c1_point = ProjectivePoint::mul_by_generator(&k);
    let shared = ProjectivePoint::from(recipient_pk.as_affine()) * k;
    let mask = kdf(&shared);

    Ciphertext {
        c1: c1_point.to_bytes().to_vec(),
        c2: xor32(message, &mask).to_vec(),
    }
}

/// Decrypt a ciphertext with the recipient's secret key.
pub fn decrypt(sk: &SigningKey, ct: &Ciphertext) -> Option<[u8; 32]> {
    let c1 = point_from_bytes(&ct.c1)?;
    let shared = c1 * *sk.as_nonzero_scalar().as_ref();
    let mask = kdf(&shared);

    if ct.c2.len() != 32 {
        return None;
    }
    let mut c2_arr = [0u8; 32];
    c2_arr.copy_from_slice(&ct.c2);
    Some(xor32(&c2_arr, &mask))
}

/// Decrypt a ciphertext and re-encrypt for a new recipient.
///
/// The plaintext exists momentarily inside TEE memory. From the outside,
/// the caller provides a ciphertext encrypted to the enclave and receives
/// a ciphertext encrypted to the recipient — functionally equivalent to
/// proxy re-encryption.
///
/// # Arguments
/// * `enclave_sk` - The enclave's session secret key
/// * `recipient_pk` - The authorized recipient's public key
/// * `ct` - Ciphertext encrypted to the enclave
pub fn re_encrypt(
    enclave_sk: &SigningKey,
    recipient_pk: &k256::PublicKey,
    ct: &Ciphertext,
) -> Option<Ciphertext> {
    let plaintext = decrypt(enclave_sk, ct)?;
    Some(encrypt(recipient_pk, &plaintext))
}

fn point_from_bytes(bytes: &[u8]) -> Option<ProjectivePoint> {
    let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
    let affine = k256::AffinePoint::from_encoded_point(&encoded);
    if affine.is_some().into() {
        Some(ProjectivePoint::from(affine.unwrap()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::VerifyingKey;

    fn keypair() -> (SigningKey, k256::PublicKey) {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let pk = k256::PublicKey::from(VerifyingKey::from(&sk));
        (sk, pk)
    }

    #[test]
    fn test_roundtrip() {
        let (sk, pk) = keypair();
        let msg = [42u8; 32];
        let ct = encrypt(&pk, &msg);
        assert_eq!(decrypt(&sk, &ct).unwrap(), msg);
    }

    #[test]
    fn test_wrong_key() {
        let (_, pk_a) = keypair();
        let (sk_b, _) = keypair();
        let msg = [42u8; 32];
        let ct = encrypt(&pk_a, &msg);
        assert_ne!(decrypt(&sk_b, &ct), Some(msg));
    }

    #[test]
    fn test_re_encrypt() {
        let (enc_sk, enc_pk) = keypair();
        let (recv_sk, recv_pk) = keypair();
        let msg = [0xAB; 32];

        let ct = encrypt(&enc_pk, &msg);
        assert_eq!(decrypt(&enc_sk, &ct).unwrap(), msg);
        assert_ne!(decrypt(&recv_sk, &ct), Some(msg));

        let re_ct = re_encrypt(&enc_sk, &recv_pk, &ct).unwrap();
        assert_eq!(decrypt(&recv_sk, &re_ct).unwrap(), msg);
        assert_ne!(decrypt(&enc_sk, &re_ct), Some(msg));
    }

    #[test]
    fn test_multiple_recipients() {
        let (enc_sk, enc_pk) = keypair();
        let (alice_sk, alice_pk) = keypair();
        let (bob_sk, bob_pk) = keypair();
        let msg = [0xCD; 32];

        let ct = encrypt(&enc_pk, &msg);

        let alice_ct = re_encrypt(&enc_sk, &alice_pk, &ct).unwrap();
        let bob_ct = re_encrypt(&enc_sk, &bob_pk, &ct).unwrap();

        assert_eq!(decrypt(&alice_sk, &alice_ct).unwrap(), msg);
        assert_eq!(decrypt(&bob_sk, &bob_ct).unwrap(), msg);
        assert_ne!(decrypt(&alice_sk, &bob_ct), Some(msg));
        assert_ne!(decrypt(&bob_sk, &alice_ct), Some(msg));
    }

    #[test]
    fn test_randomized() {
        let (_, pk) = keypair();
        let msg = [0x11; 32];
        let ct1 = encrypt(&pk, &msg);
        let ct2 = encrypt(&pk, &msg);
        assert_ne!(ct1.c1, ct2.c1); // different ephemeral keys
        assert_ne!(ct1.c2, ct2.c2); // different ciphertexts
    }
}
