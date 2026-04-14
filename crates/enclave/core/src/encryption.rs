//! ECIES encryption/decryption helpers for Quartz enclaves.
//!
//! Uses secp256k1 ECIES (Elliptic Curve Integrated Encryption Scheme)
//! for encrypting messages between users and the enclave.
//!
//! - Users encrypt requests to the enclave's session public key
//! - Enclave decrypts with its private key (held in KeyManager)
//! - Enclave encrypts responses to user-provided ephemeral public keys

use k256::ecdsa::{SigningKey, VerifyingKey};

/// Encrypt plaintext to the given secp256k1 public key using ECIES.
pub fn encrypt(pubkey: &VerifyingKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    ecies::encrypt(&pubkey.to_sec1_bytes(), plaintext)
        .map_err(|e| format!("ECIES encrypt failed: {e}"))
}

/// Decrypt ciphertext using the given secp256k1 private key.
pub fn decrypt(privkey: &SigningKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    ecies::decrypt(&privkey.to_bytes(), ciphertext)
        .map_err(|e| format!("ECIES decrypt failed: {e}"))
}

/// Encrypt a serializable value to the given public key.
pub fn encrypt_json<T: serde::Serialize>(
    pubkey: &VerifyingKey,
    value: &T,
) -> Result<Vec<u8>, String> {
    let serialized =
        serde_json::to_vec(value).map_err(|e| format!("JSON serialize failed: {e}"))?;
    encrypt(pubkey, &serialized)
}

/// Decrypt ciphertext and deserialize from JSON.
pub fn decrypt_json<T: serde::de::DeserializeOwned>(
    privkey: &SigningKey,
    ciphertext: &[u8],
) -> Result<T, String> {
    let plaintext = decrypt(privkey, ciphertext)?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("JSON deserialize failed: {e}"))
}
