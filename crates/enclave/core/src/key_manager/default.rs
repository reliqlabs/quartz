use k256::ecdsa::{Error, SigningKey, VerifyingKey};
use log::{debug, info};

use crate::{
    backup_restore::Export,
    key_manager::KeyManager,
};

/// A default secp256k1 key-manager.
#[derive(Clone)]
pub struct DefaultKeyManager {
    pub sk: SigningKey,
}

impl Default for DefaultKeyManager {
    fn default() -> Self {
        info!("Creating new default key manager with random signing key");
        Self {
            sk: SigningKey::random(&mut rand::thread_rng()),
        }
    }
}

#[async_trait::async_trait]
impl KeyManager for DefaultKeyManager {
    type PubKey = PubKey;

    async fn pub_key(&self) -> Self::PubKey {
        debug!("Retrieving public key from key manager");
        PubKey(self.sk.clone().into())
    }
}

#[derive(Clone, Debug)]
pub struct PubKey(pub VerifyingKey);

impl From<PubKey> for Vec<u8> {
    fn from(value: PubKey) -> Self {
        value.0.to_sec1_bytes().into()
    }
}

impl From<PubKey> for VerifyingKey {
    fn from(value: PubKey) -> Self {
        value.0
    }
}

// `Import for DefaultKeyManager` was removed per Round D Critical 5 Option A
// (2026-05-20 policy decision, executed 2026-05-21). Restoring a key after
// the contract has already published the corresponding pubkey would leave
// the contract bound to a stale pubkey, breaking the protocol-layer
// session-binding invariant proved in the Lean spec. With no Import impl,
// the only path to a new key is constructing a fresh `DefaultKeyManager`
// via `Default::default()`, which means the contract must re-handshake.
//
// If a future operational requirement reintroduces live key rotation,
// the sound add-back path is documented in
// `crates/enclave/core/verus-prototype/key_manager.rs` as
// `DefaultKeyManagerLifecycle::import_with_rotate` — it requires a
// corresponding `session_rotate_pub_key` contract message and a binding-
// to-attestation discipline.

#[async_trait::async_trait]
impl Export for DefaultKeyManager {
    type Error = Error;

    async fn export(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.sk.to_bytes().to_vec())
    }
}
