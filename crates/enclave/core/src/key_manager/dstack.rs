//! Key manager backed by dstack KMS.
//!
//! Derives deterministic secp256k1 keys from dstack's TEE-bound KMS.
//! Same app + same key path = same key, across restarts and migrations.
//! No sealed backup file needed.

use k256::ecdsa::{SigningKey, VerifyingKey};
use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::{
    backup_restore::Export,
    key_manager::{default::PubKey, KeyManager},
};

/// A key manager that derives keys from dstack's KMS.
///
/// On construction, calls the dstack `DeriveKey` endpoint with a
/// configurable path (e.g., "quartz/session"). The KMS derives
/// a deterministic key from the app's identity — same app deployed
/// on a different host gets the same key.
///
/// Falls back to random key generation if dstack is not available
/// (development without TEE hardware).
#[derive(Clone)]
pub struct DstackKeyManager {
    pub sk: SigningKey,
    key_path: String,
}

#[derive(Deserialize)]
struct DeriveKeyResponse {
    key: String,
}

impl DstackKeyManager {
    /// Create a new key manager by deriving a key from dstack KMS.
    ///
    /// `key_path` identifies which key to derive (e.g., "quartz/session").
    /// Same path always produces the same key for the same app.
    pub fn new(key_path: &str) -> Result<Self, String> {
        info!("Deriving key from dstack KMS (path: {})", key_path);

        match Self::derive_from_dstack(key_path) {
            Ok(sk) => {
                let vk = VerifyingKey::from(&sk);
                info!(
                    "dstack KMS key derived (pubkey: {})",
                    hex::encode(vk.to_sec1_bytes())
                );
                Ok(Self {
                    sk,
                    key_path: key_path.to_string(),
                })
            }
            Err(e) => {
                debug!(
                    "dstack KMS not available ({}), falling back to random key",
                    e
                );
                Ok(Self {
                    sk: SigningKey::random(&mut rand::thread_rng()),
                    key_path: key_path.to_string(),
                })
            }
        }
    }

    fn derive_from_dstack(key_path: &str) -> Result<SigningKey, String> {
        let client = Self::client();
        let base_url = Self::base_url();

        #[derive(Serialize)]
        struct DeriveKeyRequest<'a> {
            path: &'a str,
            #[serde(rename = "type")]
            key_type: &'a str,
        }

        let request_body = DeriveKeyRequest {
            path: key_path,
            key_type: "secp256k1",
        };

        let response = if Self::is_unix_socket() {
            let url = format!("{}/DeriveKey", base_url);
            client
                .post(&url)
                .json(&request_body)
                .send()
                .map_err(|e| format!("DeriveKey request failed: {e}"))?
        } else {
            let json_param =
                serde_json::to_string(&request_body).map_err(|e| format!("serialize: {e}"))?;
            let url = format!(
                "{}/prpc/Tappd.DeriveKey?json={}",
                base_url,
                urlencoding::encode(&json_param)
            );
            client
                .get(&url)
                .send()
                .map_err(|e| format!("DeriveKey request failed: {e}"))?
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(format!("DeriveKey failed ({status}): {body}"));
        }

        let resp: DeriveKeyResponse = response
            .json()
            .map_err(|e| format!("Failed to parse DeriveKey response: {e}"))?;

        let key_bytes = hex::decode(&resp.key).map_err(|e| format!("Invalid key hex: {e}"))?;

        // dstack returns a raw 32-byte private key
        SigningKey::from_slice(&key_bytes)
            .map_err(|e| format!("Invalid secp256k1 key from KMS: {e}"))
    }

    fn client() -> reqwest::blocking::Client {
        if let Ok(socket_path) = std::env::var("DSTACK_SOCKET") {
            return reqwest::blocking::Client::builder()
                .unix_socket(std::path::Path::new(&socket_path))
                .build()
                .expect("Failed to build Unix socket client");
        }
        reqwest::blocking::Client::new()
    }

    fn base_url() -> String {
        if std::env::var("DSTACK_SOCKET").is_ok() {
            return "http://dstack".to_string();
        }
        std::env::var("DSTACK_ENDPOINT").unwrap_or_else(|_| "http://localhost:8090".to_string())
    }

    fn is_unix_socket() -> bool {
        std::env::var("DSTACK_SOCKET").is_ok()
    }
}

#[async_trait::async_trait]
impl KeyManager for DstackKeyManager {
    type PubKey = PubKey;

    async fn pub_key(&self) -> Self::PubKey {
        debug!("Retrieving public key from dstack key manager");
        PubKey(self.sk.clone().into())
    }
}

#[async_trait::async_trait]
impl Export for DstackKeyManager {
    type Error = String;

    async fn export(&self) -> Result<Vec<u8>, Self::Error> {
        // With KMS-derived keys, export is just the path — the key
        // itself can be re-derived on import.
        serde_json::to_vec(&self.key_path).map_err(|e| format!("serialize key path: {e}"))
    }
}

// `Import for DstackKeyManager` was removed per Round D Critical 5 Option A
// (2026-05-20 policy decision, executed 2026-05-21). Even though dstack's
// KMS re-derives the same key from the same path (so import would be
// idempotent in the common case), the import path opened a window where
// the KMS-fallback `Err` branch in `derive_from_dstack` would silently
// replace the in-use signing key with a freshly-generated random key
// (see `Self::new`'s `Err(e)` arm). That fallback combined with the
// contract's already-published pubkey is the staleness vector Round D
// Critical 5 flagged.
//
// With no Import impl, the only path to a `DstackKeyManager` is
// `Self::new(key_path)`, which is invoked once at enclave startup. If
// the KMS is reachable on startup, the key is deterministic; if not,
// the fallback random key still means the contract must handshake
// against the actual published pubkey, with no opportunity for the
// pubkey-vs-sk binding to drift after handshake completion.
//
// The Verus prototype `DstackKeyManagerLifecycle::import_with_rotate`
// documents the sound add-back path for any future cycle that
// reintroduces live key rotation.
