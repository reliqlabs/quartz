use log::debug;
use quartz_contract_core::{
    msg::{
        execute::attested::{
            Attestation, DstackAttestation, HasUserData, MockAttestation, RawDstackAttestation,
            RawMockAttestation,
        },
        HasDomainType,
    },
    state::MrEnclave,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backup_restore::{Export, Import};

#[cfg(not(feature = "mock-sgx"))]
pub type DefaultAttestor = DstackAttestor;

#[cfg(feature = "mock-sgx")]
pub type DefaultAttestor = MockAttestor;

/// The trait defines the interface for generating attestations from within an enclave.
pub trait Attestor: Send + Sync + 'static {
    type Error: ToString;
    type Attestation: Attestation;
    type RawAttestation: HasDomainType<DomainType = Self::Attestation> + Serialize;

    fn quote(&self, user_data: impl HasUserData) -> Result<Vec<u8>, Self::Error>;

    fn mr_enclave(&self) -> Result<MrEnclave, Self::Error>;

    fn attestation(&self, user_data: impl HasUserData) -> Result<Self::Attestation, Self::Error>;
}

// ============================================================
// DstackAttestor — TDX attestation via dstack guest agent
// ============================================================

/// Response from dstack GetQuote endpoint
#[derive(Debug, Clone, Deserialize)]
struct DstackQuoteResponse {
    quote: String,
    #[serde(rename = "eventLog")]
    event_log: Option<String>,
}

/// Response from dstack Info endpoint
#[derive(Debug, Clone, Deserialize)]
struct DstackInfoResponse {
    #[serde(rename = "app-id", default)]
    _app_id: String,
    #[serde(rename = "compose-hash", default)]
    compose_hash: String,
}

/// Attestor that generates TDX quotes via dstack's guest agent socket API.
///
/// In production, communicates via Unix socket at DSTACK_SOCKET.
/// In development, communicates via HTTP to DSTACK_ENDPOINT (simulator).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DstackAttestor {
    /// Cached compose-hash (TDX equivalent of mr_enclave)
    compose_hash: Option<[u8; 32]>,
}

impl DstackAttestor {
    pub fn new() -> Self {
        Self {
            compose_hash: None,
        }
    }

    fn client() -> reqwest::blocking::Client {
        if let Ok(socket_path) = std::env::var("DSTACK_SOCKET") {
            debug!("Using dstack Unix socket: {}", socket_path);
            return reqwest::blocking::Client::builder()
                .unix_socket(std::path::Path::new(&socket_path))
                .build()
                .expect("Failed to build Unix socket client");
        }
        debug!("Using dstack HTTP endpoint");
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

    fn get_quote_raw(&self, report_data: &[u8]) -> Result<DstackQuoteResponse, String> {
        let hex_data = if report_data.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(report_data);
            hex::encode(hasher.finalize())
        } else {
            let mut padded = vec![0u8; 64];
            let len = report_data.len().min(64);
            padded[..len].copy_from_slice(&report_data[..len]);
            hex::encode(padded)
        };

        #[derive(Serialize)]
        struct GetQuoteRequest {
            report_data: String,
        }

        let request_body = GetQuoteRequest {
            report_data: hex_data,
        };

        let client = Self::client();
        let response = if Self::is_unix_socket() {
            let url = format!("{}/GetQuote", Self::base_url());
            client
                .post(&url)
                .json(&request_body)
                .send()
                .map_err(|e| format!("dstack GetQuote request failed: {e}"))?
        } else {
            let json_param =
                serde_json::to_string(&request_body).map_err(|e| format!("serialize: {e}"))?;
            let url = format!(
                "{}/prpc/Tappd.TdxQuote?json={}",
                Self::base_url(),
                urlencoding::encode(&json_param)
            );
            client
                .get(&url)
                .send()
                .map_err(|e| format!("dstack GetQuote request failed: {e}"))?
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(format!("dstack GetQuote failed ({status}): {body}"));
        }

        response
            .json::<DstackQuoteResponse>()
            .map_err(|e| format!("Failed to parse GetQuote response: {e}"))
    }

    fn fetch_compose_hash(&self) -> Result<[u8; 32], String> {
        if let Some(hash) = self.compose_hash {
            return Ok(hash);
        }

        let client = Self::client();
        let url = format!("{}/Info", Self::base_url());
        let response = client
            .get(&url)
            .send()
            .map_err(|e| format!("dstack Info request failed: {e}"))?;

        let info: DstackInfoResponse = response
            .json()
            .map_err(|e| format!("Failed to parse Info response: {e}"))?;

        let hash_bytes =
            hex::decode(&info.compose_hash).map_err(|e| format!("Invalid compose_hash hex: {e}"))?;

        if hash_bytes.len() != 32 {
            return Err(format!(
                "compose_hash wrong length: expected 32, got {}",
                hash_bytes.len()
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash_bytes);
        Ok(arr)
    }
}

impl Default for DstackAttestor {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for DstackAttestor {
    fn eq(&self, other: &Self) -> bool {
        self.compose_hash == other.compose_hash
    }
}

impl Attestor for DstackAttestor {
    type Error = String;
    type Attestation = DstackAttestation;
    type RawAttestation = RawDstackAttestation;

    fn quote(&self, user_data: impl HasUserData) -> Result<Vec<u8>, Self::Error> {
        debug!("Generating dstack TDX quote");
        let ud = user_data.user_data();
        let response = self.get_quote_raw(&ud)?;
        hex::decode(&response.quote).map_err(|e| format!("Invalid quote hex: {e}"))
    }

    fn mr_enclave(&self) -> Result<MrEnclave, Self::Error> {
        debug!("Retrieving compose-hash (mr_enclave equivalent)");
        self.fetch_compose_hash()
    }

    fn attestation(&self, user_data: impl HasUserData) -> Result<Self::Attestation, Self::Error> {
        debug!("Generating dstack TDX attestation");
        let ud = user_data.user_data();
        let response = self.get_quote_raw(&ud)?;
        let quote_bytes =
            hex::decode(&response.quote).map_err(|e| format!("Invalid quote hex: {e}"))?;
        let compose_hash = self.fetch_compose_hash()?;

        Ok(DstackAttestation::new(
            quote_bytes,
            response.event_log,
            ud,
            compose_hash,
        ))
    }
}

#[async_trait::async_trait]
impl Export for DstackAttestor {
    type Error = String;

    async fn export(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self).map_err(|e| format!("serialize DstackAttestor: {e}"))
    }
}

#[async_trait::async_trait]
impl Import for DstackAttestor {
    type Error = String;

    async fn import(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
        *self =
            serde_json::from_slice(&data).map_err(|e| format!("deserialize DstackAttestor: {e}"))?;
        Ok(())
    }
}

// ============================================================
// MockAttestor — for testing without TEE hardware
// ============================================================

#[derive(Clone, PartialEq, Debug, Default)]
pub struct MockAttestor;

impl Attestor for MockAttestor {
    type Error = String;
    type Attestation = MockAttestation;
    type RawAttestation = RawMockAttestation;

    fn quote(&self, user_data: impl HasUserData) -> Result<Vec<u8>, Self::Error> {
        debug!("Generating mock quote");
        let user_data = user_data.user_data();
        Ok(user_data.to_vec())
    }

    fn mr_enclave(&self) -> Result<MrEnclave, Self::Error> {
        debug!("Retrieving mock MRENCLAVE");
        Ok(Default::default())
    }

    fn attestation(&self, user_data: impl HasUserData) -> Result<Self::Attestation, Self::Error> {
        debug!("Generating mock attestation");
        Ok(MockAttestation(user_data.user_data()))
    }
}

#[async_trait::async_trait]
impl Import for MockAttestor {
    type Error = ();

    async fn import(&mut self, _data: Vec<u8>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl Export for MockAttestor {
    type Error = ();

    async fn export(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }
}
