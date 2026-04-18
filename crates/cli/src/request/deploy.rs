use std::path::PathBuf;

use crate::request::Request;

#[derive(Clone, Debug)]
pub struct DeployRequest {
    pub contract_manifest: PathBuf,
    pub init_msg: serde_json::Value,
    pub label: String,
    pub admin: Option<String>,
    pub no_admin: bool,
    pub unsafe_trust_latest: bool,
    pub wasm_bin_path: Option<PathBuf>,
    pub bin_path: Option<PathBuf>,
    /// Use an existing contract address (skip deployment)
    pub contract_address: Option<String>,
}

impl From<DeployRequest> for Request {
    fn from(request: DeployRequest) -> Self {
        Self::Deploy(request)
    }
}
