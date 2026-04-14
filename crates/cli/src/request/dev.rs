use std::path::PathBuf;

use crate::request::Request;

#[derive(Clone, Debug)]
pub struct DevRequest {
    pub watch: bool,
    pub unsafe_trust_latest: bool,
    pub init_msg: serde_json::Value,
    pub label: String,
    pub admin: Option<String>,
    pub no_admin: bool,
    pub contract_manifest: PathBuf,
    pub release: bool,
    pub wasm_bin_path: Option<PathBuf>,
    pub bin_path: Option<PathBuf>,
    pub no_backup: bool,
}

impl From<DevRequest> for Request {
    fn from(request: DevRequest) -> Self {
        Self::Dev(request)
    }
}
