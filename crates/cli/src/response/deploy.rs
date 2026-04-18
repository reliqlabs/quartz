use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct DeployResponse {
    pub contract_addr: String,
    pub pub_key: String,
}

impl From<DeployResponse> for super::Response {
    fn from(response: DeployResponse) -> Self {
        Self::Deploy(response)
    }
}
