//! Integration tests for Quartz with mocked Xion ZK module.
//!
//! Uses cw_multi_test with a custom Stargate handler that intercepts
//! `/xion.zk.v1.Query/ProofVerify` gRPC queries and returns mock
//! verification results.

pub mod fixtures;
pub mod zk_mock;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod model_based;

#[cfg(test)]
mod testnet;
