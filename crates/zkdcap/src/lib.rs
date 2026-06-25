//! Canonical Noir/UltraHonk TDX attestation verification primitives.
//!
//! This crate owns everything application-INDEPENDENT about consuming a
//! dcap-noir UltraHonk proof on-chain:
//!
//! - the packed 672-byte / 21-field `public_inputs` layout and its decoders
//!   ([`layout`]): `extract_report_data`, `extract_measurements`,
//!   `extract_timestamp`, `extract_tcb_eval_num`, `extract_valid_from`,
//!   `extract_valid_until`, `measurement_digest`, `build_public_inputs`,
//!   `split_attestation`/`frame_attestation`, `unix_to_packed_datetime`;
//! - the [`ProofBackend`] seam and the generic [`verify_quote`] primitive that
//!   decodes, range-checks recency/validity + the tcb-eval floor, and verifies
//!   the proof;
//! - the CosmWasm [`xion`] backend (feature `xion-backend`) that calls
//!   `/xion.zk.v1.Query/ProofVerifyUltraHonk`.
//!
//! What is NOT here, because it is inherently per-application: what the 64-byte
//! `report_data` must equal (each consumer recomputes its own domain binding),
//! and which measurements are expected (the consumer's image registry). Callers
//! compare [`DecodedQuote::report_data`] / [`DecodedQuote::measurements`]
//! against their own recomputed values.
//!
//! Shared by `quartz-contract-core`, `dossier`, and `verified-rcv` so a circuit
//! layout change or a new check is a one-place edit.

#![forbid(unsafe_code)]

/// 32-byte hash (SHA-256 digest / measurement register low half, etc.).
pub type Hash32 = [u8; 32];

pub mod eventlog;
mod layout;
mod verifier;

pub use layout::*;
pub use verifier::*;

#[cfg(feature = "xion-backend")]
pub mod xion;
#[cfg(feature = "xion-backend")]
pub use xion::XionUltraHonkBackend;

#[cfg(test)]
mod tests;
