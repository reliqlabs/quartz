#![warn(
    clippy::checked_conversions,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    rust_2018_idioms,
    unused_lifetimes
)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications,
    warnings
)]
#![forbid(unsafe_code)]

// A production wasm contract must never accept unverified attestations.
// `insecure-accept-raw-quote` bypasses TDX verification (dev/test against a
// trusted host only). Cargo features are additive across a workspace, so refuse
// to compile it into a wasm artifact — it cannot ship by accident.
#[cfg(all(target_arch = "wasm32", feature = "insecure-accept-raw-quote"))]
compile_error!("`insecure-accept-raw-quote` must not be enabled in a wasm build");

pub mod error;
pub mod handler;
pub mod msg;
pub mod prelude;
pub mod state;
