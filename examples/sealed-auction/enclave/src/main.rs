//! Sealed Auction Enclave
//!
//! Runs inside a dstack CVM. Handles:
//! - Quartz handshake (session establishment)
//! - Auction resolution (decrypt sealed bids, determine winner + second price)

pub mod cli;
pub mod request;

use clap::Parser;
use cli::Cli;
use quartz_common::{
    contract::state::{Config, LightClientOpts},
    enclave::{
        attestor::{self, Attestor},
        DefaultSharedEnclave,
    },
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .write_style(env_logger::WriteStyle::Always)
        .init();

    let args = Cli::parse();

    let light_client_opts = LightClientOpts::new(
        args.chain_id.clone(),
        args.trusted_height.into(),
        Vec::from(args.trusted_hash)
            .try_into()
            .expect("invalid trusted hash"),
        (2, 3),
        1_209_600, // 14 days trusting period
        300,       // 5 min max clock drift
        600,       // 10 min max block lag
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    #[cfg(not(feature = "mock"))]
    let attestor = attestor::DstackAttestor::new().expect("failed to create DstackAttestor");

    #[cfg(feature = "mock")]
    let attestor = attestor::MockAttestor::default();

    let config = Config::new(
        attestor.mr_enclave()?,
        light_client_opts,
        args.zkdcap_vkey.map(|c| c.to_string()),
    );

    let (_enclave, _notifier_rx) = DefaultSharedEnclave::shared(attestor, config, ());

    println!("Sealed auction enclave ready");
    println!("  chain_id: {}", args.chain_id);

    // In a full implementation, a host process would:
    // 1. Serve the Quartz gRPC handshake
    // 2. Watch for chain events (auction deadline reached)
    // 3. Read encrypted bids from chain via light client proofs
    // 4. Call request::resolve_auction() with the enclave's session key
    // 5. Submit the attested result back to the contract
    //
    // The resolution logic is in request.rs with unit tests.

    tokio::signal::ctrl_c().await?;
    Ok(())
}
