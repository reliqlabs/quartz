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
        1_209_600,
        300,
        600,
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

    println!("Ranked choice voting enclave ready");
    println!("  chain_id: {}", args.chain_id);

    tokio::signal::ctrl_c().await?;
    Ok(())
}
