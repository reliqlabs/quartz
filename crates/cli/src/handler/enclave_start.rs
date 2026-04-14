use std::path::{Path, PathBuf};

use async_trait::async_trait;
use cargo_metadata::MetadataCommand;
use color_eyre::{
    eyre::{eyre, Context},
    owo_colors::OwoColorize,
    Report, Result,
};
use tokio::process::{Child, Command};
use tracing::{debug, info};

use crate::{
    config::Config,
    handler::{utils::helpers::write_cache_hash_height, Handler},
    request::enclave_start::EnclaveStartRequest,
    response::{enclave_start::EnclaveStartResponse, Response},
};

#[async_trait]
impl Handler for EnclaveStartRequest {
    type Response = Response;

    async fn handle<C: AsRef<Config> + Send>(self, config: C) -> Result<Self::Response, Report> {
        let config = config.as_ref().clone();
        info!("{}", "\nStarting Enclave".blue().bold());

        // Get trusted height and hash
        let (trusted_height, trusted_hash) = self
            .get_hash_height(&config)
            .wrap_err("Error getting trusted hash and height")?;
        write_cache_hash_height(trusted_height, trusted_hash, &config).await?;

        let mut enclave_args: Vec<String> = vec![
            "--chain-id".to_string(),
            config.chain_id.to_string(),
            "--trusted-height".to_string(),
            trusted_height.to_string(),
            "--trusted-hash".to_string(),
            trusted_hash.to_string(),
            "--node-url".to_string(),
            config.node_url.to_string(),
            "--ws-url".to_string(),
            config.ws_url.to_string(),
            "--grpc-url".to_string(),
            config.grpc_url.to_string(),
            "--tx-sender".to_string(),
            config.tx_sender,
        ];

        if self.no_backup {
            enclave_args.push("--no-backup".to_string());
        }

        // In mock mode or dstack mode, the enclave runs as a normal process.
        // In dstack production, the entire VM is the TEE — no Gramine needed.
        // The DstackAttestor communicates with the guest agent via Unix socket.
        let enclave_child = create_enclave_child(
            config.app_dir.as_path(),
            config.release,
            enclave_args,
            self.bin_path.as_ref(),
        )
        .await?;
        handle_process(enclave_child).await?;

        Ok(EnclaveStartResponse.into())
    }
}

async fn handle_process(mut child: Child) -> Result<()> {
    let status = child.wait().await?;

    if !status.success() {
        return Err(eyre!("Enclave process failed. {:?}", status));
    }
    Ok(())
}

async fn create_enclave_child(
    app_dir: &Path,
    release: bool,
    enclave_args: Vec<String>,
    bin_path: Option<&PathBuf>,
) -> Result<Child> {
    let executable = if let Some(bin_path) = bin_path {
        bin_path.clone()
    } else {
        let enclave_dir = app_dir.join("enclave");
        let target_dir = app_dir.join("target");

        let package_name = MetadataCommand::new()
            .manifest_path(enclave_dir.join("Cargo.toml"))
            .exec()?
            .root_package()
            .ok_or("No root package found in the metadata")
            .map_err(|e| eyre!(e))?
            .name
            .clone();

        if release {
            target_dir.join("release").join(package_name)
        } else {
            target_dir.join("debug").join(package_name)
        }
    };

    let mut command = Command::new(executable.display().to_string());
    command.args(enclave_args);

    debug!("Enclave Start Command: {:?}", command);
    info!("{}", "Spawning enclave process ...".green().bold());
    let child = command.kill_on_drop(true).spawn()?;

    Ok(child)
}
