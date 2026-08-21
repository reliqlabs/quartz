//! `quartz deploy` — Build, deploy, and handshake in one command.
//!
//! Runs the full lifecycle:
//! 1. Build contract (wasm)
//! 2. Build enclave
//! 3. Deploy contract to chain
//! 4. Run handshake (session establishment)
//! 5. Print summary (contract address, session pubkey, env vars)

use async_trait::async_trait;
use color_eyre::{
    eyre::{eyre, Context},
    owo_colors::OwoColorize,
    Report, Result,
};
use tracing::info;

use crate::{
    config::Config,
    handler::{utils::helpers::wasmaddr_to_id, Handler},
    request::{
        contract_build::ContractBuildRequest, contract_deploy::ContractDeployRequest,
        deploy::DeployRequest, enclave_build::EnclaveBuildRequest, handshake::HandshakeRequest,
    },
    response::{deploy::DeployResponse, Response},
};

#[async_trait]
impl Handler for DeployRequest {
    type Response = Response;

    async fn handle<C: AsRef<Config> + Send>(self, config: C) -> Result<Self::Response, Report> {
        let config = config.as_ref();

        info!("{}", "\nQuartz Deploy".blue().bold());
        info!(
            "{}",
            "Building, deploying, and establishing session...\n".blue()
        );

        // Step 1: Build contract
        if self.wasm_bin_path.is_none() {
            info!("{}", "[1/4] Building contract...".green().bold());
            let contract_build = ContractBuildRequest {
                contract_manifest: self.contract_manifest.clone(),
            };
            contract_build
                .handle(config)
                .await
                .wrap_err("Contract build failed")?;
        } else {
            info!(
                "{}",
                "[1/4] Skipping contract build (wasm path provided)".green()
            );
        }

        // Step 2: Build enclave
        if self.bin_path.is_none() {
            info!("{}", "[2/4] Building enclave...".green().bold());
            let enclave_build = EnclaveBuildRequest {};
            enclave_build
                .handle(config)
                .await
                .wrap_err("Enclave build failed")?;
        } else {
            info!(
                "{}",
                "[2/4] Skipping enclave build (bin path provided)".green()
            );
        }

        // Step 3: Deploy contract
        let contract_addr = if let Some(ref existing) = self.contract_address {
            info!(
                "{}",
                format!("[3/4] Using existing contract: {existing}").green()
            );
            existing.clone()
        } else {
            info!("{}", "[3/4] Deploying contract...".green().bold());
            let contract_deploy = ContractDeployRequest {
                init_msg: self.init_msg.clone(),
                label: self.label.clone(),
                admin: self.admin.clone(),
                no_admin: self.no_admin,
                contract_manifest: self.contract_manifest.clone(),
                wasm_bin_path: self.wasm_bin_path.clone(),
            };
            let cd_res = contract_deploy
                .handle(config)
                .await
                .wrap_err("Contract deployment failed")?;

            if let Response::ContractDeploy(res) = cd_res {
                res.contract_addr
            } else {
                return Err(eyre!("Unexpected response from contract deploy"));
            }
        };

        // Step 4: Handshake
        info!("{}", "[4/4] Running handshake...".green().bold());
        let handshake = HandshakeRequest {
            contract: wasmaddr_to_id(&contract_addr)?,
            unsafe_trust_latest: self.unsafe_trust_latest,
        };
        let hs_res = handshake
            .handle(config)
            .await
            .wrap_err("Handshake failed")?;

        let pub_key = if let Response::Handshake(res) = hs_res {
            res.pub_key
        } else {
            "unknown".to_string()
        };

        // Summary
        info!("{}", "\n=== Deploy Complete ===".green().bold());
        info!("Contract:    {}", contract_addr);
        info!("Session key: {}", pub_key);
        info!("Chain ID:    {}", config.chain_id);
        info!("");
        info!("Frontend env vars:");
        info!("  NEXT_PUBLIC_CONTRACT_ADDRESS={}", contract_addr);
        info!("  NEXT_PUBLIC_CHAIN_ID={}", config.chain_id);
        info!("  NEXT_PUBLIC_RPC_URL={}", config.node_url);

        Ok(DeployResponse {
            contract_addr,
            pub_key,
        }
        .into())
    }
}
