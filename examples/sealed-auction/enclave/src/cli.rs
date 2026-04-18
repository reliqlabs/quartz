use clap::Parser;
use cosmrs::AccountId;
use tendermint::block::Height;
use tendermint::Hash;

#[derive(Debug, Parser)]
#[command(name = "sealed-auction-enclave")]
pub struct Cli {
    /// Chain ID
    #[clap(long)]
    pub chain_id: String,

    /// RPC URL
    #[clap(long)]
    pub node_url: String,

    /// WebSocket URL
    #[clap(long)]
    pub ws_url: String,

    /// gRPC URL
    #[clap(long)]
    pub grpc_url: String,

    /// Transaction sender
    #[clap(long)]
    pub tx_sender: String,

    /// Trusted block height
    #[clap(long)]
    pub trusted_height: Height,

    /// Trusted block hash
    #[clap(long)]
    pub trusted_hash: Hash,

    /// zkdcap verification key name (optional)
    #[clap(long)]
    pub zkdcap_vkey: Option<AccountId>,

    /// Disable backup/restore
    #[clap(long, default_value_t = false)]
    pub no_backup: bool,
}
