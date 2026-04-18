use clap::Parser;
use cosmrs::AccountId;
use tendermint::block::Height;
use tendermint::Hash;

#[derive(Debug, Parser)]
#[command(name = "ranked-choice-enclave")]
pub struct Cli {
    #[clap(long)]
    pub chain_id: String,
    #[clap(long)]
    pub node_url: String,
    #[clap(long)]
    pub ws_url: String,
    #[clap(long)]
    pub grpc_url: String,
    #[clap(long)]
    pub tx_sender: String,
    #[clap(long)]
    pub trusted_height: Height,
    #[clap(long)]
    pub trusted_hash: Hash,
    #[clap(long)]
    pub zkdcap_vkey: Option<AccountId>,
    #[clap(long, default_value_t = false)]
    pub no_backup: bool,
}
