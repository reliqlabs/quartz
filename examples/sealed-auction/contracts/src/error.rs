use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Quartz(#[from] quartz_contract_core::error::Error),

    #[error("unauthorized")]
    Unauthorized,

    #[error("auction not in bidding phase")]
    NotBidding,

    #[error("auction still in bidding phase")]
    StillBidding,

    #[error("already bid this round")]
    AlreadyBid,

    #[error("no active auction")]
    NoAuction,
}
