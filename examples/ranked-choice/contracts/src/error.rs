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

    #[error("election not in voting phase")]
    NotVoting,

    #[error("election still in voting phase")]
    StillVoting,

    #[error("already voted")]
    AlreadyVoted,

    #[error("no active election")]
    NoElection,

    #[error("candidate already registered")]
    DuplicateCandidate,

    #[error("need at least 2 candidates")]
    NotEnoughCandidates,
}
