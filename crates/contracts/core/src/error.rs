use cosmwasm_std::StdError;
use k256::ecdsa::Error as K256Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("user data mismatch")]
    UserDataMismatch,
    #[error("mr_enclave mismatch")]
    MrEnclaveMismatch,
    #[error("Signature verification error: {0}")]
    SignatureVerification(String),
    #[error("Not Secp256K1")]
    K256(K256Error),
    #[error("invalid session nonce or attempt to reset pub_key")]
    BadSessionTransition,
    #[error("contract address mismatch")]
    ContractAddrMismatch,
}

impl From<K256Error> for Error {
    fn from(e: K256Error) -> Self {
        Self::K256(e)
    }
}
