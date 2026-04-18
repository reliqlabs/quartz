use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint128};
use quartz_contract_core::{
    msg::execute::attested::{RawAttested, RawDefaultAttestation, RawNoop},
    prelude::*,
};
use quartz_contract_core_derive::UserData;

/// Attested message wrapper (enclave -> contract)
pub type AttestedMsg<M, RA = RawDefaultAttestation> = RawAttested<RawNoop<M>, RA>;

#[cw_serde]
pub struct InstantiateMsg<RA = RawDefaultAttestation> {
    pub quartz: QuartzInstantiateMsg<RA>,
    /// Duration of the bidding period in seconds
    pub auction_duration: u64,
    /// Minimum bid amount
    pub reserve_price: Uint128,
}

#[cw_serde]
#[allow(clippy::large_enum_variant)]
pub enum ExecuteMsg<RA = RawDefaultAttestation> {
    /// Quartz session management (handshake)
    Quartz(QuartzExecuteMsg<RA>),

    /// Admin: start a new auction round
    StartAuction {},

    /// Sponsor: submit a sealed bid (encrypted to session pubkey)
    /// The ciphertext contains a SealedBid struct.
    SubmitBid { ciphertext: HexBinary },

    /// Enclave: publish the auction result (attested)
    /// Called by the host after the enclave resolves the auction.
    Resolve(AttestedMsg<ResolveMsg, RA>),
}

/// The plaintext bid structure (encrypted client-side, decrypted in enclave)
#[cw_serde]
pub struct SealedBid {
    /// Bid amount in micro-units
    pub amount: Uint128,
}

/// The enclave's attested resolution result
#[derive(UserData)]
#[cw_serde]
pub struct ResolveMsg {
    pub round_id: u64,
    pub winner: Option<String>,
    /// Second-price: what the winner pays
    pub price: Uint128,
    pub bid_count: u32,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(crate::state::Config)]
    Config {},

    #[returns(crate::state::AuctionRound)]
    CurrentRound {},

    #[returns(crate::state::AuctionResult)]
    Result { round_id: u64 },

    /// Returns the enclave's session public key (for encrypting bids)
    #[returns(SessionResponse)]
    Session {},
}

#[cw_serde]
pub struct SessionResponse {
    pub pub_key: Option<HexBinary>,
}
