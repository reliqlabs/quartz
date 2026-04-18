use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Timestamp, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    /// Duration of the bidding period in seconds
    pub auction_duration: u64,
    /// Minimum bid amount (public, used for validation)
    pub reserve_price: Uint128,
}

#[cw_serde]
pub enum AuctionPhase {
    Idle,
    Bidding,
    Resolving,
    Complete,
}

#[cw_serde]
pub struct AuctionRound {
    pub round_id: u64,
    pub phase: AuctionPhase,
    pub auction_end: Timestamp,
    pub bid_count: u32,
}

/// Public result after the enclave resolves the auction
#[cw_serde]
pub struct AuctionResult {
    pub round_id: u64,
    pub winner: Option<Addr>,
    /// Second-price amount (what the winner pays)
    pub price: Uint128,
    pub bid_count: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const ROUND: Item<AuctionRound> = Item::new("round");
pub const ROUND_COUNTER: Item<u64> = Item::new("round_counter");

/// Encrypted sealed bids: bidder address -> ciphertext
/// The ciphertext contains the bid amount, encrypted to the enclave's session pubkey.
/// The contract cannot read the bid amounts — only the enclave can decrypt them.
pub const SEALED_BIDS: Map<&Addr, HexBinary> = Map::new("sealed_bids");

/// Past auction results (public after resolution)
pub const RESULTS: Map<u64, AuctionResult> = Map::new("results");
