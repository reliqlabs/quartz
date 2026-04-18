use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Timestamp};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub voting_duration: u64,
}

#[cw_serde]
pub enum ElectionPhase {
    Setup,
    Voting,
    Tallying,
    Complete,
}

#[cw_serde]
pub struct Election {
    pub election_id: u64,
    pub phase: ElectionPhase,
    pub title: String,
    pub candidates: Vec<String>,
    pub voting_end: Timestamp,
    pub ballot_count: u32,
}

/// A single round in the instant-runoff tally
#[cw_serde]
pub struct TallyRound {
    /// Round number (1-indexed)
    pub round: u32,
    /// Vote counts per candidate in this round
    pub counts: Vec<(String, u32)>,
    /// Candidate eliminated this round (None if final round)
    pub eliminated: Option<String>,
}

/// Public result after the enclave tallies the election
#[cw_serde]
pub struct ElectionResult {
    pub election_id: u64,
    pub winner: String,
    pub rounds: Vec<TallyRound>,
    pub total_ballots: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const ELECTION: Item<Election> = Item::new("election");
pub const ELECTION_COUNTER: Item<u64> = Item::new("election_counter");

/// Encrypted ballots: voter address -> ciphertext
/// Each ciphertext contains a Ballot (ranked list of candidates).
pub const BALLOTS: Map<&Addr, HexBinary> = Map::new("ballots");

/// Past election results
pub const RESULTS: Map<u64, ElectionResult> = Map::new("results");
