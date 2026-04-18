use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use quartz_contract_core::{
    msg::execute::attested::{RawAttested, RawDefaultAttestation, RawNoop},
    prelude::*,
};
use quartz_contract_core_derive::UserData;

use crate::state::TallyRound;

pub type AttestedMsg<M, RA = RawDefaultAttestation> = RawAttested<RawNoop<M>, RA>;

#[cw_serde]
pub struct InstantiateMsg<RA = RawDefaultAttestation> {
    pub quartz: QuartzInstantiateMsg<RA>,
    pub voting_duration: u64,
}

#[cw_serde]
#[allow(clippy::large_enum_variant)]
pub enum ExecuteMsg<RA = RawDefaultAttestation> {
    /// Quartz session management
    Quartz(QuartzExecuteMsg<RA>),

    /// Admin: create a new election with candidates
    CreateElection {
        title: String,
        candidates: Vec<String>,
    },

    /// Admin: open voting (moves from Setup to Voting)
    OpenVoting {},

    /// Voter: submit an encrypted ranked ballot
    CastBallot { ciphertext: HexBinary },

    /// Enclave: publish the election result (attested)
    Tally(AttestedMsg<TallyMsg, RA>),
}

/// The plaintext ballot (encrypted client-side, decrypted in enclave)
#[cw_serde]
pub struct Ballot {
    /// Ranked candidates, first choice first.
    /// Must only contain registered candidates.
    pub ranked_choices: Vec<String>,
}

/// The enclave's attested tally result
#[derive(UserData)]
#[cw_serde]
pub struct TallyMsg {
    pub election_id: u64,
    pub winner: String,
    pub rounds: Vec<TallyRound>,
    pub total_ballots: u32,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(crate::state::Config)]
    Config {},

    #[returns(crate::state::Election)]
    Election {},

    #[returns(crate::state::ElectionResult)]
    Result { election_id: u64 },

    #[returns(SessionResponse)]
    Session {},
}

#[cw_serde]
pub struct SessionResponse {
    pub pub_key: Option<HexBinary>,
}
