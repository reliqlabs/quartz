use cosmwasm_std::{
    entry_point, to_json_binary, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo,
    Order, Response, StdResult,
};
use quartz_contract_core::handler::RawHandler;
use quartz_contract_core::state::SESSION;

use crate::error::ContractError;
use crate::msg::*;
use crate::state::*;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    msg.quartz.handle_raw(deps.branch(), &env, &info)?;

    CONFIG.save(
        deps.storage,
        &Config {
            admin: info.sender,
            voting_duration: msg.voting_duration,
        },
    )?;
    ELECTION_COUNTER.save(deps.storage, &0u64)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Quartz(msg) => msg.handle_raw(deps, &env, &info).map_err(Into::into),
        ExecuteMsg::CreateElection { title, candidates } => {
            exec_create_election(deps, info, title, candidates)
        }
        ExecuteMsg::OpenVoting {} => exec_open_voting(deps, env, info),
        ExecuteMsg::CastBallot { ciphertext } => exec_cast_ballot(deps, env, info, ciphertext),
        ExecuteMsg::Tally(attested_msg) => {
            attested_msg
                .clone()
                .handle_raw(deps.branch(), &env, &info)?;
            exec_tally(deps, attested_msg.msg.0)
        }
    }
}

fn exec_create_election(
    deps: DepsMut,
    info: MessageInfo,
    title: String,
    candidates: Vec<String>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }
    if candidates.len() < 2 {
        return Err(ContractError::NotEnoughCandidates);
    }

    // Check for duplicate candidates
    let mut seen = std::collections::HashSet::new();
    for c in &candidates {
        if !seen.insert(c.as_str()) {
            return Err(ContractError::DuplicateCandidate);
        }
    }

    // Clear previous ballots
    let keys: Vec<Addr> = BALLOTS
        .keys(deps.storage, None, None, Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;
    for key in keys {
        BALLOTS.remove(deps.storage, &key);
    }

    let counter = ELECTION_COUNTER.load(deps.storage)? + 1;
    ELECTION_COUNTER.save(deps.storage, &counter)?;

    ELECTION.save(
        deps.storage,
        &Election {
            election_id: counter,
            phase: ElectionPhase::Setup,
            title,
            candidates,
            voting_end: cosmwasm_std::Timestamp::from_seconds(0),
            ballot_count: 0,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "create_election")
        .add_attribute("election_id", counter.to_string()))
}

fn exec_open_voting(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    let mut election = ELECTION.load(deps.storage)?;
    if election.phase != ElectionPhase::Setup {
        return Err(ContractError::StillVoting);
    }

    election.phase = ElectionPhase::Voting;
    election.voting_end = env.block.time.plus_seconds(config.voting_duration);
    ELECTION.save(deps.storage, &election)?;

    Ok(Response::new().add_attribute("action", "open_voting"))
}

fn exec_cast_ballot(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    ciphertext: HexBinary,
) -> Result<Response, ContractError> {
    let election = ELECTION.load(deps.storage)?;

    if election.phase != ElectionPhase::Voting {
        return Err(ContractError::NotVoting);
    }
    if env.block.time >= election.voting_end {
        return Err(ContractError::NotVoting);
    }
    if BALLOTS.has(deps.storage, &info.sender) {
        return Err(ContractError::AlreadyVoted);
    }

    BALLOTS.save(deps.storage, &info.sender, &ciphertext)?;

    let mut election = ELECTION.load(deps.storage)?;
    election.ballot_count += 1;
    ELECTION.save(deps.storage, &election)?;

    Ok(Response::new()
        .add_attribute("action", "cast_ballot")
        .add_attribute("voter", info.sender))
}

fn exec_tally(deps: DepsMut, result: TallyMsg) -> Result<Response, ContractError> {
    let mut election = ELECTION.load(deps.storage)?;

    if election.phase != ElectionPhase::Voting && election.phase != ElectionPhase::Tallying {
        return Err(ContractError::NoElection);
    }
    if result.election_id != election.election_id {
        return Err(ContractError::NoElection);
    }

    RESULTS.save(
        deps.storage,
        result.election_id,
        &ElectionResult {
            election_id: result.election_id,
            winner: result.winner.clone(),
            rounds: result.rounds,
            total_ballots: result.total_ballots,
        },
    )?;

    election.phase = ElectionPhase::Complete;
    ELECTION.save(deps.storage, &election)?;

    Ok(Response::new()
        .add_attribute("action", "tally")
        .add_attribute("winner", result.winner))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::Election {} => to_json_binary(&ELECTION.load(deps.storage)?),
        QueryMsg::Result { election_id } => {
            to_json_binary(&RESULTS.load(deps.storage, election_id)?)
        }
        QueryMsg::Session {} => {
            let session = SESSION.may_load(deps.storage)?;
            let pub_key = session.and_then(|s| s.pub_key());
            to_json_binary(&SessionResponse { pub_key })
        }
    }
}
