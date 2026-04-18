use cosmwasm_std::{
    entry_point, to_json_binary, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo,
    Order, Response, StdResult, Timestamp,
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
    // Quartz handshake setup
    msg.quartz.handle_raw(deps.branch(), &env, &info)?;

    let config = Config {
        admin: info.sender,
        auction_duration: msg.auction_duration,
        reserve_price: msg.reserve_price,
    };
    CONFIG.save(deps.storage, &config)?;

    let round = AuctionRound {
        round_id: 0,
        phase: AuctionPhase::Idle,
        auction_end: Timestamp::from_seconds(0),
        bid_count: 0,
    };
    ROUND.save(deps.storage, &round)?;
    ROUND_COUNTER.save(deps.storage, &0u64)?;

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
        ExecuteMsg::StartAuction {} => exec_start_auction(deps, env, info),
        ExecuteMsg::SubmitBid { ciphertext } => exec_submit_bid(deps, env, info, ciphertext),
        ExecuteMsg::Resolve(attested_msg) => {
            // Verify attestation (compose-hash, user_data match)
            attested_msg
                .clone()
                .handle_raw(deps.branch(), &env, &info)?;
            // Attestation verified — process the result
            exec_resolve(deps, env, attested_msg.msg.0)
        }
    }
}

fn exec_start_auction(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    let round = ROUND.load(deps.storage)?;
    if round.phase != AuctionPhase::Idle && round.phase != AuctionPhase::Complete {
        return Err(ContractError::StillBidding);
    }

    // Clear previous bids
    let keys: Vec<Addr> = SEALED_BIDS
        .keys(deps.storage, None, None, Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;
    for key in keys {
        SEALED_BIDS.remove(deps.storage, &key);
    }

    let counter = ROUND_COUNTER.load(deps.storage)? + 1;
    ROUND_COUNTER.save(deps.storage, &counter)?;

    let new_round = AuctionRound {
        round_id: counter,
        phase: AuctionPhase::Bidding,
        auction_end: env.block.time.plus_seconds(config.auction_duration),
        bid_count: 0,
    };
    ROUND.save(deps.storage, &new_round)?;

    Ok(Response::new()
        .add_attribute("action", "start_auction")
        .add_attribute("round_id", counter.to_string()))
}

fn exec_submit_bid(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    ciphertext: HexBinary,
) -> Result<Response, ContractError> {
    let mut round = ROUND.load(deps.storage)?;

    if round.phase != AuctionPhase::Bidding {
        return Err(ContractError::NotBidding);
    }
    if env.block.time >= round.auction_end {
        return Err(ContractError::NotBidding);
    }
    if SEALED_BIDS.has(deps.storage, &info.sender) {
        return Err(ContractError::AlreadyBid);
    }

    // Store the encrypted bid. The contract cannot read the bid amount —
    // it's encrypted to the enclave's session pubkey. Only the enclave
    // can decrypt it during resolution.
    SEALED_BIDS.save(deps.storage, &info.sender, &ciphertext)?;
    round.bid_count += 1;
    ROUND.save(deps.storage, &round)?;

    Ok(Response::new()
        .add_attribute("action", "submit_bid")
        .add_attribute("bidder", info.sender))
}

fn exec_resolve(
    deps: DepsMut,
    _env: Env,
    result: ResolveMsg,
) -> Result<Response, ContractError> {
    let mut round = ROUND.load(deps.storage)?;

    if round.phase != AuctionPhase::Bidding && round.phase != AuctionPhase::Resolving {
        return Err(ContractError::NoAuction);
    }
    if result.round_id != round.round_id {
        return Err(ContractError::NoAuction);
    }

    // Store the public result
    let winner = result
        .winner
        .as_ref()
        .map(|w| deps.api.addr_validate(w))
        .transpose()?;

    let auction_result = AuctionResult {
        round_id: result.round_id,
        winner,
        price: result.price,
        bid_count: result.bid_count,
    };
    RESULTS.save(deps.storage, result.round_id, &auction_result)?;

    round.phase = AuctionPhase::Complete;
    ROUND.save(deps.storage, &round)?;

    Ok(Response::new()
        .add_attribute("action", "resolve")
        .add_attribute(
            "winner",
            result.winner.unwrap_or_else(|| "none".to_string()),
        )
        .add_attribute("price", result.price))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::CurrentRound {} => to_json_binary(&ROUND.load(deps.storage)?),
        QueryMsg::Result { round_id } => to_json_binary(&RESULTS.load(deps.storage, round_id)?),
        QueryMsg::Session {} => {
            let session = SESSION.may_load(deps.storage)?;
            let pub_key = session.and_then(|s| s.pub_key());
            to_json_binary(&SessionResponse { pub_key })
        }
    }
}
