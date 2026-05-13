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

// ── Pure guards (mirror the action-local checks in `contract.rs`) ───
//
// These small, total functions are the canonical phase-transition
// guards. They have no I/O, no storage, and no `Env` dependency — so
// they are tractable targets for Kani symbolic execution. `contract.rs`
// composes the same predicates inline; keeping the pure form here lets
// the proofs anchor on the predicate, not the surrounding handler.

/// Admin can start a new auction round only when the contract is idle
/// or the previous round has completed.
#[inline]
pub fn can_start_auction(phase: &AuctionPhase) -> bool {
    matches!(phase, AuctionPhase::Idle | AuctionPhase::Complete)
}

/// A sealed bid is accepted only while the auction is in the Bidding
/// phase, strictly before the deadline, and only the first time the
/// bidder submits this round (no double-bid).
#[inline]
pub fn can_submit_bid(
    phase: &AuctionPhase,
    block_time_secs: u64,
    auction_end_secs: u64,
    bidder_already_present: bool,
) -> bool {
    matches!(phase, AuctionPhase::Bidding)
        && block_time_secs < auction_end_secs
        && !bidder_already_present
}

/// The enclave's attested Resolve is accepted only while the round is
/// still Bidding or has been moved to Resolving, and the attested
/// `round_id` matches the on-chain round.
#[inline]
pub fn can_resolve(phase: &AuctionPhase, msg_round_id: u64, current_round_id: u64) -> bool {
    matches!(phase, AuctionPhase::Bidding | AuctionPhase::Resolving)
        && msg_round_id == current_round_id
}

/// Vickrey second-price selection from a pre-decrypted, reserve-filtered
/// bid list. Pure arithmetic so it can be Kani-verified. Mirrors the
/// enclave's `resolve_auction` logic.
///
/// Returns `(winner_index, price)`:
/// - `winner_index = Some(i)` if there is at least one valid bid, and
///   `bids[i]` is the unique highest bid (ties broken by smallest index).
/// - `price` is the second-highest valid bid, or `reserve` when fewer
///   than two valid bids are present.
#[inline]
pub fn vickrey_select(bids: &[u128], reserve: u128) -> (Option<usize>, u128) {
    if bids.is_empty() {
        return (None, 0);
    }

    // First pass: pick the winner. Initialize from index 0 so the
    // smallest-index tie-break is unambiguous (matches the Quint
    // `inv_winner_is_highest` + determinism intent in the spec).
    let mut winner_idx: usize = 0;
    let mut best: u128 = bids[0];
    for (i, &b) in bids.iter().enumerate().skip(1) {
        if b > best {
            best = b;
            winner_idx = i;
        }
    }

    // Second pass: highest bid that is not the winner.
    let mut second: u128 = 0;
    let mut have_second = false;
    for (i, &b) in bids.iter().enumerate() {
        if i != winner_idx && (!have_second || b > second) {
            second = b;
            have_second = true;
        }
    }

    let price = if have_second && second > reserve {
        second
    } else {
        reserve
    };
    (Some(winner_idx), price)
}

// ── Kani verification harnesses ────────────────────────────────────
//
// Pure-logic proofs for the contract's phase transitions and the
// enclave's Vickrey arithmetic. Mirrors the pattern used in
// `crates/contracts/core/src/state.rs`.
//
// Run with: `cargo kani` from `examples/sealed-auction/contracts/`.

#[cfg(kani)]
mod verification {
    use super::*;

    /// `can_start_auction` is total and accepts exactly Idle/Complete.
    #[kani::proof]
    fn start_auction_guard_total() {
        let p: u8 = kani::any();
        kani::assume(p < 4);
        let phase = match p {
            0 => AuctionPhase::Idle,
            1 => AuctionPhase::Bidding,
            2 => AuctionPhase::Resolving,
            _ => AuctionPhase::Complete,
        };
        let allowed = can_start_auction(&phase);
        match phase {
            AuctionPhase::Idle | AuctionPhase::Complete => assert!(allowed),
            AuctionPhase::Bidding | AuctionPhase::Resolving => assert!(!allowed),
        }
    }

    /// A bid is admitted iff phase==Bidding AND deadline not yet
    /// reached AND bidder hasn't already submitted. Proves all four
    /// guard clauses interact correctly.
    #[kani::proof]
    fn submit_bid_guard_exact() {
        let p: u8 = kani::any();
        kani::assume(p < 4);
        let phase = match p {
            0 => AuctionPhase::Idle,
            1 => AuctionPhase::Bidding,
            2 => AuctionPhase::Resolving,
            _ => AuctionPhase::Complete,
        };
        let now: u64 = kani::any();
        let end: u64 = kani::any();
        let dup: bool = kani::any();

        let ok = can_submit_bid(&phase, now, end, dup);
        let expected =
            matches!(phase, AuctionPhase::Bidding) && now < end && !dup;
        assert_eq!(ok, expected);
    }

    /// A bid past the deadline is always rejected, regardless of phase
    /// or duplicate flag. This is the canonical "no late bids" check.
    #[kani::proof]
    fn submit_bid_rejected_past_deadline() {
        let p: u8 = kani::any();
        kani::assume(p < 4);
        let phase = match p {
            0 => AuctionPhase::Idle,
            1 => AuctionPhase::Bidding,
            2 => AuctionPhase::Resolving,
            _ => AuctionPhase::Complete,
        };
        let now: u64 = kani::any();
        let end: u64 = kani::any();
        kani::assume(now >= end);
        let dup: bool = kani::any();
        assert!(!can_submit_bid(&phase, now, end, dup));
    }

    /// A duplicate bid from the same bidder is always rejected.
    /// Mirrors the `SEALED_BIDS.has(...)` check in `exec_submit_bid`.
    #[kani::proof]
    fn submit_bid_rejected_duplicate() {
        let p: u8 = kani::any();
        kani::assume(p < 4);
        let phase = match p {
            0 => AuctionPhase::Idle,
            1 => AuctionPhase::Bidding,
            2 => AuctionPhase::Resolving,
            _ => AuctionPhase::Complete,
        };
        let now: u64 = kani::any();
        let end: u64 = kani::any();
        assert!(!can_submit_bid(&phase, now, end, true));
    }

    /// Resolve requires the message round_id to match the current
    /// round, and a phase that hasn't completed yet.
    #[kani::proof]
    fn resolve_guard_round_id_must_match() {
        let p: u8 = kani::any();
        kani::assume(p < 4);
        let phase = match p {
            0 => AuctionPhase::Idle,
            1 => AuctionPhase::Bidding,
            2 => AuctionPhase::Resolving,
            _ => AuctionPhase::Complete,
        };
        let msg_id: u64 = kani::any();
        let cur_id: u64 = kani::any();

        let ok = can_resolve(&phase, msg_id, cur_id);
        let expected = matches!(
            phase,
            AuctionPhase::Bidding | AuctionPhase::Resolving
        ) && msg_id == cur_id;
        assert_eq!(ok, expected);
    }

    /// Vickrey selection with an empty bid set returns no winner and
    /// zero price. Models the "no valid bids" branch.
    #[kani::proof]
    fn vickrey_empty_no_winner() {
        let reserve: u128 = kani::any();
        let (w, p) = vickrey_select(&[], reserve);
        assert!(w.is_none());
        assert_eq!(p, 0);
    }

    /// Single-bidder Vickrey pays the reserve (since there is no
    /// second-highest bid above reserve). The winner is that sole
    /// bidder.
    #[kani::proof]
    fn vickrey_single_bidder_pays_reserve() {
        let bid: u128 = kani::any();
        let reserve: u128 = kani::any();
        // The reserve-filter is the caller's responsibility (mirrors the
        // enclave path that drops sub-reserve bids before this helper).
        kani::assume(bid >= reserve);
        let bids = [bid];
        let (w, price) = vickrey_select(&bids, reserve);
        assert_eq!(w, Some(0));
        assert_eq!(price, reserve);
    }

    /// Two-bidder Vickrey: the higher bidder wins, paying exactly the
    /// lower bid (or the reserve if the lower bid is below reserve).
    #[kani::proof]
    fn vickrey_two_bidders_second_price() {
        let a: u128 = kani::any();
        let b: u128 = kani::any();
        let reserve: u128 = kani::any();
        kani::assume(a >= reserve && b >= reserve);
        // Asymmetric ordering: keep one strictly higher to avoid the
        // tie case in this harness (tie-break is exercised separately).
        kani::assume(a > b);

        let bids = [a, b];
        let (w, price) = vickrey_select(&bids, reserve);
        assert_eq!(w, Some(0));
        let expected_price = if b > reserve { b } else { reserve };
        assert_eq!(price, expected_price);
    }

    /// Tie-break determinism: when two bids are exactly equal, the
    /// smaller index wins. This guards against non-deterministic
    /// winner selection that would let the enclave silently choose.
    #[kani::proof]
    fn vickrey_tie_break_lowest_index() {
        let v: u128 = kani::any();
        let reserve: u128 = kani::any();
        kani::assume(v >= reserve);
        let bids = [v, v, v];
        let (w, _price) = vickrey_select(&bids, reserve);
        assert_eq!(w, Some(0));
    }
}
