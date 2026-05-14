// Sealed Vickrey Auction with Quartz Privacy
//
// Models a second-price sealed-bid auction where bids are encrypted
// to the enclave's session public key. The contract stores opaque
// ciphertext. The enclave decrypts, determines the winner + second
// price, and returns an attested result.
//
// Privacy model:
// - Bid amounts are private during bidding (encrypted)
// - Winner and second price are public after resolution
// - The enclave is the only entity that sees plaintext bids
// - The contract verifies the result via attestation

module auction {

  // ============================================================
  // Types
  // ============================================================

  type Addr = str
  type Ciphertext = str    // opaque encrypted blob
  type Amount = int        // micro-units

  type AuctionPhase =
    | Idle
    | Bidding
    | Resolving
    | Complete

  /// What the contract sees (public chain state)
  type ContractState = {
    phase: AuctionPhase,
    round_id: int,
    auction_end: int,          // block time when bidding closes
    reserve_price: Amount,
    // Encrypted bids — contract stores but cannot read
    sealed_bids: Addr -> Ciphertext,
    bid_count: int,
    // Result (public after resolution)
    winner: Addr,              // "" if no winner
    winning_price: Amount,     // second price
    session_active: bool,      // handshake completed
  }

  /// What the enclave sees (private, in TEE memory)
  type EnclaveState = {
    // Decrypted bids — only visible inside the enclave
    decrypted_bids: Addr -> Amount,
    has_session_key: bool,
  }

  /// What an external observer sees
  type ObserverView = {
    can_see_bids: bool,        // always false (bid amounts never revealed)
    can_see_result: bool,      // true after resolution
    // Per-round flag: at least one sealed bid has been posted to the
    // chain this round. Reset at `start_auction`, set on the first
    // `submit_bid`. This is intentionally a per-round predicate, not a
    // monotone "any ciphertext has ever been revealed" — auctions reset
    // their visible state at each new round.
    current_round_has_revealed_ciphertexts: bool,
  }

  /// Tag of the most recent action — promoted from the stub-style
  /// `last_input` pattern in specs/attestation.qnt (Phase 2). Lets
  /// state-only invariants check action-local obligations.
  type LastAction =
    | NoAction
    | DidInit
    | DidStartAuction
    | DidSubmitBid
    | DidTick
    | DidCloseBidding
    | DidResolve

  // ============================================================
  // State
  // ============================================================

  var contract: ContractState
  var enclave: EnclaveState
  var observer: ObserverView
  var block_time: int
  /// Most recent action label.
  var last_action: LastAction
  /// Sealed-bid keys at the moment the last submit_bid ran. Used to
  /// check that the bidder was not already present (no double-bid),
  /// and that the submitter was admitted only during Bidding.
  var last_bidder: Addr
  /// Block time at which the last action ran. For Resolve, this is
  /// the time the enclave wrote the result — must be at/after deadline.
  var last_action_block_time: int
  /// Auction end captured at the moment the last action ran. Lets us
  /// check `last_action_block_time < auction_end_at_action` for bids,
  /// without relying on the current (possibly mutated) auction_end.
  var last_auction_end: int

  // ============================================================
  // Constants
  // ============================================================

  val ADMIN = "admin"
  val SPONSOR_A = "sponsor_a"
  val SPONSOR_B = "sponsor_b"
  val SPONSOR_C = "sponsor_c"
  val RESERVE = 100
  val AUCTION_DURATION = 300  // seconds

  // ============================================================
  // Initial state
  // ============================================================

  action init = all {
    contract' = {
      phase: Idle,
      round_id: 0,
      auction_end: 0,
      reserve_price: RESERVE,
      sealed_bids: Map(),
      bid_count: 0,
      winner: "",
      winning_price: 0,
      session_active: true,  // assume handshake already done
    },
    enclave' = {
      decrypted_bids: Map(),
      has_session_key: true,
    },
    observer' = {
      can_see_bids: false,
      can_see_result: false,
      current_round_has_revealed_ciphertexts: false,
    },
    block_time' = 1000,
    last_action' = DidInit,
    last_bidder' = "",
    last_action_block_time' = 1000,
    last_auction_end' = 0,
  }

  // ============================================================
  // Actions
  // ============================================================

  /// Admin starts a new auction round
  action start_auction: bool = all {
    contract.phase == Idle or contract.phase == Complete,
    contract.session_active,
    val new_round = contract.round_id + 1
    contract' = {
      ...contract,
      phase: Bidding,
      round_id: new_round,
      auction_end: block_time + AUCTION_DURATION,
      sealed_bids: Map(),
      bid_count: 0,
      winner: "",
      winning_price: 0,
    },
    enclave' = { ...enclave, decrypted_bids: Map() },
    observer' = { can_see_bids: false, can_see_result: false, current_round_has_revealed_ciphertexts: false },
    block_time' = block_time,
    last_action' = DidStartAuction,
    last_bidder' = "",
    last_action_block_time' = block_time,
    last_auction_end' = block_time + AUCTION_DURATION,
  }

  /// Sponsor submits an encrypted bid
  /// The contract stores the ciphertext without knowing the amount.
  /// The actual amount is only known to the sponsor and (later) the enclave.
  action submit_bid(sponsor: Addr, actual_amount: Amount, ciphertext: Ciphertext): bool = all {
    contract.phase == Bidding,
    block_time < contract.auction_end,
    not(contract.sealed_bids.keys().contains(sponsor)),
    // Contract stores opaque ciphertext
    contract' = {
      ...contract,
      sealed_bids: contract.sealed_bids.put(sponsor, ciphertext),
      bid_count: contract.bid_count + 1,
    },
    // Observer sees ciphertext appear on-chain but NOT the amount
    observer' = { ...observer, current_round_has_revealed_ciphertexts: true, can_see_bids: false },
    // Enclave doesn't decrypt yet — bids are just stored
    enclave' = enclave,
    block_time' = block_time,
    last_action' = DidSubmitBid,
    last_bidder' = sponsor,
    last_action_block_time' = block_time,
    last_auction_end' = contract.auction_end,
  }

  /// Advance block time
  action tick(dt: int): bool = all {
    dt > 0,
    block_time' = block_time + dt,
    contract' = contract,
    enclave' = enclave,
    observer' = observer,
    last_action' = DidTick,
    last_bidder' = last_bidder,
    last_action_block_time' = block_time + dt,
    last_auction_end' = last_auction_end,
  }

  /// **Off-chain orchestration step**: an external admin/relayer flips
  /// the on-chain phase from `Bidding` to `Resolving` once the deadline
  /// has passed. The contract's `exec_resolve` accepts `Bidding |
  /// Resolving` as input phases (see the `phase != Bidding && phase
  /// != Resolving` guard at `contract.rs::exec_resolve`), but no execute
  /// branch in `contract.rs` writes `Resolving` — this action models
  /// the external transition that does. The prior docstring claimed
  /// "anyone can flip the phase ... pure observable, not an admin-gated
  /// transition" — this was misleading: the contract has no on-chain
  /// path into `Resolving` at all. The action remains as a *model* of
  /// the orchestration step the deployment relies on; if/when the
  /// contract gains a real `exec_close_bidding` branch, this can be
  /// re-aligned. (Round B 2026-05-14 adversarial finding; see
  /// `.colosseum/attacks/quint-recently-revised-2026-05-14/`.)
  action close_bidding: bool = all {
    contract.phase == Bidding,
    block_time >= contract.auction_end,
    contract' = { ...contract, phase: Resolving },
    enclave' = enclave,
    observer' = observer,
    block_time' = block_time,
    last_action' = DidCloseBidding,
    last_bidder' = last_bidder,
    last_action_block_time' = block_time,
    last_auction_end' = contract.auction_end,
  }

  /// Enclave decrypts all bids and resolves the auction.
  /// This models the enclave's private computation:
  /// 1. Read encrypted bids from chain (via light client proof)
  /// 2. Decrypt each bid with the session key
  /// 3. Run Vickrey logic
  /// 4. Return attested result
  ///
  /// Accepts both `Bidding` and `Resolving` as entry phases — mirrors the
  /// contract's `exec_resolve` guard, which permits either.
  action resolve(decrypted: Addr -> Amount): bool = all {
    contract.phase == Bidding or contract.phase == Resolving,
    block_time >= contract.auction_end,
    contract.bid_count > 0,
    // The decrypted bids must have the same keys as the sealed bids
    decrypted.keys() == contract.sealed_bids.keys(),
    // Enclave now has all decrypted bids in memory
    enclave' = { ...enclave, decrypted_bids: decrypted },
    // Find winner (highest bid above reserve)
    val valid_bids = decrypted.keys().filter(addr =>
      decrypted.get(addr) >= contract.reserve_price
    )
    if (valid_bids == Set()) {
      // No valid bids
      all {
        contract' = {
          ...contract,
          phase: Complete,
          winner: "",
          winning_price: 0,
        },
        observer' = { ...observer, can_see_result: true, can_see_bids: false },
        last_action' = DidResolve,
        last_bidder' = last_bidder,
        last_action_block_time' = block_time,
        last_auction_end' = contract.auction_end,
      }
    } else {
      // Find highest bidder
      val max_amount = valid_bids.fold(0, (best, addr) =>
        if (decrypted.get(addr) > best) decrypted.get(addr) else best
      )
      val winner_addr = valid_bids.fold("", (best_addr, addr) =>
        if (decrypted.get(addr) == max_amount and best_addr == "") addr else best_addr
      )
      // Find second price
      val other_amounts = valid_bids.exclude(Set(winner_addr)).fold(0, (best, addr) =>
        if (decrypted.get(addr) > best) decrypted.get(addr) else best
      )
      val second_price = if (other_amounts > contract.reserve_price)
        other_amounts else contract.reserve_price
      all {
        contract' = {
          ...contract,
          phase: Complete,
          winner: winner_addr,
          winning_price: second_price,
        },
        // Result is public, but individual bid amounts remain private
        observer' = { can_see_bids: false, can_see_result: true, current_round_has_revealed_ciphertexts: true },
        last_action' = DidResolve,
        last_bidder' = last_bidder,
        last_action_block_time' = block_time,
        last_auction_end' = contract.auction_end,
      }
    },
    block_time' = block_time,
  }

  // ============================================================
  // Step
  // ============================================================

  action step = {
    nondet sponsor = oneOf(Set(SPONSOR_A, SPONSOR_B, SPONSOR_C))
    nondet amount = oneOf(Set(50, 100, 150, 200, 300, 500))
    nondet ciphertext = oneOf(Set("ct_a", "ct_b", "ct_c"))
    nondet dt = oneOf(Set(1, 10, 100, 300, 500))

    // Per-sponsor nondet amounts. Quint 0.32 still does not permit
    // introducing fresh `nondet` bindings inside `fold` or other
    // higher-order combinators, so we pre-bind one amount per
    // candidate bidder up front and look them up by address while
    // building the decrypted-bids map. This is a workaround for the
    // missing "nondet per element" capability — once Quint supports
    // it, the per-sponsor bindings collapse to a single
    // `nondet amount_for: Addr -> Amount` over the key set.
    nondet amount_a = oneOf(Set(50, 100, 200, 300))
    nondet amount_b = oneOf(Set(50, 150, 250, 500))
    nondet amount_c = oneOf(Set(50, 100, 200, 400))

    // Build a decrypted-bids map whose keys exactly match the current
    // sealed_bids keys, picking the matching per-sponsor amount. This
    // replaces the previous cardinality-enumeration of resolve calls.
    val decrypted_bids: Addr -> Amount =
      contract.sealed_bids.keys().fold(Map(), (acc, addr) =>
        if (addr == SPONSOR_A) acc.put(addr, amount_a)
        else if (addr == SPONSOR_B) acc.put(addr, amount_b)
        else acc.put(addr, amount_c)
      )

    any {
      start_auction,
      submit_bid(sponsor, amount, ciphertext),
      tick(dt),
      close_bidding,
      resolve(decrypted_bids),
    }
  }

  // ============================================================
  // Invariants
  // ============================================================

  /// Bid amounts are NEVER visible to observers during bidding
  val inv_bids_private_during_bidding: bool = {
    if (contract.phase == Bidding)
      not(observer.can_see_bids)
    else true
  }

  /// Bid amounts are NEVER visible to observers even after resolution
  /// (only the winner and second price are published)
  val inv_individual_bids_always_private: bool = {
    not(observer.can_see_bids)
  }

  /// Winner always has the highest valid bid
  val inv_winner_is_highest: bool = {
    if (contract.phase == Complete and contract.winner != "") {
      val winner_amount = enclave.decrypted_bids.get(contract.winner)
      enclave.decrypted_bids.keys().forall(addr =>
        enclave.decrypted_bids.get(addr) <= winner_amount
      )
    } else true
  }

  /// Winning price is at most the winner's bid
  val inv_price_bounded: bool = {
    if (contract.phase == Complete and contract.winner != "") {
      val winner_amount = enclave.decrypted_bids.get(contract.winner)
      contract.winning_price <= winner_amount
    } else true
  }

  /// Winning price is at least the reserve price
  val inv_price_above_reserve: bool = {
    if (contract.phase == Complete and contract.winner != "")
      contract.winning_price >= contract.reserve_price
    else true
  }

  /// No bids can be submitted after the deadline. Promoted from
  /// `true` stub to a state-based check using last_action tracking:
  /// whenever the most recent action was a SubmitBid, it ran strictly
  /// before the auction_end captured at the time of that bid.
  val inv_no_late_bids: bool = {
    if (last_action == DidSubmitBid)
      last_action_block_time < last_auction_end
    else true
  }

  /// No front-running / no premature reveal: bids cannot be "revealed"
  /// (i.e., the enclave cannot publish decrypted_bids) while the
  /// contract is still in the Bidding phase before the deadline. The
  /// resolve action's pre-condition `block_time >= auction_end` is the
  /// gate; this invariant is the corresponding state predicate.
  ///
  /// Concretely: if any decrypted bids exist (i.e. the enclave has
  /// resolved), then either the phase is Complete already, or — at
  /// the very least — the captured auction_end at the time of the
  /// last action was at or before the resolve's block_time.
  val inv_no_premature_reveal: bool = {
    if (enclave.decrypted_bids.keys() != Set())
      // After a resolve, phase must be Complete and the resolve must
      // have run at or after the captured auction_end.
      contract.phase == Complete
        and (last_action == DidResolve
             implies last_action_block_time >= last_auction_end)
    else true
  }

  /// Reveal-phase consistency: when the enclave publishes decrypted
  /// bids (which models the reveal step in the protocol), the set of
  /// decrypted bidders must exactly match the set of sealed bidders.
  /// This is the spec analog of "revealed bid matches commitment" —
  /// since the contract holds the ciphertext as the commitment, the
  /// enclave cannot manufacture bids for addresses that never submitted.
  val inv_decrypted_matches_sealed: bool = {
    if (contract.phase == Complete and enclave.decrypted_bids.keys() != Set())
      enclave.decrypted_bids.keys() == contract.sealed_bids.keys()
    else true
  }

  /// Resolve-phase guard: the enclave's resolve action runs only after
  /// the bidding deadline. State-based equivalent of the action guard
  /// `block_time >= contract.auction_end` inside `resolve`.
  val inv_resolve_after_deadline: bool = {
    if (last_action == DidResolve)
      last_action_block_time >= last_auction_end
    else true
  }

  /// Winner is one of the bidders that actually submitted a sealed
  /// bid. The enclave cannot pick a winner who never participated.
  val inv_winner_is_bidder: bool = {
    if (contract.phase == Complete and contract.winner != "")
      contract.sealed_bids.keys().contains(contract.winner)
    else true
  }

  /// Phase transitions are valid
  val inv_valid_phases: bool = {
    contract.phase == Idle or
    contract.phase == Bidding or
    contract.phase == Resolving or
    contract.phase == Complete
  }

  /// Session must be active for auction to start
  val inv_session_required: bool = {
    if (contract.phase == Bidding
        or contract.phase == Resolving
        or contract.phase == Complete)
      contract.session_active
    else true
  }

  /// Ciphertexts are visible on-chain when bids exist
  val inv_ciphertexts_public: bool = {
    if (contract.bid_count > 0)
      observer.current_round_has_revealed_ciphertexts
    else true
  }

  /// The Resolving phase is only ever entered after the bidding window
  /// has closed. Catches accidental shortcut transitions that would
  /// allow the enclave's resolve handler to accept bids closed early.
  /// Before introducing the Resolving state explicitly, the spec had no
  /// way to express "the contract is past the deadline but the enclave
  /// has not yet posted" — the implicit Bidding -> Complete shortcut
  /// silently merged the two.
  val inv_resolving_only_after_deadline: bool = {
    if (contract.phase == Resolving)
      block_time >= contract.auction_end
    else true
  }

  /// Composite invariant
  val all_invariants: bool = {
    inv_bids_private_during_bidding
    and inv_individual_bids_always_private
    and inv_winner_is_highest
    and inv_price_bounded
    and inv_price_above_reserve
    and inv_valid_phases
    and inv_session_required
    and inv_ciphertexts_public
    and inv_no_late_bids
    and inv_no_premature_reveal
    and inv_decrypted_matches_sealed
    and inv_resolve_after_deadline
    and inv_winner_is_bidder
    and inv_resolving_only_after_deadline
  }
}
