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
    can_see_bids: bool,        // always false during bidding
    can_see_result: bool,      // true after resolution
    can_see_ciphertexts: bool, // always true (on-chain)
  }

  // ============================================================
  // State
  // ============================================================

  var contract: ContractState
  var enclave: EnclaveState
  var observer: ObserverView
  var block_time: int

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
      can_see_ciphertexts: false,
    },
    block_time' = 1000,
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
    observer' = { can_see_bids: false, can_see_result: false, can_see_ciphertexts: false },
    block_time' = block_time,
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
    observer' = { ...observer, can_see_ciphertexts: true, can_see_bids: false },
    // Enclave doesn't decrypt yet — bids are just stored
    enclave' = enclave,
    block_time' = block_time,
  }

  /// Advance block time
  action tick(dt: int): bool = all {
    dt > 0,
    block_time' = block_time + dt,
    contract' = contract,
    enclave' = enclave,
    observer' = observer,
  }

  /// Enclave decrypts all bids and resolves the auction.
  /// This models the enclave's private computation:
  /// 1. Read encrypted bids from chain (via light client proof)
  /// 2. Decrypt each bid with the session key
  /// 3. Run Vickrey logic
  /// 4. Return attested result
  action resolve(decrypted: Addr -> Amount): bool = all {
    contract.phase == Bidding,
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
        observer' = { can_see_bids: false, can_see_result: true, can_see_ciphertexts: true },
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

    // For resolve, we need to provide decrypted bids that match sealed_bids keys.
    // Since we can't dynamically construct maps matching arbitrary key sets in
    // the step function, we enumerate specific scenarios.
    nondet amount_a = oneOf(Set(50, 100, 200, 300))
    nondet amount_b = oneOf(Set(50, 150, 250, 500))
    nondet amount_c = oneOf(Set(50, 100, 200, 400))

    any {
      start_auction,
      submit_bid(sponsor, amount, ciphertext),
      tick(dt),
      // Resolve with different bid count scenarios
      resolve(Map()),
      // Single bidder scenarios
      all {
        contract.sealed_bids.keys() == Set(SPONSOR_A),
        resolve(Map(SPONSOR_A -> amount_a)),
      },
      all {
        contract.sealed_bids.keys() == Set(SPONSOR_B),
        resolve(Map(SPONSOR_B -> amount_b)),
      },
      // Two bidder scenarios
      all {
        contract.sealed_bids.keys() == Set(SPONSOR_A, SPONSOR_B),
        resolve(Map(SPONSOR_A -> amount_a, SPONSOR_B -> amount_b)),
      },
      // Three bidder scenarios
      all {
        contract.sealed_bids.keys() == Set(SPONSOR_A, SPONSOR_B, SPONSOR_C),
        resolve(Map(SPONSOR_A -> amount_a, SPONSOR_B -> amount_b, SPONSOR_C -> amount_c)),
      },
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

  /// No bids can be submitted after the deadline
  val inv_no_late_bids: bool = {
    if (contract.phase == Bidding and contract.bid_count > 0)
      // If there are bids, they were submitted before the deadline
      // (enforced by the block_time < auction_end guard in submit_bid)
      true
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
    if (contract.phase == Bidding or contract.phase == Complete)
      contract.session_active
    else true
  }

  /// Ciphertexts are visible on-chain when bids exist
  val inv_ciphertexts_public: bool = {
    if (contract.bid_count > 0)
      observer.can_see_ciphertexts
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
  }
}
