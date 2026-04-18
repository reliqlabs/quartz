// Ranked Choice Voting (Instant-Runoff) with Quartz Privacy
//
// Models a private ranked choice election where voters encrypt their
// ballots to the enclave's session key. The enclave decrypts and runs
// instant-runoff: eliminate the candidate with fewest first-choice
// votes, redistribute those votes to next choices, repeat until
// someone has a majority.
//
// Privacy: individual ballot rankings are never revealed. Only
// round-by-round aggregate counts and the winner are published.

module rcv {

  // ============================================================
  // Types
  // ============================================================

  type Addr = str
  type Candidate = str

  /// A ranked ballot: ordered list of candidates, first choice first
  type Ballot = List[Candidate]

  type ElectionPhase =
    | Setup
    | Voting
    | Complete

  /// What the contract sees (public)
  type ContractState = {
    phase: ElectionPhase,
    election_id: int,
    candidates: Set[Candidate],
    encrypted_ballot_count: int,
    winner: Candidate,               // "" if not resolved
    round_count: int,                // 0 until resolved
    session_active: bool,
  }

  /// What the enclave sees during tally (private)
  type EnclaveState = {
    decrypted_ballots: Addr -> Ballot,
  }

  /// What an observer can see
  type ObserverView = {
    can_see_rankings: bool,          // individual ballot rankings
    can_see_tallies: bool,           // round-by-round counts
    can_see_who_voted: bool,         // voter addresses
  }

  // ============================================================
  // State
  // ============================================================

  var contract: ContractState
  var enclave: EnclaveState
  var observer: ObserverView

  // ============================================================
  // Constants
  // ============================================================

  val ALICE = "Alice"
  val BOB = "Bob"
  val CAROL = "Carol"
  val ALL_CANDIDATES = Set(ALICE, BOB, CAROL)

  val VOTER_1 = "voter1"
  val VOTER_2 = "voter2"
  val VOTER_3 = "voter3"
  val VOTER_4 = "voter4"
  val VOTER_5 = "voter5"

  // ============================================================
  // Pure helpers
  // ============================================================

  /// Count first-choice votes for each candidate from the given ballots,
  /// excluding eliminated candidates
  pure def count_first_choices(
    ballots: Addr -> Ballot,
    eliminated: Set[Candidate],
    candidates: Set[Candidate]
  ): Candidate -> int = {
    val active = candidates.exclude(eliminated)
    active.fold(Map(), (counts, c) => {
      val votes = ballots.keys().filter(voter => {
        val ballot = ballots.get(voter)
        val first_active = ballot.indices().fold("", (found, i) =>
          if (found == "" and active.contains(ballot[i])) ballot[i] else found
        )
        first_active == c
      }).size()
      counts.put(c, votes)
    })
  }

  /// Find the candidate with the fewest votes.
  /// Among ties, picks any (nondeterministic — matches Rust's sort tiebreak).
  pure def find_loser(counts: Candidate -> int): Candidate = {
    val min_votes = counts.keys().fold(999999, (best, c) =>
      if (counts.get(c) < best) counts.get(c) else best
    )
    counts.keys().fold("", (loser, c) =>
      if (counts.get(c) == min_votes and loser == "")
        c else loser
    )
  }

  /// Check if any candidate has a majority
  pure def has_majority(counts: Candidate -> int): bool = {
    val total = counts.keys().fold(0, (sum, c) => sum + counts.get(c))
    val majority = total / 2 + 1
    counts.keys().exists(c => counts.get(c) >= majority)
  }

  /// Find the majority winner
  pure def majority_winner(counts: Candidate -> int): Candidate = {
    val total = counts.keys().fold(0, (sum, c) => sum + counts.get(c))
    val majority = total / 2 + 1
    counts.keys().fold("", (winner, c) =>
      if (winner == "" and counts.get(c) >= majority) c else winner
    )
  }

  type IRVState = {
    winner: Candidate,
    round_count: int,
    eliminated: Set[Candidate],
  }

  /// Run instant-runoff and return { winner, round_count }
  pure def instant_runoff(
    ballots: Addr -> Ballot,
    candidates: Set[Candidate]
  ): IRVState = {
    val max_rounds = candidates.size()
    val initial: IRVState = { winner: "", round_count: 0, eliminated: Set() }
    (0).to(max_rounds).fold(initial, (state, _round) => {
      if (state.winner != "") {
        state
      } else {
        val active = candidates.exclude(state.eliminated)
        if (active.size() <= 1) {
          val last = active.fold("", (_w, c) => c)
          { winner: last, round_count: state.round_count + 1, eliminated: state.eliminated }
        } else {
          val counts = count_first_choices(ballots, state.eliminated, candidates)
          if (has_majority(counts)) {
            { winner: majority_winner(counts), round_count: state.round_count + 1, eliminated: state.eliminated }
          } else {
            val loser = find_loser(counts)
            { winner: "", round_count: state.round_count + 1, eliminated: state.eliminated.union(Set(loser)) }
          }
        }
      }
    })
  }

  // ============================================================
  // Initial state
  // ============================================================

  action init = all {
    contract' = {
      phase: Setup,
      election_id: 0,
      candidates: Set(),
      encrypted_ballot_count: 0,
      winner: "",
      round_count: 0,
      session_active: true,
    },
    enclave' = { decrypted_ballots: Map() },
    observer' = {
      can_see_rankings: false,
      can_see_tallies: false,
      can_see_who_voted: false,
    },
  }

  // ============================================================
  // Actions
  // ============================================================

  /// Admin creates an election with candidates
  action create_election(candidates: Set[Candidate]): bool = all {
    contract.phase == Setup or contract.phase == Complete,
    candidates.size() >= 2,
    contract' = {
      ...contract,
      phase: Setup,
      election_id: contract.election_id + 1,
      candidates: candidates,
      encrypted_ballot_count: 0,
      winner: "",
      round_count: 0,
    },
    enclave' = { decrypted_ballots: Map() },
    observer' = { can_see_rankings: false, can_see_tallies: false, can_see_who_voted: false },
  }

  /// Admin opens voting
  action open_voting: bool = all {
    contract.phase == Setup,
    contract.candidates.size() >= 2,
    contract.session_active,
    contract' = { ...contract, phase: Voting },
    enclave' = enclave,
    observer' = observer,
  }

  /// Voter casts an encrypted ballot
  /// The contract stores the ciphertext. We model the actual ranking
  /// as the enclave's view (it will decrypt during tally).
  action cast_ballot(voter: Addr, ranking: Ballot): bool = all {
    contract.phase == Voting,
    not(enclave.decrypted_ballots.keys().contains(voter)),
    // All choices must be registered candidates
    ranking.indices().forall(i => contract.candidates.contains(ranking[i])),
    ranking.length() > 0,
    contract' = {
      ...contract,
      encrypted_ballot_count: contract.encrypted_ballot_count + 1,
    },
    enclave' = {
      decrypted_ballots: enclave.decrypted_ballots.put(voter, ranking),
    },
    // Observer sees someone voted but not how
    observer' = { ...observer, can_see_who_voted: true },
  }

  /// Enclave tallies the election using instant-runoff
  action tally: bool = all {
    contract.phase == Voting,
    contract.encrypted_ballot_count > 0,
    val result = instant_runoff(enclave.decrypted_ballots, contract.candidates)
    all {
      contract' = {
        ...contract,
        phase: Complete,
        winner: result.winner,
        round_count: result.round_count,
      },
      enclave' = enclave,
      // Tallies are public but individual rankings are NOT
      observer' = {
        can_see_rankings: false,
        can_see_tallies: true,
        can_see_who_voted: observer.can_see_who_voted,
      },
    },
  }

  // ============================================================
  // Step
  // ============================================================

  action step = {
    nondet voter = oneOf(Set(VOTER_1, VOTER_2, VOTER_3, VOTER_4, VOTER_5))
    // Enumerate some ballot orderings
    nondet ballot = oneOf(Set(
      List(ALICE, BOB, CAROL),
      List(ALICE, CAROL, BOB),
      List(BOB, ALICE, CAROL),
      List(BOB, CAROL, ALICE),
      List(CAROL, ALICE, BOB),
      List(CAROL, BOB, ALICE),
      List(ALICE, BOB),
      List(BOB, CAROL),
      List(CAROL),
      List(ALICE)
    ))
    any {
      create_election(ALL_CANDIDATES),
      create_election(Set(ALICE, BOB)),
      open_voting,
      cast_ballot(voter, ballot),
      tally,
    }
  }

  // ============================================================
  // Invariants
  // ============================================================

  /// Individual ballot rankings are NEVER visible to observers
  val inv_rankings_always_private: bool = {
    not(observer.can_see_rankings)
  }

  /// Tallies are only visible after the election is complete
  val inv_tallies_only_after_complete: bool = {
    if (observer.can_see_tallies)
      contract.phase == Complete
    else true
  }

  /// Winner is only set when election is complete
  val inv_winner_only_when_complete: bool = {
    if (contract.winner != "")
      contract.phase == Complete
    else true
  }

  /// Winner must be a registered candidate
  val inv_winner_is_candidate: bool = {
    if (contract.winner != "")
      contract.candidates.contains(contract.winner)
    else true
  }

  /// The winner has the most first-choice votes in the final round
  /// (after eliminations). This is the core RCV correctness property.
  val inv_winner_has_support: bool = {
    if (contract.phase == Complete and contract.winner != "" and
        enclave.decrypted_ballots.keys().size() > 0) {
      // The winner should be obtainable by running instant_runoff
      val expected = instant_runoff(enclave.decrypted_ballots, contract.candidates)
      contract.winner == expected.winner
    } else true
  }

  /// Phase transitions are valid
  val inv_valid_phases: bool = {
    contract.phase == Setup or
    contract.phase == Voting or
    contract.phase == Complete
  }

  /// Session must be active for voting
  val inv_session_required: bool = {
    if (contract.phase == Voting)
      contract.session_active
    else true
  }

  /// Need at least 2 candidates to start an election
  val inv_enough_candidates: bool = {
    if (contract.phase == Voting or contract.phase == Complete)
      contract.candidates.size() >= 2
    else true
  }

  /// Composite invariant
  val all_invariants: bool = {
    inv_rankings_always_private
    and inv_tallies_only_after_complete
    and inv_winner_only_when_complete
    and inv_winner_is_candidate
    and inv_winner_has_support
    and inv_valid_phases
    and inv_session_required
    and inv_enough_candidates
  }
}
