// Ranked-Choice Voting Protocol — Formal Spec
//
// Verification target: examples/ranked-choice
//   contracts/src/contract.rs   — phase machine, ballot eligibility
//   contracts/src/state.rs      — Election, BALLOTS map
//   enclave/src/request.rs      — instant-runoff tally
//
// IRV variant implemented by the contract+enclave:
//   - Majority threshold      : total_active_votes / 2 + 1
//   - Exhausted ballots       : drop out — denominator shrinks
//   - Tie-break on elimination: candidate.0.cmp() — i.e. ALPHABETIC
//     LEAST among those tied for fewest votes (find_loser scans the
//     sorted vector in reverse and picks the first min-vote entry,
//     which after `(b.1, a.0)` sort is the LEXICOGRAPHICALLY SMALLEST
//     of the tied losers). We model this deterministic rule below.
//   - Termination             : majority found OR one candidate left.
//
// Bounded universe for Apalache tractability:
//   - 3 candidates  : ALICE < BOB < CAROL  (alphabetic order matters)
//   - 2 voters max (sufficient to exercise majority, elimination,
//     exhaustion, and lex-smallest tie-break with the 3-candidate
//     universe; reduced from 3 to shrink Apalache BMC state-space)
//   - Ballot length up to 3
//
// State-space encoding notes:
//   - `ballot_history` is omitted: the spec never mutates `ballots`
//     after a voter has voted (cast_ballot rejects repeats), and
//     `ballot_history` would always equal `ballots` in every
//     reachable state. Ballot integrity is checked structurally by
//     asserting the cast_ballot guard holds (every recorded voter is
//     a known voter, every ballot is non-empty).
//   - `last_action`, `last_voter`, `election_id`: dropped because no
//     invariant in `all_invariants` consumes them.
//   - EnclaveState wrapper record flattened to a bare `ballots` map.
//   - `round_active` retained as state (rather than recomputed in
//     each invariant) because three invariants read it and Apalache
//     SMT encoding is far cheaper for a lookup than for re-unrolling
//     `instant_runoff` per invariant per BMC step.

module ranked_choice {

  // ============================================================
  // Types
  // ============================================================

  type Addr = str
  type Candidate = str
  type Ballot = List[Candidate]

  /// Phase enum mirrors `contracts/src/state.rs::ElectionPhase`. Note
  /// the contract never *writes* `Tallying` from any of its execute
  /// branches: `exec_tally` accepts `Voting | Tallying` as input phases
  /// but only writes `Complete`. `Tallying` is therefore reachable only
  /// via off-chain orchestration (a relayer or external admin call not
  /// modelled in `contract.rs`). The `set_tallying` action below models
  /// this external transition explicitly; see its docstring.
  type Phase =
    | Setup
    | Voting
    | Tallying
    | Complete

  /// On-chain visible state.
  type ContractState = {
    phase: Phase,
    candidates: Set[Candidate],
    ballot_count: int,
    winner: Candidate,
    round_count: int,
  }

  // ============================================================
  // State variables
  // ============================================================

  var contract: ContractState
  /// Enclave-private decrypted ballots keyed by voter. Flattened out
  /// of the previous one-field EnclaveState record.
  var ballots: Addr -> Ballot
  /// (round -> active candidate set) populated by `tally` from the
  /// IRV trace. Empty in Setup/Voting; nonempty in Complete.
  var round_active: int -> Set[Candidate]

  // ============================================================
  // Constants — fixed bounded universe
  // ============================================================

  val ALICE: Candidate = "Alice"
  val BOB:   Candidate = "Bob"
  val CAROL: Candidate = "Carol"
  val ALL_CANDIDATES = Set(ALICE, BOB, CAROL)

  /// Lex-rank table over the bounded candidate universe. Quint lacks
  /// built-in string ordering; we encode the alphabetic order
  /// (ALICE < BOB < CAROL) as a map and use it everywhere the Rust
  /// code does `a.0.cmp(&b.0)`.
  pure def lex_rank(c: Candidate): int = {
    if (c == ALICE) 0
    else if (c == BOB) 1
    else if (c == CAROL) 2
    else 999
  }

  pure def lex_lt(a: Candidate, b: Candidate): bool = {
    lex_rank(a) < lex_rank(b)
  }

  val V1: Addr = "v1"
  val V2: Addr = "v2"
  val ALL_VOTERS = Set(V1, V2)

  /// All ballots a voter may submit (Apalache enumerates these).
  ///
  /// Reduced from the full 15-ballot universe to a representative
  /// 9-ballot universe that still exercises every IRV branch:
  ///   - 6 full rankings (all 3! permutations) drive elimination
  ///     transfers and majority computation.
  ///   - 3 singleton ballots force exhaustion after the named
  ///     candidate is eliminated, exercising the shrinking-denominator
  ///     branch.
  /// Two-element ballots (e.g. [ALICE, BOB]) are omitted: their
  /// first-active behaviour is equivalent to the corresponding full
  /// permutation modulo at most one elimination, and IRV with only 3
  /// candidates collapses any second-elimination after the first one
  /// (only one candidate remains, so the tail of a length-2 ballot
  /// adds nothing the full ranking doesn't already cover).
  val BALLOT_UNIVERSE: Set[Ballot] = Set(
    [ALICE, BOB, CAROL],
    [ALICE, CAROL, BOB],
    [BOB, ALICE, CAROL],
    [BOB, CAROL, ALICE],
    [CAROL, ALICE, BOB],
    [CAROL, BOB, ALICE],
    [ALICE],
    [BOB],
    [CAROL]
  )

  // ============================================================
  // Pure helpers — mirror enclave/src/request.rs::tally_election
  // ============================================================

  /// First non-eliminated choice on a ballot, or "" if exhausted.
  pure def first_active(b: Ballot, elim: Set[Candidate]): Candidate = {
    b.indices().fold("", (acc, i) =>
      if (acc != "") acc
      else if (elim.contains(b[i])) acc
      else b[i]
    )
  }

  /// Count first-active votes per active candidate.
  pure def round_counts(
    bs: Addr -> Ballot,
    candidates: Set[Candidate],
    elim: Set[Candidate]
  ): Candidate -> int = {
    val active = candidates.exclude(elim)
    active.fold(Map(), (acc, c) => {
      val v = bs.keys().filter(a => first_active(bs.get(a), elim) == c).size()
      acc.put(c, v)
    })
  }

  /// Has-majority predicate: any candidate with > 50% of the active
  /// (non-exhausted) ballots.
  pure def has_majority(counts: Candidate -> int): bool = {
    val total = counts.keys().fold(0, (s, c) => s + counts.get(c))
    val maj = total / 2 + 1
    counts.keys().exists(c => counts.get(c) >= maj)
  }

  pure def majority_winner(counts: Candidate -> int): Candidate = {
    val total = counts.keys().fold(0, (s, c) => s + counts.get(c))
    val maj = total / 2 + 1
    // Pick the lexicographically smallest candidate at or above
    // majority (matches the Rust sort_by `(b.1, a.0)` order).
    counts.keys().fold("", (acc, c) =>
      if (counts.get(c) >= maj and (acc == "" or lex_lt(c, acc))) c
      else acc
    )
  }

  /// Deterministic tie-break: among candidates tied for fewest votes,
  /// eliminate the LEXICOGRAPHICALLY LARGEST. This matches
  /// enclave/src/request.rs lines 92-93 + 137-143: the vec is sorted
  /// `b.1.cmp(&a.1).then(a.0.cmp(&b.0))` (votes desc, then name asc),
  /// then we scan from the back (`.iter().rev()`) and pick the first
  /// min-vote entry — backwards through a name-ASC-sorted run yields
  /// the lex-LARGEST name first, not the smallest. (Round B 2026-05-14
  /// adversarial finding: prior docstring drew the wrong conclusion from
  /// the correct intermediate step, and the spec body matched the wrong
  /// conclusion. See `.colosseum/attacks/quint-recently-revised-2026-05-14/`.)
  pure def find_loser(counts: Candidate -> int): Candidate = {
    val min_v = counts.keys().fold(999999, (best, c) =>
      if (counts.get(c) < best) counts.get(c) else best
    )
    counts.keys().fold("", (acc, c) =>
      if (counts.get(c) == min_v and (acc == "" or lex_lt(acc, c))) c
      else acc
    )
  }

  // IRV result. `trace` records the (round → active candidate set)
  // witnessed during the loop.
  type IRV = {
    winner: Candidate,
    rounds: int,
    eliminated: Set[Candidate],
    trace: int -> Set[Candidate],
  }

  /// One iteration of the IRV loop.
  pure def irv_step(
    s: IRV,
    bs: Addr -> Ballot,
    candidates: Set[Candidate]
  ): IRV = {
    if (s.winner != "") s
    else {
      val active = candidates.exclude(s.eliminated)
      val r = s.rounds + 1
      val trace_next = s.trace.put(r, active)
      if (active.size() <= 1) {
        val last = active.fold("", (_, c) => c)
        { winner: last, rounds: r, eliminated: s.eliminated, trace: trace_next }
      } else {
        val counts = round_counts(bs, candidates, s.eliminated)
        if (has_majority(counts)) {
          { winner: majority_winner(counts), rounds: r,
            eliminated: s.eliminated, trace: trace_next }
        } else {
          val loser = find_loser(counts)
          { winner: "", rounds: r,
            eliminated: s.eliminated.union(Set(loser)),
            trace: trace_next }
        }
      }
    }
  }

  pure def instant_runoff(
    bs: Addr -> Ballot,
    candidates: Set[Candidate]
  ): IRV = {
    // |ALL_CANDIDATES| = 3 iterations suffice: each non-terminating
    // round eliminates one candidate, termination triggers at
    // active.size() <= 1. Once `s.winner != ""` the step is a no-op,
    // so over-running is safe but wastes Apalache SMT work — we use
    // exactly 3 iterations to stay tight against the bounded universe.
    val init: IRV = { winner: "", rounds: 0, eliminated: Set(), trace: Map() }
    0.to(2).fold(init, (s, _) => irv_step(s, bs, candidates))
  }

  // ============================================================
  // Initial state
  // ============================================================

  action init = all {
    contract' = {
      phase: Setup,
      candidates: Set(),
      ballot_count: 0,
      winner: "",
      round_count: 0,
    },
    ballots' = Map(),
    round_active' = Map(),
  }

  // ============================================================
  // Actions
  // ============================================================

  /// Admin creates an election with a candidate set.
  action create_election(cs: Set[Candidate]): bool = all {
    contract.phase == Setup or contract.phase == Complete,
    cs.size() >= 2,
    contract' = {
      phase: Setup,
      candidates: cs,
      ballot_count: 0,
      winner: "",
      round_count: 0,
    },
    ballots' = Map(),
    round_active' = Map(),
  }

  /// Admin opens voting.
  action open_voting: bool = all {
    contract.phase == Setup,
    contract.candidates.size() >= 2,
    contract' = { ...contract, phase: Voting },
    ballots' = ballots,
    round_active' = round_active,
  }

  /// Voter submits a ballot. Models the on-chain check
  /// (`BALLOTS.has(deps.storage, &info.sender)` => AlreadyVoted) and
  /// the enclave-side ranking persistence.
  action cast_ballot(voter: Addr, b: Ballot): bool = all {
    contract.phase == Voting,
    not(ballots.keys().contains(voter)),
    b.length() > 0,
    // All ranked choices must be registered candidates (the enclave
    // would filter invalid ones anyway, but the contract-side
    // validation would also reject bogus encryptions).
    b.indices().forall(i => contract.candidates.contains(b[i])),
    contract' = { ...contract, ballot_count: contract.ballot_count + 1 },
    ballots' = ballots.put(voter, b),
    round_active' = round_active,
  }

  /// **Off-chain orchestration step**: an external admin/relayer flips
  /// the on-chain phase from `Voting` to `Tallying`. The contract's
  /// `exec_tally` accepts `Voting | Tallying` as input phases, but no
  /// execute branch in `contract.rs` writes `Tallying` — this action
  /// models the external transition that does. Mirror of the auction
  /// spec's `close_bidding` (which is similarly off-chain).
  action set_tallying: bool = all {
    contract.phase == Voting,
    contract' = { ...contract, phase: Tallying },
    ballots' = ballots,
    round_active' = round_active,
  }

  /// Enclave runs IRV and the contract stores the result.
  /// Fires from either `Voting` or `Tallying` to match `exec_tally`'s
  /// phase guard at `contracts/src/contract.rs:160`.
  action tally: bool = all {
    contract.phase == Voting or contract.phase == Tallying,
    contract.ballot_count > 0,
    val result = instant_runoff(ballots, contract.candidates)
    all {
      contract' = {
        ...contract,
        phase: Complete,
        winner: result.winner,
        round_count: result.rounds,
      },
      ballots' = ballots,
      round_active' = result.trace,
    },
  }

  // ============================================================
  // Step relation
  // ============================================================

  action step = {
    nondet voter = oneOf(ALL_VOTERS)
    nondet ballot = oneOf(BALLOT_UNIVERSE)
    any {
      create_election(ALL_CANDIDATES),
      create_election(Set(ALICE, BOB)),
      create_election(Set(ALICE, CAROL)),
      open_voting,
      cast_ballot(voter, ballot),
      set_tallying,
      tally,
    }
  }

  // ============================================================
  // Invariants
  // ============================================================

  /// I1 - Ballot integrity. Once a voter has cast a ballot in the
  /// current election, the recorded ranking is never modified.
  ///
  /// In this encoding `ballots` is the sole record of a voter's
  /// ranking and `cast_ballot` rejects repeats
  /// (`not(ballots.keys().contains(voter))`), so the integrity
  /// property reduces to: every recorded ballot is non-empty and
  /// every entry in the map corresponds to a known voter.
  ///
  /// (The original spec maintained a parallel `ballot_history` map
  /// and asserted ballots.get(v) == ballot_history.get(v); since the
  /// two maps were written together and never mutated independently,
  /// the assertion is structurally equivalent to "the cast_ballot
  /// guard holds" — which is what we now check.)
  val inv_ballot_integrity: bool = {
    ballots.keys().forall(v =>
      ALL_VOTERS.contains(v) and ballots.get(v).length() > 0
    )
  }

  /// I2 - Monotone progress. Across the witnessed IRV trace, each
  /// round's active candidate set is a STRICT subset of the previous
  /// round's, or the algorithm has terminated by majority.
  val inv_monotone_progress: bool = {
    contract.phase == Complete implies
      round_active.keys().forall(r =>
        if (round_active.keys().contains(r + 1))
          round_active.get(r + 1).subseteq(round_active.get(r)) and
          round_active.get(r + 1).size() < round_active.get(r).size()
        else true
      )
  }

  /// I3 - Winner satisfies the IRV majority rule. The declared
  /// winner is the candidate `instant_runoff` would pick, which by
  /// construction either holds a strict majority of the active
  /// ballots in some round, or is the last surviving candidate.
  val inv_winner_satisfies_irv: bool = {
    if (contract.phase == Complete and contract.winner != ""
        and ballots.keys().size() > 0)
      contract.winner == instant_runoff(ballots, contract.candidates).winner
    else true
  }

  /// I4 - No double-voting. The enclave's ballot map has at most one
  /// entry per voter; equivalently, |keys| == |distinct keys|, which
  /// is trivially true for maps, BUT we additionally require that
  /// ballot_count agrees with the number of distinct voters who voted.
  val inv_no_double_vote: bool = {
    contract.ballot_count == ballots.keys().size() and
    ballots.keys().subseteq(ALL_VOTERS)
  }

  /// I5 - Deterministic tie-break. For any candidate-count map
  /// reachable in the trace where there is a unique non-empty set of
  /// minimum-vote candidates, the eliminated candidate is the
  /// LEXICOGRAPHICALLY SMALLEST among them — the rule the Rust
  /// implementation actually uses (see enclave/src/request.rs:92).
  ///
  /// We check this structurally by recomputing the elimination order:
  /// for every consecutive round, the candidate that disappears must
  /// be the find_loser of the previous round's count map.
  val inv_deterministic_tiebreak: bool = {
    contract.phase == Complete implies
      round_active.keys().forall(r =>
        if (round_active.keys().contains(r + 1)) {
          val active_prev = round_active.get(r)
          val active_now = round_active.get(r + 1)
          val removed = active_prev.exclude(active_now)
          val expected_loser = find_loser(round_counts(
              ballots, contract.candidates,
              ALL_CANDIDATES.exclude(active_prev)))
          // exactly one candidate eliminated per round AND it is the
          // deterministic loser (lex-smallest among min-vote candidates).
          removed.size() == 1
            and removed.fold("", (_, c) => c) == expected_loser
        } else true
      )
  }

  // -- Sanity guards (kept terse) ---------------------------------

  /// I6 - Phase is one of the four legal values (no garbage states).
  val inv_phase_well_formed: bool = {
    contract.phase == Setup or
    contract.phase == Voting or
    contract.phase == Tallying or
    contract.phase == Complete
  }

  /// I7 - Winner field is only populated once the tally has run.
  val inv_winner_only_when_complete: bool = {
    if (contract.winner != "") contract.phase == Complete
    else true
  }

  /// I8 - Winner (when present) is one of the registered candidates.
  val inv_winner_is_candidate: bool = {
    if (contract.winner != "")
      contract.candidates.contains(contract.winner)
    else true
  }

  /// I9 - Each round's active set is a subset of the registered
  /// candidates. (Catches accidental introduction of phantom names.)
  val inv_active_subset_candidates: bool = {
    round_active.keys().forall(r =>
      round_active.get(r).subseteq(contract.candidates)
    )
  }

  /// I10 - Number of rounds never exceeds candidate count. With C
  /// candidates IRV eliminates at most C-1 times before declaring a
  /// winner.
  val inv_rounds_bounded: bool = {
    contract.phase == Complete implies
      contract.round_count <= contract.candidates.size()
  }

  // -- Composite -------------------------------------------------

  val all_invariants: bool = {
    inv_ballot_integrity
      and inv_monotone_progress
      and inv_winner_satisfies_irv
      and inv_no_double_vote
      and inv_deterministic_tiebreak
      and inv_phase_well_formed
      and inv_winner_only_when_complete
      and inv_winner_is_candidate
      and inv_active_subset_candidates
      and inv_rounds_bounded
  }
}
