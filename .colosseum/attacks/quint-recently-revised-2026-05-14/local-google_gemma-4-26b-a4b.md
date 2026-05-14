# Adversarial review: auction.qnt & ranked-choice.qnt — Round B

- Specs under review: `examples/sealed-auction/specs/auction.qnt`, `examples/ranked-choice/specs/ranked-choice.qnt`
- Intent doc: `CLAUDE.md`
- Date: 2026-05-14
- Round: B.local
- Adversary: google/gemma-4-26b-a4b

---

VERDICT (auction.qnt): HOLDS WITH CAVEATS
VERDICT (ranked-choice.qnt): BREAKS

---

## 1. [auction.qnt] Phase-machine bypass: `Resolving` is not a mandatory state

- **Category**: Refactor hazard
- **Severity**: serious
- **Scenario**: A developer refactors the contract to allow a "fast-track" resolution where `resolve` can be called directly from `Bidding`. In the current spec, the `resolve` action (line 185) accepts both `Bidding` and `Resolving`. While this mirrors the Rust code, it means the `Resolving` phase—and its associated invariant `inv_resolving_only_after_deadline` (line 352)—can be entirely bypassed.
- **Why it succeeds**: The phase machine is modeled as a set of valid transitions, but the sequence `Bidding -> Resolving -> Complete` is not enforced as a requirement for reaching `Complete`. The spec allows the shortcut `Bidding -> Complete`. If the business intent of the `Resolving` phase is to provide a period where the deadline has passed but results aren't yet published (for auditing/observability), the spec fails to guarantee this period exists.
- **Suggested defense**: If the `Resolving` phase is a required lifecycle step, add a guard to `resolve` that requires `contract.phase == Resolving`, and ensure the only way to enter `Resolving` is via a transition that respects the deadline.

## 2. [auction.qnt] `inv_resolving_only_after_deadline` is a dormant invariant

- **Category**: Dormant invariant
- **Severity**: advisory
- **Scenario**: The invariant `inv_resolving_only_after_deadline` (line 352) checks that if the phase is `Resolving`, the deadline has passed. However, the only action capable of entering this state is `close_bidding` (line 168), which itself has a guard `block_time >= contract.auction_end`.
- **Why it succeeds**: The invariant is technically satisfied, but it tests nothing that the action guard hasn't already proven. It provides no additional safety coverage and serves only as a redundant check of the `close_bidding` precondition.
- **Suggested defense**: Either remove the invariant to reduce SMT complexity or use it to model a property that *isn't* already guarded by the action (e.g., a property about the observer's view during that phase).

## 3. [auction.qnt] Observer model: `inv_ciphertexts_public` is a tautology

- **Category**: Triviality
- **Severity**: advisory
- **Scenario**: The invariant `inv_ciphertexts_public` (line 342) asserts that if bids exist, the observer flag `current_round_has_revealed_ciphertexts` is true. In the current action set, `submit_bid` (line 145) is the only way to increase `bid_count`, and it immediately sets this flag to `true`.
- **Why it succeeds**: The invariant is structurally tied to the side effects of a single action. It does not model a property of the system's state, but rather mirrors the implementation of `submit_bid`. It would fail to catch a bug where a bid is submitted but the flag is *not* set, yet it doesn't represent a meaningful constraint on the auction logic itself.
- **Suggested defense**: Rephrase as a property of the `ObserverView` relative to the existence of bids in the `ContractState`, independent of the most recent action's side effects.

## 4. [ranked-choice.qnt] Tie-break logic mismatch: Spec picks wrong candidate

- **Category**: Refinement mismatch
- **Severity**: critical
- **Scenario**: The Rust implementation (described in the spec comments, line 52) sorts candidates by `(votes DESC, name ASC)` and then performs a **reverse scan** to pick the first minimum-vote entry. In a tie where Alice and Bob both have 2 votes, the vector is `[(2, "Alice"), (2, "Bob")]`. A reverse scan picks **"Bob"** (the lexicographically largest). However, the spec's `find_loser` function (line 158) uses a `fold` that picks the lexicographically **smallest** name (`lex_lt(c, acc)`).
- **Why it succeeds**: The spec's `inv_deterministic_tiebreak` (line 295) will pass if the enclave picks "Alice", even though the actual Rust contract would have picked "Bob". The formal model is verifying a different tie-breaking rule than the one implemented in the code.
- **Suggested defense**: Update `find_loser` to match the Rust behavior: either use a forward scan on the sorted vector or change the `lex_lt` logic to `lex_gt` to ensure the "last" candidate in a tie is selected.

## 5. [ranked-choice.qnt] Equivalence claim failure: `inv_ballot_integrity` is not "Integrity"

- **Category**: Equivalence-claim verification
- **Severity**: serious
- **Scenario**: The author claims that dropping `ballot_history` and checking the current `ballots` map is structurally equivalent. This is false. The original property (checking `ballots == ballot_history`) enforced **immutability** (once a ballot is set, it cannot change). The new property `inv_ballot_integrity` (line 276) only enforces **validity** (all current ballots are non-empty and from known voters).
- **Why it succeeds**: If a future action `update_ballot` were added to the spec, the new invariant would still pass as long as the updated ballot was non-empty. The original invariant would have correctly flagged this as a violation of integrity. The property has been weakened from a "non-mutation" guarantee to a "format validation" guarantee.
- **Suggested defense**: If immutability is required, the spec must include a `last_ballot` or similar history variable to ensure that once a key is present in the map, its value remains constant across all subsequent steps.

## 6. [ranked-choice.qnt] Bounded universe coverage gap: Denominator exhaustion

- **Category**: Bounded-universe accuracy
- **Severity**: advisory
- **Scenario**: The universe is limited to 2 voters and 3 candidates. While the `BALLOT_UNIVERSE` includes singletons (e.g., `[ALICE]`), the 2-voter limit significantly limits the ability of Apalache to explore complex IRV "exhaustion" paths where a candidate is eliminated and the total number of active ballots (the denominator) shrinks.
- **Why it succeeds**: In a 2-voter scenario, the "shrinking denominator" is trivial. The most complex behavior (where a ballot becomes exhausted and affects the majority threshold of remaining candidates) is barely exercised. The property `inv_monotone_progress` (line 285) might pass simply because the state space is too small to construct a multi-round exhaustion sequence that violates monotonicity.
- **Suggested defense**: Increase the voter universe to at least 4 and use a larger set of permutations in `BALLOT_UNIVERSE` to ensure the "exhaustion" branch is a meaningful part of the SMT search space.

## 7. [ranked-choice.qnt] `inv_monotone_progress` is a test of the action, not a property

- **Category**: Triviality (transition-encoding bug)
- **Severity**: serious
- **Scenario**: `inv_monotone_progress` (line 285) checks the `round_active` map, which is populated exclusively by the `tally` action's `result.trace`. 
- **Why it succeeds**: The invariant is not checking a property of the election; it is checking that the `tally` action correctly implements the IRV algorithm. If the `tally` action is buggy, the invariant will fail; if it's correct, the invariant passes. This makes the invariant a "test" of the action rather than a safety property of the system state. It does not protect against other actions that might corrupt the `round_active` map or the `phase`.
- **Suggested defense**: Separate the "correctness of tally" (which should be a unit test or Kani proof) from the "safety of the state" (the invariant). The invariant should focus on ensuring that no action can ever move the system into a state where `round_active` is inconsistent with the current `winner`.

---

## META

- **Categories attacked**: Refactor hazard (1), Dormant invariant (2), Triviality (2), Tie-break mismatch (1), Equivalence-claim verification (1), Bounded-universe accuracy (1).
- **Total attacks**: 8.
- **Severity distribution**: Critical (1), Serious (3), Advisory (4).
- **Note on coverage**: The review successfully distinguished between the "loose" phase machine in `auction.qnt` and the "mathematically incorrect" tie-break logic in `ranked-choice.qnt`. The most significant finding is the tie-break mismatch, which constitutes a direct failure of the formal model to represent the implementation.