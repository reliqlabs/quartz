# Multi-model adversarial synthesis: 2 recently-revised Quint specs (Round B)

- Specs under review:
  - `examples/sealed-auction/specs/auction.qnt` (~490 lines, 14 invariants, `Resolving` phase recently wired)
  - `examples/ranked-choice/specs/ranked-choice.qnt` (~473 lines, 10 invariants, state-space recently slimmed)
- Intent docs: `examples/{sealed-auction,ranked-choice}/contracts/src/{state.rs,contract.rs}` + `enclave/src/request.rs` for each
- Reviewed at: 2026-05-14
- Adversaries: **Claude** (subagent, file access, Opus 4.7 / 1M context) + **Gemma 4 26B** (local via LM Studio, full context inlined)
- Result: 14 distinct attacks after dedup; 3 critical, 7 serious, 4 advisory

This synthesis is orchestrator output. The per-model reports (`claude.md`, `local-google_gemma-4-26b-a4b.md`) are persisted verbatim. Orchestrator summarizes overlap and divergence; it does not add, weaken, or re-author findings.

---

## Verdict aggregate

| Adversary | auction.qnt | ranked-choice.qnt | Total attacks | Crit | Serious | Advisory |
|---|---|---|---|---|---|---|
| Claude (file access) | **BREAKS** | **BREAKS** | 12 | 3 | 6 | 3 |
| Gemma 4 26B (local) | HOLDS WITH CAVEATS | **BREAKS** | 8 | 1 | 3 | 4 |
| **Cross-family agreement** | mixed | **BREAKS** | 3 shared themes | 1 | 2 | — |

The two arms agree on ranked-choice (BREAKS). On auction, Claude saw critical drift (the invented `close_bidding` action) that Gemma framed as a refactor hazard — the disagreement is real but largely about severity, not existence: both arms flag the `Resolving`-phase machinery as suspect, Claude judges it more harshly.

---

## The headline finding

**Both arms unique-and-critical: ranked-choice `find_loser` inverts the Rust tie-break direction** (Claude #1, Gemma #4).

The Rust enclave at `examples/ranked-choice/enclave/src/request.rs:93` sorts the count vector by `(votes DESC, name ASC)`, then traverses *backwards* to find the min-vote entry. Backwards through a name-ASC run yields the **lexicographically largest** name first. The Quint `find_loser` at `ranked-choice.qnt:182-190` picks the **lexicographically smallest** — the inverse direction.

**Concrete reproducible divergence**: `create_election(Set(ALICE, BOB))` → voter 1 casts `[ALICE]`, voter 2 casts `[BOB]`. Counts ALICE=1, BOB=1; no majority; elimination must run.
- **Rust**: eliminates BOB → winner ALICE.
- **Quint**: eliminates ALICE → winner BOB.

The Quint spec models a different protocol from the implementation. `inv_winner_satisfies_irv` is hollow because the same buggy `find_loser` is used by both `instant_runoff` (spec semantics) and `inv_deterministic_tiebreak` (the check) — the spec is internally consistent with itself but inconsistent with the Rust. Apalache cannot detect this without an oracle.

The bug propagates from a docstring reasoning error at `ranked-choice.qnt:176-181`: the comment correctly describes the Rust as "scan from the back, pick the first min-vote entry" but then incorrectly concludes "i.e. the lexicographically smallest name among the losers." Scanning backwards through a name-ASC-sorted run yields the largest name first, not the smallest. The implementation matched the wrong conclusion. Fix is one line.

**This is the load-bearing example of "verified the wrong thing"**: every formal tool reported green, but the spec and implementation compute different winners.

---

## Shared findings — surfaced by both adversaries

### S1. Ranked-choice tie-break direction (the headline; see above)

- **Claude attack #1**, **Gemma attack #4**: both flag CRITICAL.
- **Orchestrator assessment**: identical finding, identical proposed fix (flip the predicate in `find_loser`).
- **Severity** (orchestrator's call): **critical**, confirmed cross-family.

### S2. `inv_ballot_integrity` equivalence claim is wrong

- **Claude attack #3** (serious): the old invariant was a *temporal correspondence* between `ballots` and `ballot_history`; the new form is a stateless type predicate (universe-membership + non-empty). A buggy `cast_ballot` that allowed overwriting an existing ballot with a different non-empty ballot from a known voter would *still* satisfy the new invariant.
- **Gemma attack #5** (serious): identical observation, slightly different framing. Old form enforced **immutability**; new form enforces **validity**. The structural equivalence claim relies on the *current* `cast_ballot` body being correct — but the point of invariants is to detect when the body becomes incorrect.
- **Orchestrator assessment**: same finding, both arms propose the same alternative: either rename to `inv_ballot_well_formed` + retract the docstring equivalence claim, or re-introduce a ghost history variable. Severity: **serious**.

### S3. `inv_resolving_only_after_deadline` is dormant/brittle

- **Claude attack #5** (serious): the invariant reads live state where the rest of the spec uses captured-at-action-time bookkeeping (`last_action == ActVerifyZk` pattern from Round 1 S1). One new action — e.g. `extend_auction_end` for anti-sniping (a feature already implied by `CLAUDE.md`'s BidBoard mention) — and the invariant becomes ill-formed.
- **Gemma attack #2** (advisory): the invariant is technically satisfied but adds no coverage beyond what `close_bidding`'s own guard already enforces.
- **Orchestrator assessment**: Claude's framing is sharper (it identifies the action-tag-vs-state-only brittleness pattern from Round 1 S1; same fix applies). Gemma sees the redundancy; Claude sees the redundancy *plus* the refactor hazard. Severity: **serious** (Claude's framing carries more weight given the cross-round pattern).

---

## Unique findings per adversary

### Unique to Claude (file access, deeper analysis)

| # | Spec | Category | Severity | One-line |
|---|---|---|---|---|
| Claude #2 | ranked-choice | Phase-machine completeness | **critical** | `Tallying` phase silently dropped — same pattern the auction `Resolving` revision was meant to fix |
| Claude #4 | auction | Phase-machine over-specification | **critical** | `close_bidding` is an invented action with no Rust counterpart — `Resolving` is reached via off-chain orchestration the Quint spec does not model |
| Claude #6 | auction | Dormant invariant | serious | `inv_no_premature_reveal`'s `last_action == DidResolve` guard goes dormant after one tick |
| Claude #7 | auction | Spec-vs-implementation drift | serious | Quint's `Set.fold` is unspecified-order; Rust's stable sort + `Map<&Addr, ...>` iteration is deterministic by lex-smallest-address. No Quint analog for the Kani-verified tie-break determinism |
| Claude #8 | auction | Observer model partial coverage | serious | Bidder-identity disclosure is not modeled; the privacy boundary (amount vs identity) is implicit |
| Claude #9 | both | Admin authorization unmodeled | serious | Neither spec models a `caller` or admin gate; admin-only actions are callable by anyone in the spec's state space |
| Claude #10 | ranked-choice | Bounded-universe accuracy | serious | The Quint `cast_ballot` validates registered-candidates at submit; the Rust contract has no such gate (the enclave filters at tally) — spec models a tighter submission than the implementation |
| Claude #11 | auction | Bounded-universe nondet limitation | advisory | Pre-bound per-sponsor amounts in `step` prevent verification of decryption-result invariance across re-invocations |
| Claude #12 | auction | Dormant invariant | advisory | `inv_session_required` is vacuous — `session_active` is constant-true; no action invalidates the session |

**Pattern**: Claude's unique findings cluster around (a) spec-vs-implementation drift surfaced by cross-file reading of the Rust contract + enclave + verification artifacts, and (b) action-tag refactor hazards (Round 1 S1 carryover, multiple instances within a single spec). File access made the cross-file pattern available; large context held the multi-file evidence.

### Unique to Gemma (local, prompt-inlined)

| # | Spec | Category | Severity | One-line |
|---|---|---|---|---|
| Gemma #1 | auction | Refactor hazard | serious | The `Bidding -> Complete` shortcut bypasses `Resolving` entirely — phase-machine doesn't *require* `Resolving` if business intent demands it |
| Gemma #3 | auction | Triviality | advisory | `inv_ciphertexts_public` mirrors `submit_bid`'s side-effect; it can't catch a bug where a bid is submitted but the flag is *not* set |
| Gemma #6 | ranked-choice | Bounded-universe accuracy | advisory | 2-voter limit barely exercises IRV exhaustion paths; `inv_monotone_progress` may pass trivially due to state-space smallness |
| Gemma #7 | ranked-choice | Triviality / transition-encoding | serious | `inv_monotone_progress` checks `round_active`, which is populated only by `tally`'s `result.trace` — so the invariant is a test of `tally`'s correctness, not a property of system state |

**Pattern**: Gemma's unique findings focus on *invariant-shape critiques* — does the invariant actually express a constraint on state, or does it just re-state what the action body does? This is complementary to Claude's spec-vs-implementation focus. Gemma found two trivality-cluster issues (#3, #7) that Claude did not surface; Claude found multiple cross-file drifts that Gemma's inlined-context could not see.

---

## Severity-weighted unified attack list

After dedup across 12 + 8 = 20 raw attacks, **14 distinct attacks**:

**Critical** (3):
1. **`find_loser` tie-break inversion** (S1; Claude #1 / Gemma #4) — concrete reproducible divergence between spec and Rust
2. **Ranked-choice `Tallying` phase unmodeled** (Claude #2)
3. **Auction `close_bidding` is invented** (Claude #4)

**Serious** (7):
4. **`inv_ballot_integrity` equivalence claim wrong** (S2; Claude #3 / Gemma #5)
5. **`inv_resolving_only_after_deadline` action-tag brittleness** (S3; Claude #5 / Gemma #2)
6. **`inv_no_premature_reveal` dormant after one tick** (Claude #6)
7. **`inv_winner_is_highest` no deterministic-tie-break analog to Kani** (Claude #7)
8. **Auction observer model partial coverage** (Claude #8)
9. **Both specs lack admin authorization** (Claude #9)
10. **Ranked-choice ballot universe over-tight** (Claude #10)
11. **`inv_monotone_progress` is a tally-test, not a state property** (Gemma #7)

**Advisory** (4):
12. **`inv_ciphertexts_public` mirrors action side-effect** (Gemma #3)
13. **Auction per-sponsor nondet limitation** (Claude #11)
14. **`inv_session_required` vacuous** (Claude #12) + ranked-choice voter-universe smallness (Gemma #6) — closely related, both grouped here

---

## Coverage analysis

| Attack category | Claude | Gemma |
|---|---|---|
| Cross-file spec-vs-impl reading | ✓✓ deep | — |
| Tie-break direction analysis | ✓ | ✓ |
| Equivalence-claim verification | ✓ | ✓ |
| Phase-machine completeness | ✓✓ (both specs) | ✓ (auction only) |
| Dormant invariant detection | ✓✓ (3 instances) | ✓ (1 instance) |
| Invariant-shape / triviality critique | — | ✓✓ |
| Action-tag refactor hazard | ✓✓ (Round 1 S1 pattern) | — |
| Bounded-universe analysis | ✓✓ | ✓ |
| Observer / privacy model | ✓ | — |
| Admin authorization | ✓ | — |

**Claude's coverage advantage** comes from file access + cross-file evidence chaining. Multiple Claude findings cite specific Rust line numbers in `contract.rs` + `state.rs` + `request.rs` and Kani harnesses in `state.rs` simultaneously. This kind of evidence is not available to a prompt-inlined arm without the orchestrator picking which files to inline (which would bias the review).

**Gemma's coverage contribution** is the invariant-shape critique. Gemma's #3 (`inv_ciphertexts_public` mirrors submit_bid's side effects) and #7 (`inv_monotone_progress` tests `tally`'s correctness rather than state safety) are *meta-invariant* findings — they critique the *shape* of the invariant, not its target. These are findings Claude did not surface, and they're qualitatively different from the spec-vs-impl drifts.

**Methodology meta-finding reinforced**: Round A established that file-access + large-context is necessary for theorem-signature analysis. Round B reinforces it for spec-vs-implementation drift. The complementary finding: **prompt-inlined arms excel at invariant-shape critique** — and a methodology that drops the prompt-inlined arm would lose this complementary depth.

---

## Recommended actions, by leverage

1. **Fix the ranked-choice tie-break direction (1-line change)**. The Rust eliminates lex-LARGEST; flip Quint's `find_loser` predicate from `lex_lt(c, acc)` to `lex_lt(acc, c)`. Update the docstring at lines 176-181 to remove the "smallest" claim. Re-run Apalache after the fix — additional counter-examples may surface in 3-candidate IRV traces if more elimination ties become reachable. **This is the load-bearing example of "the verified property was wrong"; it should ship before any other work that depends on the ranked-choice spec.**

2. **Address the `Resolving`/`Tallying` mirror pattern across both specs**. Both auction and ranked-choice have a phase-enum vs phase-action mismatch — auction *over*-models (`close_bidding` invented), ranked-choice *under*-models (`Tallying` dropped). The consistent fix: treat `Resolving` and `Tallying` as **external nondeterministic phase inputs**, not on-chain transitions. Document the off-chain orchestration explicitly. Mirror the same wording across both specs.

3. **Apply the action-tag pattern uniformly within auction.qnt**. `inv_resolve_after_deadline` and `inv_no_late_bids` use `last_action == ...`; `inv_resolving_only_after_deadline` and `inv_no_premature_reveal` do not. Make the pattern consistent — the same fix applies to all action-time-of-trigger invariants. Reframes Round 1's S1 as a recurring methodology lesson: **state-only guards become brittle as actions are added; action-tag predicates are the right shape**.

4. **Retract the `inv_ballot_integrity` equivalence claim** in the docstring. The rephrase is *useful* (it caught the universe-membership and non-empty conditions) but it is *not equivalent* to the original temporal correspondence. Rename to `inv_ballot_well_formed` and document the scope reduction.

5. **Strengthen the admin-authorization model** in both specs, OR document explicitly that admin authorization is out of scope and modeled at the `quartz-contract-core` layer. Either way the spec's silence is misleading.

6. **Fold Round B's findings into the v0.2 PR currently with the colosseum agent**. The methodology asks should include a "verify spec actions correspond to contract execute branches" check — Claude's attack #4 (invented `close_bidding`) is a methodology gap, not just a Quartz gap. The fix-pattern (treat enum-member-only states as external nondeterministic inputs) is a generalizable methodology move worth surfacing.

---

## What does NOT change

- The verification posture overall is unchanged: the form-phase Lean reduction stands; the classical chain is honest; CI is green.
- The Round A findings on the Lean `_negl` lifts stand; Round B is a separate axis (Quint spec correctness, not Lean lift content-vacuity).
- The CI workflows do not need updating — the specs still typecheck and pass Apalache; the issues here are semantic, not syntactic.

## What this means for the verification trust posture

Two specs in the example set are now known to encode the wrong property in places — ranked-choice's tie-break direction most concretely. The other 4 (handshake, attestation, pingpong, transfers) have *not* had Round B-style cross-file adversarial review. **Round C should run on those four** before any production-trust claim. The ledger's per-spec verification status entries should be amended with a "Round B status" column.

Compounding observation: Round A found Lean lifts were content-free; Round B found Quint specs were content-wrong-in-places. The pattern across both: **automated tools (Apalache, Lean kernel) check that the encoded property holds; they do not check that the encoded property is the *intended* one.** Adversarial review is the only existing mechanism in the methodology that does. **The methodology cannot operate without it.**
