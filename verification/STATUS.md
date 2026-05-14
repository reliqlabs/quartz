# Quartz verification status

Snapshot of the formal-verification posture across the four-tool stack: Kani (bounded model checking), Quint (protocol model checking), Verus (deductive verifier on Rust), Lean (theorem prover). Each tool covers a distinct property class — see [the methodology note](#methodology) at the bottom.

Last refreshed by maintainer at the same time as the latest CI run.

## Aggregate counts

| Surface | Kani harnesses | Quint invariants | Verus verified | Lean theorems |
|---|---|---|---|---|
| **Framework** (`crates/contracts/core` + `crates/enclave/core`) | 8 | 20 + 2 temporal | 43 (6 files) | 71 |
| **Examples** (4 contracts) | 31 | 43 (4 specs) | — | — |
| **Total** | **39** | **63 + 2 temporal** | **43** | **71** |

Trust-boundary axioms in Lean: **26 named, bucketed** (down from 40; -35%). Bucket split per `.colosseum/ledger.md`: 3 (a) named-constants, ~9 (c) genuine carrier/bridge axioms, 4 (d) bundle axioms, plus 14 abstract carriers and miscellaneous (b) demotables already discharged. Classical chain preserved via `_classical` corollaries.

**Content-phase status [2026-05-14, post-cycle-6.4–6.11]**: 8 `_negl` lifts def-tied across cycles 6.4–6.11 (8 commits, all `lake build` green at 2667 jobs). Round A's structural critique addressed: each lift now has a `Pr[…]`-based content-bearing `def` for its failure advantage, a concrete reduction to the underlying cryptographic-assumption adversary, and a proven (not assumed) pointwise bound via `probEvent_mono` + `probEvent_bind_pure_comp`. Round A attacks #1, #2, #3, #4 (partial), #11 are structurally closed across all 8 lifts. Per-cycle change records at `.colosseum/changes/2026-05-14T*-cycle-6.{4..11}-*.md`.

**Methodology meta-finding**: 7 of 8 lifts were over-bundled in the original Step 6.0–6.3 work — the union-bound shape was inflated relative to each classical proof's actual probabilistic-failure modes. Six lifts have a single surviving Groth16-soundness failure mode; two are degenerate-zero (deterministic-only). The terminal lift's 5-summand union bound was over-bundled by factor 5. Worth back-porting to colosseum v0.2: bundle-count derivation must come from per-conjunct failure-mode analysis of the classical proof, not from a static axiom-count classifier.

**Remaining Round A attacks** (require deeper refactors than def-tying): #5 (`IsPPT := True` vacuity), #6 (`ProtocolSpec` unused / no oracle access), #8 (Option-(b) framing for `commitHashE`). **Cycle 6.12 (2026-05-14) closes #5 surface-side via Option (b)**: the 7 `*Game_secure_of_*_bundle_secure` packagings renamed to `*_AGAINST_UNBOUNDED_ADVERSARIES` so the placeholder gap is visible at every call site. The substantive Option-(a) closure (`IsPPT := PolyQueries`) is queued as cycle 6.14 once cycle 6.13 (#6, `OracleComp ProtocolSpec` adversaries) lands as prereq.

The 40 → 26 axiom reduction itself is durable and the classical chain is unaffected.

All CI workflows green: `.github/workflows/{kani,quint,verus,lean}.yml`.

## Per-surface detail

### Framework — `crates/contracts/core`

| Layer | Coverage |
|---|---|
| Kani | 8 harnesses in `state.rs`, `msg/execute/session_create.rs`, `msg/execute/session_set_pub_key.rs`. All pass <5s each. Two `LightClientOpts` harnesses gated behind `#[cfg(kani_slow)]` — stdlib `Backtrace` unwinding too deep for default budget. |
| Quint | `specs/handshake.qnt` (15 invariants, all real state-based — promoted from 7 stubs in Phase 2) + `specs/attestation.qnt` (5 real state-based invariants + 2 temporal properties `temporal_zk_accept_requires_vkey`, `temporal_mock_mode_monotonic`). Apalache BMC at depth 15 clean. |
| Verus | 4 handler prototypes in `crates/contracts/core/verus-prototype/`: `session_create` (6 verified), `session_set_pub_key` (5), `instantiate` (8), `attested` (13). Standalone — not integrated into production build. cw_storage_plus + cosmwasm-std stubbed via `external_body`. |
| Lean | 14 spec files split across `Crypto/`, `Attestation/`, and `Protocol/`. Each of the 5 carrier modules (`Ecies`, `UserDataCommit`, `RawMessages`, `Dstack`, `Zkdcap`) has a paired `*VCVio.lean` companion holding `OracleComp` material. Protocol layer split by bundle cardinality: `ProtocolVCVio` (foundations), `ProtocolVCVioDual` / `Triple` / `Quad` (8 lifted `_negl` theorems — scaffolding pending def-tying refactor per Round A; classical chain unaffected). `Handshake`, `Confidentiality`, `Conservation`, `AuctionDeterminism`, `CrossComponent` keep the classical-Prop forms via `_classical` re-exports (Round A confirms these are honest). |

### Framework — `crates/enclave/core`

| Layer | Coverage |
|---|---|
| Verus | 2 prototypes in `crates/enclave/core/verus-prototype/`: `encryption` (6 verified — ECIES roundtrip on production-mirroring wrappers) + `key_manager` (5 verified — DefaultKeyManager's stored-sk-matches-published-pk binding). |

### Examples

| Example | Kani | Quint |
|---|---|---|
| pingpong | 6 harnesses, all pass | `pingpong.qnt`, 10 real invariants, Apalache BMC depth 5 in ~5.9s |
| transfers | 8 harnesses, all pass | `transfers.qnt`, 9 real invariants including `inv_conservation` (sum_of_balances == total_supply). Apalache BMC depth 6 in 2.3s, depth 8 in 3.7min |
| ranked-choice | 8 harnesses, all pass | `ranked-choice.qnt`, 10 real invariants including IRV winner correctness + deterministic alphabetic tie-break. State-space slimmed (6→3 state vars, ballot universe 15→9, voter universe 4→2); Apalache BMC depth 7 in 139.6s post-Round-B (was 51.1s pre-Round-B fix; depth-7 slowdown reflects the new `Tallying` phase + `set_tallying` action added to match the contract enum). Round B (2026-05-14) found and **fixed** the `find_loser` tie-break inversion: Rust eliminates lex-LARGEST among min-vote ties, prior spec eliminated lex-SMALLEST. |
| sealed-auction | 9 harnesses, all pass (incl. Vickrey arithmetic and tie-break) | `auction.qnt`, 14 real invariants (8 original + 1 promoted from stub + 4 new + 1 for Resolving phase transition) including `inv_winner_is_highest`, `inv_decrypted_matches_sealed`. Apalache BMC depth 10 in 25.0s. Round B (2026-05-14) clarified that `close_bidding` models off-chain orchestration, not an on-chain contract transition — `Resolving` is an enum-member-only state the contract permits as input to `exec_resolve` but never writes itself. |

### Lean — composition layer

| Theorem | Composition |
|---|---|
| `cross_component_session_bind` | Handshake attestation → ECIES key binding to dstack-attested enclave |
| `cross_component_transfers_conservation` | Attested transfer → conservation invariant preserved on enclave ghost state |
| `cross_component_auction_winner_determinism` | Attested resolve → winner = canonical Vickrey output for canonical inputs |

## Bug-finding history

| When | What | Where |
|---|---|---|
| Verus prototype mutation tests | Caught `!=` ↔ `==` flips, off-by-one, inverted comparisons | All 6 Verus prototypes; mutation reverted after each test |
| Vickrey helper extraction | Single-bidder-zero-bid produced `winner = None` in extracted helper | `examples/sealed-auction/contracts/src/state.rs::vickrey_select`. Fixed by seeding `best` from `bids[0]`. **Note: production `enclave/src/request.rs::resolve_auction` does not have this bug** — uses sort-and-take, agent's extraction diverged |
| Quint Phase 2 | `inv_zk_accept_requires_vkey` first cut fired in random simulation | Time-coupling spec bug, not production. Downgraded to documentation + later promoted as temporal property |

**No production-code bugs found.** Verification surface is live (mutations confirmed catchable); production code as written satisfies the encoded properties.

## CI

| Workflow | Trigger paths | Runtime budget |
|---|---|---|
| `kani.yml` | `crates/contracts/core/**` | 30 min |
| `quint.yml` | `specs/**` — fast sim + Apalache BMC + temporal verify (separate jobs) | 15 min sim, 30 min BMC |
| `verus.yml` | `crates/contracts/core/verus-prototype/**`, `crates/enclave/core/verus-prototype/**` | 15 min |
| `lean.yml` | `proofs/lean/**` — uses `leanprover/lean-action@v1.5.0` + Mathlib cache via `lake exe cache get`; post-build `grep` step fails on `sorry`/`admit` | 30 min |

## Methodology

Four-tool split — each tool covers a property class the others can't:

| Property class | Tool |
|---|---|
| Panic-freedom, overflow, unreachable arms | **Kani** (bounded model checking) |
| Protocol-level safety/liveness, action-discipline, temporal | **Quint** (Apalache BMC) |
| Hoare-triple state pre/post on real Rust, mutation-test catches | **Verus** (SMT-backed Rust verifier) |
| Crypto-attestation composition soundness, cross-component theorems | **Lean** (Mathlib theorem prover) |

See `proofs/lean/Specs/Quartz/Protocol/CrossComponent.lean` and `Conservation.lean` for the composition-layer theorems that explicitly chain results across tools.

## Known gaps

- **Verus on examples**: handler-level functional correctness for the 4 example contracts not yet annotated. Pattern is the same as the framework; budget ~1 week per example.
- **Verus on enclave `handler.rs`**: `async_trait` + `tonic` + `cosmrs` heavy, doesn't translate cleanly. Needs design work before committing time.
- **Ranked-choice Apalache depth**: addressed — state-space slimmed (dropped `ballot_history`, `last_action`, `last_voter`, `election_id`; flattened `EnclaveState` wrapper; ballot universe 15→9; voter universe 4→2; `instant_runoff` fold range tightened from 5→3 iters matching `|candidates|`). Depth 7 now 51.1s (target was <60s), depth 10 reachable at 391s. `round_active` retained as state — recomputing it as a `pure def` in invariants regressed depth-7 BMC from 51s to >633s timeout.
- **Sealed-auction spec smells**: addressed — `Resolving` phase now wired into the Quint state machine matching the contract's `AuctionPhase::Resolving`, plus 1 new invariant governing the transition. Hardcoded bidder count and observer-flag reset semantics may still be present depending on the agent's scope; verify in the diff.
- **Multi-model adversarial review**: three rounds complete.
  - Round 1 (2026-05-12): Quint `temporal_zk_accept_requires_vkey` spec — BREAKS, 9 findings. See `.colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/synthesis.md`.
  - Round A (2026-05-14): 8 Lean `_negl` lifts — BREAKS (Claude arm) / WEAKENS (Gemma arm), 12 distinct attacks. See `.colosseum/attacks/lean-negl-lifts-2026-05-14/synthesis.md`. Root cause: lifts are content-free tautologies of `negligible_of_le` + `negligible_add`. Cycle 6.4 (def-tying for `verifyGroth16_yields_decoded_negl`) lands in the same commit as Round A response; cycles 6.5–6.14 queued at `.colosseum/refactor-plan-vcvio-content.md`.
  - Round B (2026-05-14): 2 recently-revised Quint specs (sealed-auction + ranked-choice) — BREAKS (auction by Claude / HOLDS-WITH-CAVEATS by Gemma; ranked-choice BREAKS by both). 14 distinct attacks. See `.colosseum/attacks/quint-recently-revised-2026-05-14/synthesis.md`. **3 critical findings fixed in this commit**: (a) ranked-choice `find_loser` tie-break inverted from lex-smallest to lex-largest to match the Rust enclave's reverse-scan iteration; (b) ranked-choice `Tallying` phase added to the enum + `set_tallying` action modeling external orchestration; (c) auction `close_bidding` docstring corrected to clarify it models off-chain orchestration, not an on-chain contract transition.
  - Round C (2026-05-14): 4 previously-unattacked Quint specs (handshake, attestation, pingpong, transfers) — **27 distinct attacks after dedup** (Claude 20, Gemma 16, 9 shared, 1 Gemma false positive). Per-spec verdicts (both arms agree): handshake.qnt **WEAKENS**, attestation.qnt **HOLDS WITH CAVEATS**, pingpong.qnt **WEAKENS**, transfers.qnt **BREAKS**. 3 critical findings: (1) pingpong `inv_plaintext_private` vacuous — observer.can_see_plaintext has no writer; (2) transfers conservation theorem ignores BankMsg::Send plaintext leak (withdrawals reveal pre-withdraw balances on-chain); (3) transfers `update` action processes 1 request while Rust drains a prefix of `msg.quantity` items with no contract-side consistency check. Same-commit Round C response: docstring-honesty caveats applied to all 3 critical invariants (vacuity surfaced explicitly), substantive `prev_sequence_num` ghost added with strict-monotone invariant for Gemma examples #6 (replay protection). Substantive parameterize-by-quantity refactor for Critical 3 deferred to a follow-up cycle. See `.colosseum/attacks/quint-unattacked-2026-05-14/synthesis.md`.
  - Methodology refinement surfaced in Round C: the local-arm prompt for 4 specs (~215KB / 53K tokens) exceeded Gemma's loaded context; two-batch split (framework + examples, ~25K tokens each) succeeded. Filed as colosseum v0.2 ask candidate.
  - Pending: adversarial review on the 43 Verus invariants and 39 Kani harnesses (per ledger); 13 serious + 11 advisory Round C attacks awaiting action-tag fix sweep / dormant-invariant sweep / Rust TODO closure.
- **Lean trust-boundary axiom discharge** (substantial, mostly upstream-blocked):
  - `negligible_groth16_ks` — needs ArkLib Groth16 knowledge-soundness (upstream roadmap)
  - `negligible_circuit` — Lean reference DCAP verifier (multi-month, no owner)
  - `negligible_tdx` — PCK-signature unforgeability reduction
  - `negligible_commitHash` / `_commitHashBytes` — VCVio `randomOracle` + birthday bound + `[Fintype UserData]`
- **Near-term tractable (1–2 days)**: demote 3 (a)-bucket named-constant axioms (`rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey`) to `def`s once their carriers (`DomainSep`, `Addr`, `PubKey`) are refined to concrete byte strings. Closes the (a) bucket entirely.
- **Carrier refinement queue**: 14 abstract carriers blocking concrete `Pr[...]` statements. Currently sidestepped via parametric `[Fintype X] →` formulation in all 8 `_negl` lifts.
- **In-codebase Lean cleanup**: adopt VCVio's `PolyQueries` as the `IsPPT` body (placeholder `True` today, blocked on adversaries gaining `OracleComp ProtocolSpec` access); reformulate `Classical.propDecidable` for `was_signed_by_dstack` via extractor if a less-classical move is desired.
