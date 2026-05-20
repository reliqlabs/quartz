# Multi-model adversarial synthesis: Kani harness surface (Round E)

- Target: 41 Kani harnesses across 7 files (1666 lines) in `crates/contracts/core/`, `examples/{sealed-auction,pingpong,transfers,ranked-choice}/contracts/src/`. The only spec-class artifact in the verification pyramid that had never been adversarially reviewed prior to this round.
- Reviewed at: 2026-05-20
- Methodology: opencode multi-voice dispatch with cross-family lineup, claude voice via Agent subagent.
- Adversarial lineup (5 voices, all productive):

  | Voice | Channel | Model | Elapsed | Attacks |
  |---|---|---|---|---|
  | Claude (subagent) | Agent | claude-opus-4-7 (file-access) | ~6m | 23 |
  | GPT-5.5 | opencode/openai | openai/gpt-5.5 | 112s | 27 |
  | GPT-OSS | opencode/burnt | burnt/gpt-oss-120b (variant=high) | 48s | 10 |
  | Kimi | opencode/burnt | burnt/kimi-k2-6 (variant=high) | 301s | 16 |
  | Nemotron | opencode/burnt | burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b (variant=high) | 119s | 10 |

Raw total: 86 attacks. Per-voice reports persisted verbatim alongside this synthesis. The user-requested exclusion of `burnt/claude-sonnet-4-6` (Claude family already covered by the Agent subagent) was implemented mid-dispatch; the sonnet error file was deleted before commit.

## Verdict aggregate

| File | Claude | GPT-5.5 | GPT-OSS | Kimi | Nemotron |
|---|---|---|---|---|---|
| msg/execute/session_create.rs | HOLDS-CAV | WEAKENS | WEAKENS | HOLDS-CAV | HOLDS-CAV |
| msg/execute/session_set_pub_key.rs | HOLDS-CAV | WEAKENS | WEAKENS | HOLDS-CAV | HOLDS-CAV |
| core/state.rs (framework) | WEAKENS | **BREAKS** | HOLDS-CAV | WEAKENS | WEAKENS |
| sealed-auction/state.rs | WEAKENS | WEAKENS | HOLDS | HOLDS-CAV | HOLDS |
| pingpong/state.rs | **BREAKS** | **BREAKS** | HOLDS | HOLDS-CAV | WEAKENS |
| transfers/state.rs | **BREAKS** | **BREAKS** | HOLDS | WEAKENS | HOLDS-CAV |
| ranked-choice/verification.rs | WEAKENS | WEAKENS | HOLDS | WEAKENS | HOLDS-CAV |

Claude and GPT-5.5 strongly agree on the load-bearing finding (pingpong + transfers BREAKS, tied to Round C carry-over). GPT-OSS is the outlier (HOLDS on most examples); its narrower lineup of attacks focuses on framework gating issues rather than example-contract gaps. Kimi and Nemotron sit in the middle: WEAKENS on framework, HOLDS-WITH-CAVEATS on examples.

## Critical findings (cross-voice convergent)

### Critical 1 — `kani_slow` LightClientOpts harnesses are CI-invisible

GPT-OSS #1 (critical), Kimi #2/#3 (serious), Nemotron #2 (serious), Claude flagged similarly. Four-of-five voices agree.

`crates/contracts/core/src/state.rs` carries two `#[cfg(kani_slow)]` harnesses for `LightClientOpts::new` (trust-threshold validation and height bounds) that are compiled out under default `cargo kani` runs. The harnesses themselves are well-formed; the gating means the trust-threshold and height-bound properties they assert are not verified continuously. CI configuration at `.github/workflows/kani.yml` does not pass `--cfg kani_slow`.

Compounding issue surfaced by Kimi #2: even if the gating is fixed, the harnesses use `#[kani::unwind(20)]` because `StdError::msg` constructs a `std::backtrace::Backtrace` whose unwinding exceeds the bound. The cfg-suggested workaround `--no-unwinding-checks` truncates the path, so error-return assertions sit on truncated paths and pass vacuously. The fix is not just CI configuration but also replacing `StdError::msg` with a backtrace-free constructor under `#[cfg(kani)]`.

### Critical 2 — Transfers harnesses verify pure helpers that do not exist in the production contract

Claude #2 (critical), Kimi #6 (serious), GPT-5.5 verdict BREAKS on transfers/state.rs. Three voices converge.

`examples/transfers/contracts/src/state.rs` H1-H4 and H8 verify `safe_drain_len`, `checked_sum_withdrawals`, and a deposit accumulator. These functions exist only inside the `#[cfg(kani)]` module. Production `contract.rs::update` at line 194 does `requests.drain(0..msg.quantity as usize)` with no bounds guard, never sums withdrawals, and never accumulates a global deposit total. The harnesses prove properties about code that does not run in production.

This is the Kani-side instance of the Round C critical #17 finding (transfers `update` action processes 1 request while Rust drains a prefix with attacker-controllable `msg.quantity`). The Quint review caught it; the Kani harness suite verifies properties about a phantom safety harness that production does not invoke. Five voices' work on the Kani surface combined fails to add coverage that the Quint surface already covered, because the Kani harnesses are looking at the wrong code.

### Critical 3 — Pingpong harnesses verify struct-field roundtrips with zero coverage of the production overwrite bug

Claude #1 (critical), GPT-5.5 verdict BREAKS, Kimi #11 (advisory), Nemotron #5 (advisory). Four-of-five voices flag this surface as weak; the critical framing is Claude+GPT-5.5.

`examples/pingpong/contracts/src/state.rs` harnesses (`ping_field_roundtrip`, `pong_field_roundtrip`, `ping_pong_pubkey_symmetry`, plus a few constant-equality harnesses) verify that setting and reading struct fields preserves their values. None exercise the production `execute::ping` handler's overwrite semantics that Round C critical pingpong #13 flagged. A re-ping that overwrites a pending pong is invisible to the Kani surface.

### Critical 4 — Round C critical #16 (transfers `BankMsg::Send` plaintext leak) has no Kani coverage

Claude #3, GPT-5.5 implicit in BREAKS verdict.

Production `transfers/contracts/src/contract.rs::update` at lines 201-207 emits `BankMsg::Send { to_address, amount }` for each withdrawal. The recipient address and amount are public chain state; every withdrawal reveals the exact pre-withdraw balance to chain observers. The Kani harness suite has no harness asserting any privacy invariant on the on-chain bank-send disclosure. Round C surfaced this via Quint review; the Kani surface is silent.

## Cross-voice agreement on serious findings

| # | Finding | Voices | Files |
|---|---|---|---|
| S1 | `session_with_pub_key_no_panic` is tautological (no assertion on result; the function body cannot panic anyway) | Kimi #4, Nemotron #1 | state.rs |
| S2 | `HasUserData::user_data()` SHA-256+JSON serialization path has no harness coverage despite being attestation-critical | Kimi #5 | session_create.rs + session_set_pub_key.rs |
| S3 | Fixed-content harness inputs (`contract = "c"`, `pub_key = vec![0x04u8; 33]`) test only one shape | GPT-5.5 #1, Kimi #16, Nemotron #3, Nemotron #4 | session_create.rs + session_set_pub_key.rs |
| S4 | Address-validation pipeline never exercised by harness — production `addr_validate` canonicalises and rejects malformed bech32, harnesses don't test the rejection path | GPT-5.5 #1 area | session_create.rs |
| S5 | Ranked-choice `h_phase_transition_no_skip` checks 3-of-N forbidden transitions, leaving most pairs unverified | Kimi #13 | ranked-choice/verification.rs |
| S6 | Ranked-choice helpers (`candidates_valid`, ballot filtering) are pure mirrors of production logic; production uses `HashSet` directly | Kimi #15 | ranked-choice/verification.rs |
| S7 | Sealed-auction lacks a bid-count invariant harness tying `AuctionRound.bid_count` to `len(SEALED_BIDS)` | Nemotron #8 | sealed-auction/state.rs |

## Net-new findings per voice

### Net-new from GPT-5.5 (27 attacks, the largest set)

- **Raw roundtrip ignores contract field**: `session_create_roundtrip` asserts nonce equality on roundtrip but does not assert contract field preservation; a regression in `RawSessionCreate::from(SessionCreate)` that drops or rewrites the contract field would not be caught.
- **Multiple `into_tuple` and accessor harnesses are tautological**: GPT-5.5 enumerated several harnesses that reduce to "Rust's by-value semantics work" without testing contract-specific properties.
- Several findings overlap with other voices' attacks but with sharper line-number citations.

### Net-new from Kimi (16 attacks)

- **u64 overflow in `3 * num`**: harness explores `num > u64::MAX / 3`; the `3 * num` multiplication overflows before the inner guard is reached. Either Kani fails outright (default overflow checks) or wraps silently (with checks disabled), making the `else` branch's `result.is_ok()` assertion meaningless.
- **`h3_quantity_cast_lossless` misses the real failure mode**: asserts `u32 -> usize -> u32` is identity, which is true but irrelevant; the real bug is the unguarded `drain` panic when `quantity > requests.len()`.

### Net-new from Nemotron (10 attacks)

- **Missing IRV ballot-counting invariant**: ranked-choice has harnesses for ballot filtering and active-choice detection but none verifying that every valid ballot is counted exactly once in the tally (sum-of-candidate-votes = number-of-valid-ballots).
- **Sealed-auction bid-count invariant missing** (S7 above).

### GPT-OSS contribution

Concentrated on framework gating issues (kani_slow CI invisibility was its single critical) but did not engage with the example contracts' production-handler gaps. The HOLDS verdict on transfers, pingpong, and ranked-choice indicates the model accepted the harness-surface claims at face value rather than cross-checking against the production code. Useful as a calibration anchor (the most lenient voice) but did not contribute family-diverse coverage on the load-bearing findings.

## Per-spec final attack count after dedup

| File | Distinct | Critical | Serious | Advisory |
|---|---|---|---|---|
| msg/execute/session_create.rs | 4 | 0 | 3 | 1 |
| msg/execute/session_set_pub_key.rs | 3 | 0 | 1 | 2 |
| core/state.rs (framework) | 7 | 1 (kani_slow CI) | 4 | 2 |
| sealed-auction/state.rs | 2 | 0 | 1 | 1 |
| pingpong/state.rs | 4 | 1 (overwrite-bug missed) | 1 | 2 |
| transfers/state.rs | 7 | 2 (helpers-not-in-prod, BankMsg leak missing) | 3 | 2 |
| ranked-choice/verification.rs | 6 | 0 | 3 | 3 |
| **Total distinct** | **33** | **4** | **16** | **13** |

## Recurring patterns (cross-voice)

1. **Pure-mirror-instead-of-handler**. The dominant structural pattern across the example contracts: harnesses verify helper functions that mirror production logic but are not called by production. Five attacks across four files. The Kani surface for examples is strictly weaker than the Quint surface because the harnesses are looking at the wrong code. Quint forced state machines over the production handlers; Kani harnesses landed on phantom helpers that exist only in `#[cfg(kani)]` modules.

2. **Tautological harnesses**. At least 6 harnesses across the suite reduce to assertions that Rust's by-value semantics + `derive(Clone)` work, or that string constants are equal to themselves. Per-voice count: Kimi 6, Nemotron 3, Claude similar. These consume CI time and create false-positive coverage metrics without exercising any contract-specific property.

3. **Cfg-gated proofs that don't run**. Two `#[cfg(kani_slow)]` harnesses for LightClientOpts validation are excluded from default `cargo kani` runs. No CI workflow passes `--cfg kani_slow`. Four voices flagged this; the most-cited single finding in Round E. Compounds with the unwinding-truncation issue (Kimi #2): even if the gating is fixed, `StdError::msg`'s backtrace construction exceeds the unwind bound, so the error paths are truncated and assertions pass vacuously.

4. **Fixed-input harnesses**. Multiple harnesses constrain inputs to a single shape (`contract = "c"`, `pub_key = vec![0x04u8; 33]`, `pk_len <= 64`) for Kani tractability, then assert properties that are length-independent. The bound is too tight to exercise the equality path Kani is supposedly checking, and too tight to catch a real-world regression on differently-shaped inputs.

5. **Round C carry-over**. Each of Round C's three Quint critical findings has a Kani-side mirror that is either uncovered or covered by the wrong harness. The Kani harness suite is strictly weaker than the Quint surface for the example contracts. This is the load-bearing methodology finding from Round E.

6. **Missing attestation-critical coverage**. The framework's security depends on the exact bytes of `HasUserData::user_data()` (SHA-256 over serialized JSON of the message). No harness covers serialization discipline, field ordering, hasher initialization, or padding correctness. A regression in `user_data` would not be caught.

## Recommendation

**Priority 1 — close the methodology gap surfaced by cross-voice convergence**:

a. **Re-host the pure helpers as production code or delete them.** The transfers `safe_drain_len`, `checked_sum_withdrawals`, and similar helpers are verified-dead-code today. Either move them into `contract.rs::update` so the harnesses test the deployed path, or delete them and accept the gap explicitly. Verified dead code is not a verification result.
b. **Add per-handler harnesses targeting the public API contract handlers invoke.** Claude's report frames this as `can_<handler>_authed_and_guarded(...)` predicates. Each Round C critical finding's intended invariant maps to one such harness. Five voices' work makes the absence visible; landing the harnesses closes it.
c. **Fix the `kani_slow` gating.** Either replace `StdError::msg` with a backtrace-free constructor under `#[cfg(kani)]` and remove the gate, or add a dedicated CI job that runs `--cfg kani_slow` with `--no-unwinding-checks`. The current state is "the harnesses exist but verify nothing in CI."

**Priority 2 — close the high-density coverage gaps**:

d. Add `HasUserData::user_data()` harnesses asserting determinism (`msg.user_data() == msg.clone().user_data()`) at minimum, ideally a fixed-input regression vector.
e. Promote `session_with_pub_key_no_panic` to a functional property (or delete; the function body has no panic source so the assertion is vacuous).
f. Add a bid-count invariant harness for sealed-auction and an IRV total-vote-count invariant for ranked-choice.

**Priority 3 — clean up the tautologies**:

g. Remove or repurpose at least 6 tautological harnesses (pingpong field-roundtrip pair, framework constant-equality assertions, transfers `h3_quantity_cast_lossless` if it cannot be reframed). Consolidate the proof time into the per-handler harnesses from (b).

The combined effect of (a)+(b)+(c) is that the Kani surface starts catching the Round C / Round D carry-over findings rather than producing parallel-but-disconnected harness output. The current Kani CI runs are mostly verifying that Rust's struct field accessors work, not that the contract handlers preserve the production invariants.

## Methodology data point for v0.4 ledger

This is the third multi-voice round to surface family-diversity asymmetry: GPT-OSS-120B was consistently the most lenient voice on example contracts in Round D as well. Its profile is "catches framework / gating issues, accepts surface claims on application code." Worth keeping in the lineup as a lenient anchor but not as the primary load-bearing voice on application contract correctness.

OpenAI's `gpt-5.5` (newly added via opencode OAuth) earned its place in the lineup. 27 attacks, agreed with Claude on the load-bearing pingpong+transfers BREAKS verdict, and surfaced sharp findings on `session_create_roundtrip`'s contract-field omission. The Bug 4 Cloudflare-524 issue affecting Anthropic gateway routes makes the opencode/openai path the cleanest cross-family voice that doesn't share architecture with the Claude subagent.

Sonnet was excluded mid-dispatch on user request ("we already have a Claude voice"). The exclusion logic landed in the dispatch script (`dispatch.py:VOICES` comment block) for any future re-run. The Claude-subagent-only approach for the Anthropic family slot was confirmed reasonable.

Kimi (270-300s on long prompts; output cap ~8K per Bug 3) and Nemotron (~120s, output cap looser) both produced structured output. Kimi's longer reasoning time correlated with more nuanced findings (16 attacks vs Nemotron's 10).
