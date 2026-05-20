# burnt/kimi-k2-6 (kimi-k2-6) — Kani harness adversarial review (Round E)

- Elapsed: 300.9s
- Model: burnt/kimi-k2-6

---

```markdown
# Round E Adversarial Review — Kani Harness Surface

**Target files:**
- `crates/contracts/core/src/msg/execute/session_create.rs`
- `crates/contracts/core/src/msg/execute/session_set_pub_key.rs`
- `crates/contracts/core/src/state.rs`
- `examples/sealed-auction/contracts/src/state.rs`
- `examples/pingpong/contracts/src/state.rs`
- `examples/transfers/contracts/src/state.rs`
- `examples/ranked-choice/contracts/src/verification.rs`

**Intent docs:** `CLAUDE.md` (Quartz agent / Colosseum agent split), `.colosseum/ledger.md`

**Date:** 2026-05-20

**Round:** E

**Adversary:** burnt/kimi-k2-6

---

## Per-file verdicts

VERDICT (session_create.rs): HOLDS WITH CAVEATS
VERDICT (session_set_pub_key.rs): HOLDS WITH CAVEATS
VERDICT (state.rs): WEAKENS
VERDICT (sealed-auction/state.rs): HOLDS WITH CAVEATS
VERDICT (pingpong/state.rs): HOLDS WITH CAVEATS
VERDICT (transfers/state.rs): WEAKENS
VERDICT (ranked-choice/verification.rs): WEAKENS

---

## 1. [state.rs] `light_client_opts_threshold_validation` — u64 overflow in `3 * num`

**Target:** `crates/contracts/core/src/state.rs`, `light_client_opts_threshold_validation` (lines ~210–240)

**Category:** Coverage gaps from `kani::any_where` bounds

**Severity:** critical

**Scenario:** Kani explores `num > u64::MAX / 3`. The condition `3 * num < den` evaluates `3 * num` as a `u64` multiply. In Kani's default configuration this triggers an overflow failure before the inner guard `num <= u64::MAX / 3` is ever reached. If overflow checks are disabled, the wrapped value makes the comparison meaningless and the subsequent `else` branch may incorrectly assert `result.is_ok()` on an actually-invalid threshold.

**Why it succeeds:** The harness either fails outright (with default checks) or silently excludes the overflow path, giving a false sense of coverage. The `else` branch assumes "all remaining inputs are valid", but inputs that cause `3 * num` to overflow fall into a crack between the `else if` and the `else`.

**Suggested defense:** Constrain `num` at the top of the harness to `num <= u64::MAX / 3`, or refactor `LightClientOpts::new` to use `num.checked_mul(3)` and compare against `den` only when `Some`.

---

## 2. [state.rs] `kani_slow` LightClientOpts harnesses truncated by `#[kani::unwind(20)]`

**Target:** `crates/contracts/core/src/state.rs`, `light_client_opts_threshold_validation` and `light_client_opts_height_bounds`

**Category:** Bounded `unwind` cutoffs

**Severity:** serious

**Scenario:** `StdError::msg(...)` constructs a `std::backtrace::Backtrace`, pulling in stdlib unwinding that exceeds 20 iterations. The harness comment explicitly admits this and recommends `--no-unwinding-checks`. With that flag, Kani truncates the backtrace construction, which means the error-return paths (`den == 0`, `num > den`, etc.) are never fully executed. The assertions `result.is_err()` sit on truncated paths and pass vacuously.

**Why it succeeds:** The unwind bound cuts off execution before the assertions can be violated. The harness passes because Kani never reaches the actual `return Err(...)` statements in the error cases.

**Suggested defense:** Replace `StdError::msg` with a Kani-friendly error constructor (e.g., a custom `StdError` variant that skips backtrace generation under `#[cfg(kani)]`), or dramatically increase the unwind bound and run without `--no-unwinding-checks`.

---

## 3. [state.rs] `kani_slow` harnesses are invisible to default CI runs

**Target:** `crates/contracts/core/src/state.rs`, both `#[cfg(kani_slow)]` harnesses

**Category:** `kani_slow` vs `kani` gating

**Severity:** serious

**Scenario:** Standard `cargo kani` enables only the `kani` cfg. The two `LightClientOpts` harnesses are compiled out of default verification runs. The properties they claim — trust-threshold bounds and height bounds — are therefore not continuously verified.

**Why it succeeds:** They are excluded from the build by the cfg gate. No CI job is configured to pass `--cfg kani_slow`.

**Suggested defense:** Either promote the harnesses to `#[cfg(kani)]` by removing the backtrace dependency (see Finding 2), or add a dedicated CI job that runs with `--cfg kani_slow` and an appropriate time budget.

---

## 4. [state.rs] `session_with_pub_key_no_panic` is tautological

**Target:** `crates/contracts/core/src/state.rs`, `session_with_pub_key_no_panic` (lines ~150–160)

**Category:** Tautological harnesses

**Severity:** serious

**Scenario:** The harness calls `session.with_pub_key(check_nonce, pub_key)` and assigns the result to `_result`, asserting only that the call does not panic. The function body consists of a nonce comparison, an `is_none()` check, and an `Option` return. It contains no `panic!`, `unwrap`, indexing, or other panic source. The non-panic property is therefore true by construction for all inputs.

**Why it succeeds:** The asserted property is vacuously true; the harness exercises Kani without verifying any functional behavior.

**Suggested defense:** Delete the harness or replace it with a functional property (e.g., assert the returned `Option` satisfies the guard semantics already captured in `session_with_pub_key_guards`).

---

## 5. [session_create.rs + session_set_pub_key.rs] Missing `HasUserData::user_data()` harnesses

**Target:** `crates/contracts/core/src/msg/execute/session_create.rs` and `session_set_pub_key.rs`, `HasUserData` impls

**Category:** Missing harnesses for invariants the production code depends on

**Severity:** serious

**Scenario:** Both message types implement `HasUserData` by serializing to JSON (via `serde_json::to_string`), hashing with SHA-256, and zero-padding to 64 bytes. This `user_data` is the exact value checked during attestation in the `DstackAttestation` handler chain. No harness covers serialization discipline, field ordering, hasher initialization, or padding correctness.

**Why it succeeds:** N/A — coverage gap. A regression in `user_data` (e.g., serializing `SessionCreate` instead of `RawSessionCreate`, or omitting the zero-padding) would not be caught.

**Suggested defense:** Add harnesses that construct messages with fixed fields and assert the `user_data` bytes match a pre-computed expected digest, or at minimum assert determinism (`msg.user_data() == msg.clone().user_data()`).

---

## 6. [transfers/state.rs] Verified helpers do not exist in production code

**Target:** `examples/transfers/contracts/src/state.rs`, `h1`–`h4`, `h8`

**Category:** Helper-functions-under-test / Spec-vs-implementation drift

**Severity:** serious

**Scenario:** The harnesses verify `safe_drain_len`, `checked_sum_withdrawals`, and a deposit accumulator — pure functions defined only in the `#[cfg(kani)]` module. The production `contract.rs::update` does `requests.drain(0..msg.quantity as usize)` with no bounds guard, and never sums withdrawals or accumulates a global deposit total. The harnesses prove properties about code that does not run in production.

**Why it succeeds:** The verified code and the deployed code are different programs. A panic in `drain` or an overflow in a future production change would be invisible to this suite.

**Suggested defense:** Inline the guards into the production handlers and harness the production functions directly, or delete the harnesses and document the unverified panic/overflow paths as known risks.

---

## 7. [ranked-choice/verification.rs] `phase_transition_allowed` permits `Voting → Tallying` never used in production

**Target:** `examples/ranked-choice/contracts/src/verification.rs`, `phase_transition_allowed` (lines ~55–68)

**Category:** Spec-vs-implementation drift

**Severity:** serious

**Scenario:** The pure function lists `(Voting, Tallying)` as an allowed transition, but `contract.rs::exec_tally` transitions `Voting → Complete` directly. The `Tallying` phase is only observable as an input guard (`can_tally` allows it), never as a state written by the production handlers. The harness `h_phase_transition_no_skip` does not catch this because it only asserts three specific forbidden transitions.

**Why it succeeds:** The harness tests the pure function in isolation, not against the actual state machine in `contract.rs`.

**Suggested defense:** Remove `(Voting, Tallying)` from `phase_transition_allowed` and regenerate the harness to exhaustively assert all 16 `(from, to)` pairs against the actual transitions performed in `contract.rs`.

---

## 8. [ranked-choice/verification.rs] `h_first_active_choice_progress` misses ordering property

**Target:** `examples/ranked-choice/contracts/src/verification.rs`, `h_first_active_choice_progress` (lines ~260–290)

**Category:** Property correctness

**Severity:** serious

**Scenario:** The harness asserts `if has_active { result.is_some() } else { result.is_none() }`. It never checks that the returned `Some(c)` is the *first* active choice (the one with the smallest ballot index). A buggy implementation that scanned from the end of the ballot, or returned the last matching candidate, would satisfy the harness.

**Why it succeeds:** The property is too weak. The function name and comment promise "first active choice", but the harness only proves "some active choice".

**Suggested defense:** Assert that the returned value equals `ballot[i]` for the smallest `i` such that `ballot[i]` is a non-eliminated registered candidate.

---

## 9. [state.rs] `session_with_pub_key_guards` never tests pre-existing `Some(pub_key)`

**Target:** `crates/contracts/core/src/state.rs`, `session_with_pub_key_guards` (lines ~165–180)

**Category:** Coverage gaps from `kani::any_where` bounds

**Severity:** advisory

**Scenario:** The harness always starts from `Session::create`, so `pub_key` is always `None`. It therefore never exercises the `self.pub_key.is_none()` branch in `with_pub_key` when `pub_key` is already `Some`. A session loaded from storage after `session_set_pub_key` would have `pub_key = Some(...)`, and `with_pub_key` should return `None` regardless of nonce matching.

**Why it succeeds:** The `pub_key.is_none()` guard is always true in this harness, so the "reject double-set" behavior is only tested in the separate `session_pubkey_set_once` harness.

**Suggested defense:** Add a harness that constructs a `Session` with `pub_key = Some(...)` directly and asserts `with_pub_key` returns `None` for both matching and non-matching nonces.

---

## 10. [sealed-auction/state.rs] Vickrey harnesses never cover winner at non-zero index

**Target:** `examples/sealed-auction/contracts/src/state.rs`, vickrey harness suite (lines ~180–240)

**Category:** Coverage gaps

**Severity:** advisory

**Scenario:** All existing vickrey harnesses either have the winner at index 0 (single bidder, two bidders with `a > b`, three-way tie) or no winner. No harness constructs `bids = [lower, higher]` to force the winner to index 1. The "winner is highest" property is only verified when the highest bid happens to appear first.

**Why it succeeds:** The first-pass loop initialization (`winner_idx = 0`) is never stressed by a higher bid at a later index.

**Suggested defense:** Add a harness with `bids = [b, a]` where `a > b` and assert `w == Some(1)`.

---

## 11. [pingpong/state.rs] `pings_key_stable` is a trivial constant check

**Target:** `examples/pingpong/contracts/src/state.rs`, `pings_key_stable` (lines ~25–30)

**Category:** Tautological harnesses

**Severity:** advisory

**Scenario:** The harness asserts `!PINGS_KEY.is_empty()` and `PINGS_KEY == "pings"`. This is a constant equality assertion, not a symbolic property. It provides no more assurance than a unit test and consumes a Kani proof slot.

**Why it succeeds:** The assertion is true by literal inspection of the source code.

**Suggested defense:** Move to a unit test, or replace with a symbolic property about Map namespace uniqueness (e.g., assert no other `Item` or `Map` in the contract shares this prefix).

---

## 12. [pingpong/state.rs] Missing `to_hex()` symmetry property for Map keys

**Target:** `examples/pingpong/contracts/src/state.rs`, `ping_pong_pubkey_symmetry` (lines ~65–80)

**Category:** Missing harnesses

**Severity:** advisory

**Scenario:** The contract uses `ping.pubkey.to_hex()` and `pong.pubkey.to_hex()` as `PINGS` Map keys. The harness checks `ping.pubkey == pong.pubkey` (HexBinary equality), but the contract's correctness depends on the hex-encoded string key, not the binary value. While `to_hex()` is deterministic, the harness does not exercise the actual key-derivation path.

**Why it succeeds:** N/A — coverage gap. A hypothetical bug in `HexBinary::to_hex()` would not be caught.

**Suggested defense:** Add `assert_eq!(ping.pubkey.to_hex(), pong.pubkey.to_hex())` to the symmetry harness (may require an unwind bound for the hex-encoding loop).

---

## 13. [ranked-choice/verification.rs] `h_phase_transition_no_skip` checks only 3 of 10+ forbidden transitions

**Target:** `examples/ranked-choice/contracts/src/verification.rs`, `h_phase_transition_no_skip` (lines ~200–225)

**Category:** Property correctness

**Severity:** advisory

**Scenario:** The comment claims "Phase transitions: forbidden ones are rejected," but the harness only asserts rejection for three specific pairs: `Setup→Complete`, `Complete→Voting`, and `Voting→Setup`. Many other forbidden transitions (e.g., `Tallying→Setup`, `Complete→Tallying`, `Tallying→Voting`) are not asserted.

**Why it succeeds:** The property is weaker than advertised. The harness would pass even if `Tallying→Setup` were incorrectly allowed.

**Suggested defense:** Replace the three specific assertions with an exhaustive enumeration of all 16 `(from, to)` pairs, asserting the expected boolean for each.

---

## 14. [transfers/state.rs] `h3_quantity_cast_lossless` misses the real failure mode

**Target:** `examples/transfers/contracts/src/state.rs`, `h3_quantity_cast_lossless` (lines ~90–100)

**Category:** Property correctness

**Severity:** advisory

**Scenario:** The harness proves `u32 -> usize -> u32` is identity. The actual bug in production is `msg.quantity as usize > requests.len()`, which causes `drain` to panic. The harness does not relate the cast value to the queue length or assert any bounds safety.

**Why it succeeds:** The property is true but irrelevant to the panic path in `contract.rs::update`.

**Suggested defense:** Add a harness that verifies the production `update` handler either rejects `quantity > len` or handles it without panicking.

---

## 15. [ranked-choice/verification.rs] `candidates_valid` mirror uses different algorithm than production

**Target:** `examples/ranked-choice/contracts/src/verification.rs`, `h_candidates_dup_rejected` / `h_candidates_distinct_accepted` (lines ~120–150)

**Category:** Helper-functions-under-test

**Severity:** advisory

**Scenario:** Production `exec_create_election` uses `std::collections::HashSet` for duplicate detection. The harness tests a pure mirror using nested loops over `u8` slices. The behaviors could diverge if the HashSet path has subtle issues, and more importantly the harness does not exercise the production code at all.

**Why it succeeds:** The harness tests a different implementation of the same intent.

**Suggested defense:** Refactor production to call a pure `candidates_valid` helper (using the same nested-loop logic, or a shared utility) so the harness directly covers the code that runs on-chain.

---

## 16. [session_set_pub_key.rs] Harnesses use fixed 33-byte pub_key, missing length diversity

**Target:** `crates/contracts/core/src/msg/execute/session_set_pub_key.rs`, both harnesses (lines ~70–90)

**Category:** Coverage gaps

**Severity:** advisory

**Scenario:** Both harnesses fix `pub_key = vec![0x04u8; 33]`. The `into_tuple` and raw-roundtrip properties are length-independent, but the harness comment claims "bounded unwind for Vec equality" while using a fixed vector. Kani never explores other lengths or contents.

**Why it succeeds:** The property holds for all lengths, but the harness does not demonstrate it.

**Suggested defense:** Use `kani::any_where(|&n| n <= 64)` for length and fill with arbitrary bytes to exercise the Vec equality path more thoroughly.

---

## META

### Per-file attack counts

| File | Critical | Serious | Advisory | Total |
|------|----------|---------|----------|-------|
| `crates/contracts/core/src/state.rs` | 1 | 3 | 1 | 5 |
| `examples/transfers/contracts/src/state.rs` | 0 | 1 | 2 | 3 |
| `examples/ranked-choice/contracts/src/verification.rs` | 0 | 2 | 2 | 4 |
| `crates/contracts/core/src/msg/execute/session_create.rs` | 0 | 1 | 0 | 1 |
| `crates/contracts/core/src/msg/execute/session_set_pub_key.rs` | 0 | 0 | 1 | 1 |
| `examples/sealed-auction/contracts/src/state.rs` | 0 | 0 | 1 | 1 |
| `examples/pingpong/contracts/src/state.rs` | 0 | 0 | 2 | 2 |
| **Total** | **1** | **7** | **8** | **16** |

### Recurring patterns

1. **Pure mirrors drifting from production** (transfers, ranked-choice). The harnesses verify helper functions that mirror production logic but are not called by production. When the production path changes (e.g., `drain` without guard, HashSet duplicate check), the harnesses remain green while the deployed code retains bugs.
2. **Tautological or near-tautological harnesses** (framework `state.rs` no-panic, pingpong constant check). These consume proof time and create false confidence without exercising meaningful symbolic state.
3. **Properties weaker than the intent** (ranked-choice first-active-choice, phase-transition no-skip). The harness asserts a necessary but insufficient condition, allowing buggy implementations to pass.
4. **Cfg-gated / unwind-truncated proofs** (`kani_slow` LightClientOpts). Properties that are either excluded from CI or pass only because Kani truncates the path before reaching the assertion.
5. **Missing coverage of attestation-critical code** (`HasUserData` user_data computation). The framework's security depends on the exact bytes of `user_data`, yet no harness touches the SHA-256 + JSON serialization path.

### Recommendation

1. **Fix or remove the `light_client_opts_threshold_validation` harness immediately.** The overflow in `3 * num` makes it either broken or misleading. Use `checked_mul` in production and constrain inputs in the harness.
2. **Demote pure-mirror harnesses to unit tests, or promote the helpers into production.** The transfers `safe_drain_len` and `checked_sum_withdrawals` should either be called by `contract.rs` or deleted; verified dead code is not a verification result.
3. **Add `user_data()` harnesses for both framework message types.** These are on the critical path for attestation and are currently unverified.
4. **Run `kani_slow` in CI or eliminate the backtrace dependency.** Unverified `kani_slow` harnesses are effectively documentation, not proof.
5. **Strengthen the ranked-choice phase-transition harness to exhaustive enumeration.** The current "spot check" approach misses drift between the pure function and the actual `contract.rs` state machine.
```

