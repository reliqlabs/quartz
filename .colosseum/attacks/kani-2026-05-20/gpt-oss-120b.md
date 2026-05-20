# burnt/gpt-oss-120b (gpt-oss-120b) — Kani harness adversarial review (Round E)

- Elapsed: 48.2s
- Model: burnt/gpt-oss-120b

---

---
target: |
  crates/contracts/core/src/msg/execute/session_create.rs
  crates/contracts/core/src/msg/execute/session_set_pub_key.rs
  crates/contracts/core/src/state.rs
  examples/sealed-auction/contracts/src/state.rs
  examples/pingpong/contracts/src/state.rs
  examples/transfers/contracts/src/state.rs
  examples/ranked-choice/contracts/src/verification.rs
intent: adversarial review of Kani harnesses
date: 2026-05-20
round: E
adversary: gpt-oss-120b
---

VERDICT (crates/contracts/core/src/msg/execute/session_create.rs): WEAKENS  
VERDICT (crates/contracts/core/src/msg/execute/session_set_pub_key.rs): WEAKENS  
VERDICT (crates/contracts/core/src/state.rs): HOLDS WITH CAVEATS  
VERDICT (examples/sealed-auction/contracts/src/state.rs): HOLDS  
VERDICT (examples/pingpong/contracts/src/state.rs): HOLDS  
VERDICT (examples/transfers/contracts/src/state.rs): HOLDS  
VERDICT (examples/ranked-choice/contracts/src/verification.rs): HOLDS  

## 1. LightClientOpts validation not exercised  
**Target** `crates/contracts/core/src/state.rs` – `light_client_opts_threshold_validation` & `light_client_opts_height_bounds` harnesses (gated by `#[cfg(kani_slow)]`).  
**Category** Mock‑mode / gating omission.  
**Severity** critical.  
**Scenario** CI runs `cargo kani` without `kani_slow` flag; the two harnesses are omitted, leaving the trust‑threshold validation unchecked. An attacker can supply a malformed `LightClientOpts` with `trust_threshold` violating the 1/3 rule, causing the contract to accept insecure parameters.  
**Why it succeeds** The `#[cfg(kani_slow)]` annotation disables the harnesses in the default CI configuration, so Kani never verifies the critical error paths.  
**Suggested defense** Remove the `kani_slow` gating or ensure CI invokes `cargo kani --cfg kani_slow`. Add a plain `#[kani::proof]` wrapper that calls the same logic with a small unwind bound, guaranteeing execution in all CI runs.

## 2. SessionCreate round‑trip harness omits error case  
**Target** `crates/contracts/core/src/msg/execute/session_create.rs` – `session_create_roundtrip`.  
**Category** Property correctness (weak).  
**Severity** advisory.  
**Scenario** The harness only checks that a correctly‑sized 32‑byte nonce round‑trips. It never asserts that `SessionCreate::try_from` returns an error for non‑32‑byte `HexBinary`. An attacker could feed a malformed nonce, causing a runtime error that is not covered by the proof.  
**Why it succeeds** The harness constructs `RawSessionCreate` via `original.clone().into()`, guaranteeing a valid nonce length; no invalid input is explored.  
**Suggested defense** Add a second harness that creates a `RawSessionCreate` with a `HexBinary` of length ≠ 32, calls `SessionCreate::try_from`, and asserts `is_err()`.

## 3. SessionSetPubKey harness skips mismatch and double‑set checks  
**Target** `crates/contracts/core/src/msg/execute/session_set_pub_key.rs` – `session_set_pub_key_tuple_roundtrip`.  
**Category** Property correctness (weak).  
**Severity** advisory.  
**Scenario** The harness verifies that `SessionSetPubKey::new` and `into_tuple` are inverses for a matching nonce and fixed pub‑key length. It never tests the case where the nonce in the raw struct differs from the expected nonce, nor the case where the session already has a pub‑key. Those paths return `Err` in production but are unproven.  
**Why it succeeds** The harness supplies matching nonce and a constant pub‑key, never exercising the guard logic.  
**Suggested defense** Add two harnesses: one where `RawSessionSetPubKey` contains a mismatched nonce and asserts `SessionSetPubKey::try_from` fails; another that creates a `Session` with an existing pub‑key, calls `with_pub_key`, and asserts `None`.

## 4. Session::with_pub_key totality harness lacks guard verification  
**Target** `crates/contracts/core/src/state.rs` – `session_with_pub_key_no_panic`.  
**Category** Property correctness (weak).  
**Severity** advisory.  
**Scenario** The harness only asserts that the function does not panic for any inputs. It does not verify that the function returns `None` when the nonce mismatches or when a pub‑key is already set. Those failure modes are critical for preventing unauthorized key updates.  
**Why it succeeds** The harness never inspects the `Option` result; any return value satisfies the proof.  
**Suggested defense** Split the harness into two: one asserting `Some` only when nonce matches and pub_key is `None`, another asserting `None` otherwise. Use `kani::assume` to set mismatched conditions.

## 5. Unwind bound may mask double‑set detection in session_pubkey_set_once  
**Target** `crates/contracts/core/src/state.rs` – `session_pubkey_set_once`.  
**Category** Bounded unwind cutoff.  
**Severity** serious.  
**Scenario** The harness uses `#[kani::unwind(40)]` to bound the equality comparison of two 33‑byte vectors. If future code expands the pub‑key size (e.g., to 65 bytes), the unwind bound may be insufficient, causing Kani to miss the double‑set rejection path.  
**Why it succeeds** The current harness matches the present 33‑byte length, so the bound is adequate; however the bound is a hard limit that does not adapt to code changes.  
**Suggested defense** Replace the explicit unwind bound with a symbolic bound derived from `pub_key.len()` (e.g., `#[kani::unwind(pub_key.len())]`) or increase the bound to a safe maximum (e.g., 256) to future‑proof the proof.

## 6. Sealed‑auction harness omits state‑mutation invariants  
**Target** `examples/sealed-auction/contracts/src/state.rs` – `start_auction_guard_total`, `submit_bid_guard_exact`, etc.  
**Category** Missing harnesses for invariants.  
**Severity** advisory.  
**Scenario** The harnesses verify guard logic but do not check that `start_auction` correctly increments `ROUND_COUNTER` or clears `SEALED_BIDS`. An attacker could exploit a bug where the counter is not incremented, leading to replay or duplicate round IDs.  
**Why it succeeds** The harnesses focus solely on pure guard predicates; they never model storage mutations.  
**Suggested defense** Add a harness that simulates the full `exec_start_auction` flow (including storage mocks) and asserts that `ROUND_COUNTER` increases and that `SEALED_BIDS` is empty after execution.

## 7. Sealed‑auction phase guard harness relies on u8 mapping  
**Target** `examples/sealed-auction/contracts/src/state.rs` – phase‑enum harnesses.  
**Category** Tautological harness.  
**Severity** advisory.  
**Scenario** The harness maps a nondeterministic `u8` to an `AuctionPhase` via a match with four arms. This excludes any future enum variants (e.g., a new `Paused` state). If such a variant is added without updating the harness, Kani will silently treat the unmapped value as `Complete`, potentially missing violations.  
**Why it succeeds** The harness only enumerates existing variants; any extra bits are unreachable in the proof.  
**Suggested defense** Replace the manual `u8` mapping with `kani::any::<AuctionPhase>()` to let Kani explore all current and future variants automatically.

## 8. Ping‑pong harness does not verify storage‑key uniqueness  
**Target** `examples/pingpong/contracts/src/state.rs` – field‑roundtrip and pub‑key symmetry harnesses.  
**Category** Missing harnesses for invariants.  
**Severity** advisory.  
**Scenario** The contract relies on `PINGS` map keys being unique per pub‑key. The harnesses only test struct field preservation, not that two distinct `Ping` messages with the same `pubkey` overwrite each other as intended. An attacker could craft colliding hex representations that bypass the map.  
**Why it succeeds** The harness never invokes storage operations; it only checks pure data structures.  
**Suggested defense** Add a harness that creates two `Ping` instances with identical `pubkey` values, writes both to a mock `Map`, and asserts that the second write overwrites the first.

## 9. Transfers harness documents missing guard for out‑of‑bounds drain  
**Target** `examples/transfers/contracts/src/state.rs` – `h2_drain_out_of_bounds_detected`.  
**Category** Property correctness (missing guard in production).  
**Severity** serious.  
**Scenario** The harness proves that a safe wrapper would reject out‑of‑bounds drains, but the actual contract `update` function calls `requests.drain(0..msg.quantity as usize)` without any pre‑check, causing a panic on overflow. This discrepancy is a production bug.  
**Why it succeeds** The harness models a corrected version of the code, not the real implementation.  
**Suggested defense** Insert an explicit guard in `update` before draining: `if msg.quantity as usize > requests.len() { return Err(Error::InvalidQuantity); }`. Add a Kani harness that calls the real `update` logic with an oversized `quantity` and asserts the error is returned.

## 10. Ranked‑choice phase‑transition harness omits illegal transition Setup→Complete  
**Target** `examples/ranked-choice/contracts/src/verification.rs` – `phase_transition_allowed`.  
**Category** Tautological harness.  
**Severity** advisory.  
**Scenario** The harness verifies allowed transitions but does not assert that the illegal transition `Setup → Complete` is rejected. If future code mistakenly permits this shortcut, the harness would not catch it because it only checks the `matches!` expression.  
**Why it succeeds** The harness only tests the boolean result of `phase_transition_allowed`; it never asserts the negative case for each disallowed pair.  
**Suggested defense** Extend the harness to iterate over all unordered pairs of distinct phases, assert that `phase_transition_allowed` returns `false` for any pair not listed in the allowed set, specifically checking `Setup → Complete`.

---

**META**  
- **Attack counts per file**  
  - `session_create.rs`: 2  
  - `session_set_pub_key.rs`: 2  
  - `state.rs` (framework): 3  
  - `sealed-auction/state.rs`: 2  
  - `pingpong/state.rs`: 1  
  - `transfers/state.rs`: 1  
  - `ranked-choice/verification.rs`: 1  

- **Recurring patterns**  
  1. **Gated harnesses** (`#[cfg(kani_slow)]`) causing critical checks to be omitted in CI.  
  2. **Weak harnesses** that only test happy‑path round‑trip without exercising error branches.  
  3. **Fixed‑size unwind bounds** that may become stale if data structures grow.  
  4. **Enum mapping via `u8`** rather than direct `kani::any::<Enum>()`, leading to tautological coverage.  

- **Recommendation**  
  - Remove or replace `#[cfg(kani_slow)]` gating for any harness that validates securitycritical parameters.  
  - Augment each harness with complementary negative‑case tests that assert proper error handling for malformed inputs.  
  - Use symbolic unwind bounds derived from input sizes or set generous static limits to avoid future false negatives.  
  - Prefer `kani::any::<Enum>()` to guarantee exhaustive exploration of current and future enum variants.  
  - Align harnesses with actual production code paths (e.g., include the real `update` drain without a guard) to surface missing checks as actionable bugs.

