# burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b (nemotron-3-120b-a12b) — Kani harness adversarial review (Round E)

- Elapsed: 119.4s
- Model: burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b

---

# Round E adversarial review: Kani harness surface

**Target**: 41 Kani harnesses across 7 files (1666 lines total) in Quartz's `crates/contracts/core/` framework and four example contracts (sealed-auction, pingpong, transfers, ranked-choice).  
**Intent docs**: `.colosseum/ledger.md` (audit-ready), CLAUDE.md two-agent split defines verification surface  
**Date**: 2026-05-20  
**Round**: E  
**Adversary**: burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b  

## Per-file verdicts

**VERDICT (crates/contracts/core/src/msg/execute/session_create.rs)**: HOLDS WITH CAVEATS  
**VERDICT (crates/contracts/core/src/msg/execute/session_set_pub_key.rs)**: HOLDS WITH CAVEATS  
**VERDICT (crates/contracts/core/src/state.rs)**: WEAKENS  
**VERDICT (examples/sealed-auction/contracts/src/state.rs)**: HOLDS  
**VERDICT (examples/pingpong/contracts/src/state.rs)**: WEAKENS  
**VERDICT (examples/transfers/contracts/src/state.rs)**: HOLDS WITH CAVEATS  
**VERDICT (examples/ranked-choice/contracts/src/verification.rs)**: HOLDS WITH CAVEATS  

## Numbered attacks

## 1. [state.rs] Session::with_pub_key_no_panic
**Target**: `crates/contracts/core/src/state.rs:178-190` (session_with_pub_key_no_panic harness)  
**Category**: Property correctness  
**Severity**: serious  
**Scenario**: The harness only verifies that `Session::with_pub_key` doesn't panic, but doesn't check that it correctly returns `Some` when nonce matches and `pub_key` is `None`, or `None` otherwise.  
**Why it succeeds**: The harness uses `_result = session.with_pub_key(check_nonce, pub_key);` without asserting anything about the result value.  
**Suggested defense**: Replace the harness with proper property checks matching `session_with_pub_key_guards`, or remove it as redundant.

## 2. [state.rs] LightClientOpts harnesses gated behind kani_slow
**Target**: `crates/contracts/core/src/state.rs:225-265` (light_client_opts_threshold_validation and light_client_opts_height_bounds)  
**Category**: kani_slow vs kani gating  
**Severity**: serious  
**Scenario**: The two LightClientOpts harnesses are gated behind `#[cfg(kani_slow)]` due to backtrace unwinding depth, but there's no evidence they're run in CI.  
**Why it succeeds**: If these harnesses aren't executed in the verification pipeline, the trust threshold and height bounds properties remain unverified.  
**Suggested defense**: Either fix the unwinding issue to allow these to run under standard `kani`, or add explicit CI configuration to run them with `--no-unwinding-checks`.

## 3. [session_create.rs] Fixed contract string in harnesses
**Target**: `crates/contracts/core/src/msg/execute/session_create.rs:66, 82` (session_create_accessors and session_create_roundtrip)  
**Category**: Spec-vs-implementation drift  
**Severity**: advisory  
**Scenario**: Both harnesses use `String::from("c")` for the contract field to avoid Kani's unbounded-string overhead, but real contracts may have varying lengths that could affect behavior.  
**Why it succeeds**: The verification only tests single-character contract names, missing potential issues with longer names (e.g., buffer overflows in serialization, though unlikely in Rust).  
**Suggested defense**: Add a second harness with a variable-length but bounded contract string (e.g., `kani::any_where(|s: &String| s.len() <= 32)`) to test typical real-world cases.

## 4. [session_set_pub_key.rs] Fixed pub_key length in harnesses
**Target**: `crates/contracts/core/src/msg/execute/session_set_pub_key.rs:66, 85` (session_set_pub_key_tuple_roundtrip and session_set_pub_key_raw_roundtrip)  
**Category**: Spec-vs-implementation drift  
**Severity**: advisory  
**Scenario**: Both harnesses use `vec![0x04u8; 33]` for pub_key, which is a valid secp256k1 compressed point length, but doesn't test other valid lengths (e.g., 65 for uncompressed) or edge cases.  
**Why it succeeds**: The verification assumes a fixed pub_key length, potentially missing issues with variable-length key handling in the serialization/deserialization logic.  
**Suggested defense**: Add harnesses that test multiple valid pub_key lengths (e.g., 33 for compressed, 65 for uncompressed) within Kani-tractable bounds.

## 5. [pingpong.rs] Tautological field roundtrip harnesses
**Target**: `examples/pingpong/contracts/src/state.rs:28-48` (ping_field_roundtrip and pong_field_roundtrip)  
**Category**: Tautological harnesses  
**Severity**: advisory  
**Scenario**: These harnesses simply verify that setting a field and reading it back returns the same value, which is a trivial property of Rust structs and doesn't test contract-specific behavior.  
**Why it succeeds**: The harnesses don't interact with any contract logic; they're testing basic language functionality rather than the contract's properties.  
**Suggested defense**: Remove these harnesses or replace them with properties that actually verify contract behavior, such as checking that the pubkey field is correctly used in storage key derivation.

## 6. [transfers.rs] H8 deposit total bound may be too loose
**Target**: `examples/transfers/contracts/src/state.rs:300-318` (h8_deposit_total_bounded)  
**Category**: Coverage gaps from `kani::any_where` bounds  
**Severity**: advisory  
**Scenario**: The harness bounds deposits to 8 items (`n <= 8`), but there's no indication this limit exists in the actual contract logic.  
**Why it succeeds**: If the contract can handle more than 8 deposits, this harness doesn't verify the property for realistic workloads where overflow might occur.  
**Suggested defense**: Either increase the bound to a more realistic number (if the contract truly limits deposits) or remove the bound and find another way to make the verification tractable.

## 7. [ranked-choice.rs] Missing harness for ballot counting invariant
**Target**: `examples/ranked-choice/contracts/src/verification.rs` (verification::kani_harnesses module)  
**Category**: Missing harnesses for invariants  
**Severity**: serious  
**Scenario**: While there are harnesses for ballot filtering and active choice detection, there's no explicit harness verifying that the total vote counting preserves the invariant that every valid ballot is counted exactly once in the tally.  
**Why it succeeds**: The IRV tally process could potentially lose or duplicate ballots without detection by the current harness set.  
**Suggested defense**: Add a harness that models the full IRV tally process (or its pure logic core) and verifies that the sum of all candidates' votes equals the number of valid ballots.

## 8. [sealed-auction.rs] Missing harness for bid count invariant
**Target**: `examples/sealed-auction/contracts/src/state.rs` (verification module)  
**Category**: Missing harnesses for invariants  
**Severity**: advisory  
**Scenario**: The contract maintains a `bid_count` field in `AuctionRound` that should match the number of entries in `SEALED_BIDS`, but no harness verifies this invariant.  
**Why it succeeds**: A bug in bid submission/resolution logic that mismanages the bid count could go undetected.  
**Suggested defense**: Add a pure function that computes expected bid count from a set of bids and verifies it matches the stored value, then create a Kani harness for it.

## 9. [state.rs] Session::nonce_roundtrip harness limited scope
**Target**: `crates/contracts/core/src/state.rs:200-204` (session_nonce_roundtrip)  
**Category**: Coverage gaps from `kani::any_where` bounds  
**Severity**: advisory  
**Scenario**: The harness only tests `Session::create` followed by `nonce()`, but doesn't test the nonce roundtrip through the full session lifecycle (create → with_pub_key → nonce).  
**Why it succeeds**: If there's a bug in how `with_pub_key` affects the nonce retrieval (though unlikely), this harness wouldn't catch it.  
**Suggested defense**: Expand the harness to test nonce retrieval after `with_pub_key` calls in both success and failure cases.

## 10. [transfers.rs] H3 quantity cast lossless assumes 32/64-bit consistency
**Target**: `examples/transfers/contracts/src/state.rs:138-148` (h3_quantity_cast_lossless)  
**Category**: Spec-vs-implementation drift  
**Severity**: advisory  
**Scenario**: The harness assumes `u32 -> usize -> u32` is identity, which holds on platforms where `usize` is at least 32 bits, but the comment indicates this is checked specifically for 32/64-bit targets.  
**Why it succeeds**: While probably correct for all practical targets, the harness doesn't actually verify the property for the specific target platforms the contract might compile to.  
**Suggested defense**: Add a comment clarifying the target platform assumption or, if concerned about portability, test the property under cfg(target_pointer_width) conditions.

## META

**Per-file attack counts**: 
- session_create.rs: 1
- session_set_pub_key.rs: 1
- state.rs: 4
- sealed-auction.rs: 1
- pingpong.rs: 1
- transfers.rs: 2
- ranked-choice.rs: 2

**Recurring patterns**:
1. **Overly narrow test inputs**: Multiple harnesses use fixed-length values (contract="c", pub_key=33 bytes) to avoid Kani's path explosion, potentially missing edge cases.
2. **Tautological properties**: Several harnesses (especially in pingpong) verify basic Rust language properties rather than contract-specific behavior.
3. **Missing invariant coverage**: Critical workflow invariants (like bid count matching sealed bids, or ballot counting integrity) lack direct verification.
4. **Conditional verification**: Important properties (LightClientOpts) are gated behind special flags with uncertain CI execution.

**Recommendations**:
1. Replace narrow fixed-value inputs with bounded ranges that reflect realistic constraints (e.g., contract lengths 1-32 bytes, pub_key lengths 33 and 65 bytes).
2. Eliminate tautological harnesses; focus on properties that require contract-specific reasoning.
3. For each major state transition in the handler flow (instantiate → session_create → session_set_pubkey → attested ops), add a harness verifying the invariant preservation.
4. Establish clear verification criteria for kani_slow harnesses: either fix the root cause or mandate their execution in CI with appropriate flags.

