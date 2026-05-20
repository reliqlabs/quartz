# openai/gpt-5.5 (gpt-5-5) — Kani harness adversarial review (Round E)

- Elapsed: 111.6s
- Model: openai/gpt-5.5

---

Target files: `crates/contracts/core/src/msg/execute/session_create.rs`, `crates/contracts/core/src/msg/execute/session_set_pub_key.rs`, `crates/contracts/core/src/state.rs`, `examples/sealed-auction/contracts/src/state.rs`, `examples/pingpong/contracts/src/state.rs`, `examples/transfers/contracts/src/state.rs`, `examples/ranked-choice/contracts/src/verification.rs`  
Intent docs: supplied Round E prompt plus inline harness docstrings and adjacent production handlers  
Date: 2026-05-20  
Round: E  
Adversary: openai/gpt-5.5

VERDICT (session_create.rs): WEAKENS  
VERDICT (session_set_pub_key.rs): WEAKENS  
VERDICT (state.rs): BREAKS  
VERDICT (sealed-auction/state.rs): WEAKENS  
VERDICT (pingpong/state.rs): BREAKS  
VERDICT (transfers/state.rs): BREAKS  
VERDICT (ranked-choice/verification.rs): WEAKENS

## 1. [session_create.rs] Contract-address binding is not verified

**Target**: `crates/contracts/core/src/msg/execute/session_create.rs`, harnesses `session_create_accessors`, `session_create_roundtrip`

**Category**: Missing harness for production invariant

**Severity**: serious

**Scenario**: `SessionCreate` is accepted only if `msg.contract == env.contract.address` after address validation in `handler/execute/session_create.rs`. The Kani harness fixes `contract = "c"` and only proves constructor/accessor and nonce roundtrip behavior.

**Why it succeeds**: The production security property is the binding between the attested `SessionCreate` userdata and the executing contract address. None of the harnesses exercise `contract` preservation through `RawSessionCreate`, malformed contract strings, address validation, or mismatch rejection. A regression that drops the handler check, compares the wrong address, or rewrites `contract` during raw conversion would still pass both harnesses.

**Suggested defense**: Add a pure guard harness for contract equality and mismatch rejection, or extract the address-match predicate used by the handler and verify it against arbitrary validated contract strings. Also assert raw roundtrip preserves both `nonce` and `contract`, not just `nonce`.

## 2. [session_create.rs] Raw roundtrip ignores the contract field

**Target**: `crates/contracts/core/src/msg/execute/session_create.rs`, harness `session_create_roundtrip`

**Category**: Property correctness

**Severity**: advisory

**Scenario**: `RawSessionCreate ↔ SessionCreate roundtrip preserves the nonce` is verified, but the raw/domain conversion also carries `contract`.

**Why it succeeds**: The harness would pass if `From<SessionCreate> for RawSessionCreate` replaced every contract with `"c"`, if `TryFrom` dropped the contract, or if the contract field were accidentally hardcoded. That would break handler-level contract binding while preserving the nonce assertion.

**Suggested defense**: Assert `back.contract() == original.contract()` and use at least two symbolic or bounded contract strings, not one fixed literal.

## 3. [session_create.rs] `user_data()` domain hash is completely uncovered

**Target**: `crates/contracts/core/src/msg/execute/session_create.rs`, impl `HasUserData for SessionCreate`

**Category**: Missing harness for production invariant

**Severity**: serious

**Scenario**: Attested messages depend on `user_data()` hashing the JSON raw message. The Kani surface never checks determinism, field sensitivity, domain separation, or the 32-byte digest placement in the 64-byte userdata buffer.

**Why it succeeds**: A bug that hashes only the nonce, omits the contract, writes the digest into the wrong half of the buffer, or returns all zeroes would not affect accessor or raw nonce roundtrip harnesses. The attestation binding could silently degrade while Kani stays green.

**Suggested defense**: Add bounded harnesses asserting `user_data()` changes when nonce or contract changes, is deterministic for equal messages, and has zeroed bytes `[32..64]` if that is intended. If SHA/serde is too heavy, extract a domain-separation wrapper or test via fixed concrete vectors.

## 4. [session_set_pub_key.rs] Public-key roundtrip is not asserted

**Target**: `crates/contracts/core/src/msg/execute/session_set_pub_key.rs`, harness `session_set_pub_key_raw_roundtrip`

**Category**: Property correctness

**Severity**: serious

**Scenario**: The harness claims raw/domain conversion for `SessionSetPubKey`, but it only checks the nonce after `try_from`.

**Why it succeeds**: `pub_key` is the payload installed into `SESSION` and later exposed in the handler response. If conversion truncated, reordered, replaced, or emptied the `pub_key`, the harness would still pass because it discards the second tuple field.

**Suggested defense**: Assert `p == pub_key` after roundtrip. Use symbolic bounded bytes rather than `vec![0x04; 33]`.

## 5. [session_set_pub_key.rs] Fixed 33-byte key hides attacker-controlled key lengths

**Target**: `crates/contracts/core/src/msg/execute/session_set_pub_key.rs`, harnesses `session_set_pub_key_tuple_roundtrip`, `session_set_pub_key_raw_roundtrip`

**Category**: Coverage gap from bounds

**Severity**: serious

**Scenario**: Both harnesses use a fixed 33-byte vector. Production accepts arbitrary `HexBinary` as `pub_key`.

**Why it succeeds**: Empty keys, very large keys, compressed/uncompressed EC point lengths, malformed encodings, and response attribute cost are not explored. A bug involving zero-length keys, length-dependent serialization, or excessive pubkey sizes would not be visible.

**Suggested defense**: Add `pk_len` as symbolic with a realistic upper bound and include boundary values: `0`, expected compressed length, expected uncompressed length, and a large allowed value. If the protocol requires a concrete ECIES key format, production should validate it and Kani should verify rejection of invalid lengths.

## 6. [session_set_pub_key.rs] `user_data()` does not bind the pubkey under review

**Target**: `crates/contracts/core/src/msg/execute/session_set_pub_key.rs`, impl `HasUserData for SessionSetPubKey`

**Category**: Missing harness for production invariant

**Severity**: serious

**Scenario**: The enclave attestation flow relies on `SessionSetPubKey::user_data()` binding both nonce and public key. No harness checks the hash behavior.

**Why it succeeds**: A regression that hashes only the nonce, serializes the wrong field, or has accidental collision from malformed conversion would still satisfy tuple and nonce roundtrip harnesses.

**Suggested defense**: Add deterministic fixed-vector tests or bounded Kani harnesses proving field sensitivity for nonce and pubkey. If full SHA/serde is too expensive, isolate a lighter domain construction predicate and verify fixed vectors in normal tests.

## 7. [state.rs] `session_with_pub_key_no_panic` is tautological coverage

**Target**: `crates/contracts/core/src/state.rs`, harness `session_with_pub_key_no_panic`

**Category**: Tautological harness

**Severity**: advisory

**Scenario**: The harness calls `Session::with_pub_key` and discards the result.

**Why it succeeds**: The function is simple and returns `Option`; the harness asserts no functional property. It does not check nonce gating, one-shot behavior, pubkey preservation, or rejection on prior `Some`. Existing stronger harnesses cover some of this, but this harness itself can pass while the function accepts all nonces or drops the key.

**Suggested defense**: Remove it or replace it with assertions that `Some` implies nonce equality and stores exactly the supplied key.

## 8. [state.rs] Pubkey length bound excludes real large-input behavior

**Target**: `crates/contracts/core/src/state.rs`, harness `session_with_pub_key_no_panic`

**Category**: Coverage gap from `kani::any_where` bounds

**Severity**: advisory

**Scenario**: `pk_len <= 64` is chosen for tractability, but production `Session::with_pub_key` accepts any `Vec<u8>`.

**Why it succeeds**: Large attacker-supplied pubkeys can affect storage size, event construction in `session_set_pub_key` via `to_hex()`, gas, and serialization. The harness cannot detect failures or unacceptable behavior outside 64 bytes.

**Suggested defense**: Add production validation for pubkey length and format, then verify that validated bound. If arbitrary length is intentionally accepted, add explicit boundary tests outside Kani.

## 9. [state.rs] LightClient threshold harness has an overflow-spec bug

**Target**: `crates/contracts/core/src/state.rs`, harness `light_client_opts_threshold_validation`

**Category**: Spec-vs-implementation drift

**Severity**: serious

**Scenario**: `LightClientOpts::new` checks `if 3 * numerator < denominator`. In Rust debug/Kani arithmetic, `3 * numerator` can overflow for `numerator > u64::MAX / 3`.

**Why it succeeds**: The harness attempts to avoid checking the small-threshold assertion when `num > u64::MAX / 3`, but the production function has already computed `3 * numerator` before the harness can branch on the result. The property being verified is not a robust threshold predicate over `u64`; it is the current unchecked arithmetic expression.

**Suggested defense**: Change production to `numerator.checked_mul(3)` or compare as `numerator < denominator.div_ceil(3)` without overflow. Then verify the intended threshold relation for all `u64`.

## 10. [state.rs] `kani_slow` LightClient harnesses may not run in CI

**Target**: `crates/contracts/core/src/state.rs`, harnesses `light_client_opts_threshold_validation`, `light_client_opts_height_bounds`

**Category**: `kani_slow` vs `kani` gating

**Severity**: serious

**Scenario**: The only harnesses for `LightClientOpts` are behind `#[cfg(kani_slow)]`, with a comment suggesting manual execution using special flags.

**Why it succeeds**: If CI runs only standard `cargo kani`, these properties are not verified. The most security-relevant config validation in `state.rs`, trust threshold and trusted height, becomes documentation rather than enforced verification.

**Suggested defense**: Add a CI job that runs `kani_slow` harnesses or split the error-heavy paths so standard Kani can verify them. Track slow-harness execution in the Colosseum ledger.

## 11. [state.rs] Config raw/domain roundtrip is missing

**Target**: `crates/contracts/core/src/state.rs`, types `Config`, `RawConfig`, `LightClientOpts`, `RawLightClientOpts`

**Category**: Missing harness for production invariant

**Severity**: serious

**Scenario**: Instantiate stores `RawConfig` with `mr_enclave`, light-client opts, and `zkdcap_vkey`. The harness suite never verifies raw/domain conversion for config.

**Why it succeeds**: A regression that drops `zkdcap_vkey`, corrupts `mr_enclave`, accepts malformed `trusted_hash`, or changes light-client option serialization would not be caught by existing session-only harnesses.

**Suggested defense**: Add bounded raw/domain roundtrip harnesses for `Config` and `LightClientOpts`, including `zkdcap_vkey = None` and `Some`.

## 12. [sealed-auction/state.rs] Kani verifies helpers, not the handler code that mutates storage

**Target**: `examples/sealed-auction/contracts/src/state.rs`, harnesses `start_auction_guard_total`, `submit_bid_guard_exact`, `resolve_guard_round_id_must_match`

**Category**: Helper-functions-under-test

**Severity**: serious

**Scenario**: The helpers are said to mirror `contract.rs`, but the production handlers inline their own checks instead of calling these helpers.

**Why it succeeds**: If `exec_submit_bid`, `exec_start_auction`, or `exec_resolve` drift from the helper logic, Kani remains green. For example, changing `env.block.time >= round.auction_end` to `>` in the handler would allow bids exactly at the deadline while `can_submit_bid` still proves strict-before semantics.

**Suggested defense**: Make handlers call the verified helpers, or add a test that checks helper/handler equivalence through `cw_multi_test` for representative boundary states.

## 13. [sealed-auction/state.rs] `bid_count += 1` overflow is not covered

**Target**: `examples/sealed-auction/contracts/src/contract.rs`, `exec_submit_bid`; missing from `examples/sealed-auction/contracts/src/state.rs`

**Category**: Missing harness for production invariant

**Severity**: serious

**Scenario**: `round.bid_count` is a `u32` and increments with `round.bid_count += 1`.

**Why it succeeds**: None of the sealed-auction harnesses model bid count arithmetic or storage state. In a long-running or malicious state scenario, `u32::MAX + 1` can panic in debug or wrap in optimized Wasm semantics depending on build configuration. The Kani suite proves only phase/deadline/duplicate predicates.

**Suggested defense**: Use `checked_add(1)` and return an error on overflow. Add a Kani harness for the bid-count transition.

## 14. [sealed-auction/state.rs] Vickrey harness assumes reserve filtering but does not verify it

**Target**: `examples/sealed-auction/contracts/src/state.rs`, harnesses `vickrey_single_bidder_pays_reserve`, `vickrey_two_bidders_second_price`

**Category**: Spec-vs-implementation drift

**Severity**: serious

**Scenario**: The helper docs say bids are pre-decrypted and reserve-filtered. The harnesses enforce `bid >= reserve` with `kani::assume`, but the public contract accepts opaque ciphertext and trusts the enclave result.

**Why it succeeds**: The verified helper property only holds under an off-chain precondition not enforced by the contract. If the enclave includes sub-reserve bids, reports a winner with price below reserve, or reports a bid count inconsistent with sealed bids, the contract accepts the attested result after checking only phase and round ID.

**Suggested defense**: Add enclave-side verification harnesses for reserve filtering, or contract-side checks on result fields that are public and enforceable. At minimum, document this as a composition obligation in the ledger.

## 15. [sealed-auction/state.rs] Resolve result consistency is not verified

**Target**: `examples/sealed-auction/contracts/src/state.rs`, missing harness for `exec_resolve`

**Category**: Missing harness for production handler flow

**Severity**: serious

**Scenario**: `exec_resolve` stores `winner`, `price`, and `bid_count` from the attested message. The Kani harness only checks `phase` and `round_id`.

**Why it succeeds**: A result can claim `bid_count` unrelated to `round.bid_count`, a winner when no bids exist, or a nonzero price with no winner. These may violate auction intent but pass the verified `can_resolve` predicate and production handler.

**Suggested defense**: Add explicit result validity predicates and harness them: no winner implies zero or reserve-consistent price, `result.bid_count <= round.bid_count`, and winner presence implies at least one valid bid. If these are enclave-only obligations, add them to the composition ledger.

## 16. [pingpong/state.rs] Harnesses prove struct field discipline, not contract behavior

**Target**: `examples/pingpong/contracts/src/state.rs`, harnesses `ping_field_roundtrip`, `pong_field_roundtrip`, `ping_pong_pubkey_symmetry`, `ping_clone_preserves_fields`

**Category**: Tautological harnesses

**Severity**: serious

**Scenario**: Most pingpong harnesses construct a struct and assert its fields equal the values just assigned.

**Why it succeeds**: These assertions are guaranteed by Rust struct construction and clone semantics. They do not verify storage key derivation, overwrite behavior, attested `Pong` authorization, or that `Pong` corresponds to a prior `Ping`.

**Suggested defense**: Replace with harnesses or tests over extracted pure storage-key functions and handler preconditions. For storage behavior, use `cw_multi_test` or unit tests rather than Kani if symbolic storage is impractical.

## 17. [pingpong/state.rs] Full `to_hex()` key derivation is explicitly skipped

**Target**: `examples/pingpong/contracts/src/state.rs`, comment excluding full `HexBinary::to_hex()`

**Category**: Coverage gap from bounded/unmodeled helper

**Severity**: serious

**Scenario**: Production stores both ping and pong under `pubkey.to_hex()`. The harnesses avoid full `to_hex()` over arbitrary lengths.

**Why it succeeds**: The critical invariant is that equal pubkey bytes map to the same storage key and different relevant pubkeys do not accidentally collide under the key encoding. The suite checks only `HexBinary` clone equality, not the string key actually used in `PINGS.save`.

**Suggested defense**: Extract `fn ping_key(pubkey: &HexBinary) -> String` and verify fixed vectors and bounded symbolic lengths. Add normal tests for arbitrary longer pubkeys.

## 18. [pingpong/state.rs] No harness covers unsolicited `Pong` overwrite

**Target**: `examples/pingpong/contracts/src/contract.rs`, `execute::pong`; missing from `examples/pingpong/contracts/src/state.rs`

**Category**: Missing harness for production invariant

**Severity**: serious

**Scenario**: `pong` writes `PINGS.save(pong.pubkey.to_hex(), &pong.response)` without checking that a corresponding ping exists.

**Why it succeeds**: The Kani harness proves only that a `Pong` constructed with a pubkey stores that pubkey field. It does not express the intended lifecycle that a pong answers a prior ping. An attested enclave message can create or overwrite any pubkey slot if attestation passes.

**Suggested defense**: Decide whether unsolicited pong creation is allowed. If not, production should require `PINGS.has(key)` before saving, and the invariant should be tested.

## 19. [transfers/state.rs] Harnesses verify mirror functions, not the vulnerable production `drain`

**Target**: `examples/transfers/contracts/src/state.rs`, harnesses `h1_drain_in_bounds_safe`, `h2_drain_out_of_bounds_detected`; production `contract.rs::execute::update`

**Category**: Spec-vs-implementation drift

**Severity**: critical

**Scenario**: The harness proves `safe_drain_len` returns `None` when `quantity > len`, while production directly executes `requests.drain(0..msg.quantity as usize)` with no guard.

**Why it succeeds**: This is a coverage gap masquerading as verification. The harness documents the missing precondition but does not verify that production enforces it. An attested `UpdateMsg` with `quantity > requests.len()` can panic the contract execution.

**Suggested defense**: Add a production check before `drain` and return a contract error when `quantity > requests.len()`. Then verify the production guard or make `update` call a verified helper.

## 20. [transfers/state.rs] Withdrawal sum harness proves a non-production property

**Target**: `examples/transfers/contracts/src/state.rs`, harness `h4_withdrawal_sum_no_overflow`; production `contract.rs::execute::update`

**Category**: Property correctness

**Severity**: advisory

**Scenario**: Production does not sum withdrawals. It maps each `(user, funds)` to an independent `BankMsg::Send`.

**Why it succeeds**: A bounded total-sum property over up to eight `u64` amounts does not constrain production behavior. It does not verify per-message conversion, denom validity, duplicate recipients, total solvency, or conservation against encrypted state.

**Suggested defense**: Remove this as a claimed production proof or relabel it as a future-design helper. Add tests for actual `BankMsg::Send` construction and any intended solvency invariant.

## 21. [transfers/state.rs] Deposit and withdrawal amount bounds exclude real `Uint128` values

**Target**: `examples/transfers/contracts/src/state.rs`, harnesses `h4_withdrawal_sum_no_overflow`, `h8_deposit_total_bounded`

**Category**: Coverage gap from amount bounds

**Severity**: serious

**Scenario**: The harnesses bound individual deposits and withdrawals to `u64::MAX`, but production uses `Uint128`.

**Why it succeeds**: Any bug or invariant failure involving high `u128` values is excluded. This is especially relevant because the contract converts `Uint128` to `u128` and emits bank messages without checking aggregate conservation against encrypted balances.

**Suggested defense**: Verify properties over full `u128` where possible, or explicitly make the production contract reject amounts above the proven bound.

## 22. [transfers/state.rs] Sequence monotonicity harness is detached from production state

**Target**: `examples/transfers/contracts/src/state.rs`, harness `h6_sequence_strictly_monotone`

**Category**: Helper-functions-under-test

**Severity**: serious

**Scenario**: The harness verifies local `next_seq(prev) = prev.checked_add(1)`, but the transfers contract code shown does not update sequence state in `deposit`, `withdraw`, `transfer_request`, or `update`.

**Why it succeeds**: The proof says nothing about whether replay protection is actually applied to transfer requests. It verifies a helper not invoked by the contract path under review.

**Suggested defense**: Point the harness at the actual `RawSequenced` verification path or add integration tests proving replayed `TransferRequest` messages are rejected.

## 23. [transfers/state.rs] Request dispatch harness models discriminants, not request contents

**Target**: `examples/transfers/contracts/src/state.rs`, harness `h7_request_dispatch_total`

**Category**: Tautological harness

**Severity**: advisory

**Scenario**: The harness restricts `tag < 3`, constructs one of three variants, matches it, and asserts the tag matches.

**Why it succeeds**: This primarily proves Rust enum matching works. It avoids the values that matter: ciphertext length, address validation, deposit amount, and queue ordering.

**Suggested defense**: Replace with properties over queue append/drain behavior for actual `Request` values, including order preservation and front-drain semantics.

## 24. [ranked-choice/verification.rs] Verified predicates are not called by handlers

**Target**: `examples/ranked-choice/contracts/src/verification.rs`, all guard harnesses; production `contract.rs`

**Category**: Helper-functions-under-test

**Severity**: serious

**Scenario**: `candidates_valid`, `can_cast_ballot`, `can_tally`, and `phase_transition_allowed` mirror handler logic, but production handlers inline their checks.

**Why it succeeds**: Handler drift is invisible. A future change in `exec_cast_ballot` deadline comparison, duplicate check, or phase condition would not affect the Kani proofs.

**Suggested defense**: Refactor handlers to call the verified predicates, or add equivalence tests between handler outcomes and predicate outcomes for boundary cases.

## 25. [ranked-choice/verification.rs] Candidate validation uses `u8`, production uses `String`

**Target**: `examples/ranked-choice/contracts/src/verification.rs`, function `candidates_valid`, harnesses `h_candidates_*`

**Category**: Spec-vs-implementation drift

**Severity**: advisory

**Scenario**: The harness models candidates as byte identifiers, while production candidate IDs are `String`.

**Why it succeeds**: The structural duplicate property is similar, but string-specific cases are skipped: empty strings, Unicode normalization, very long names, case folding expectations, and serialization costs. A production policy bug around candidate names would not be seen.

**Suggested defense**: Add bounded `String` or byte-vector tests for production candidate validation, including empty and duplicate string cases. If only byte identity matters, document that no normalization is intended.

## 26. [ranked-choice/verification.rs] Phase-transition harness checks only three forbidden edges

**Target**: `examples/ranked-choice/contracts/src/verification.rs`, harness `h_phase_transition_no_skip`

**Category**: Property correctness

**Severity**: advisory

**Scenario**: `h_phase_transition_no_skip` computes `ok` for all phase pairs but asserts only three bad transitions.

**Why it succeeds**: If `phase_transition_allowed` accidentally allowed other forbidden transitions, such as `Tallying -> Voting`, `Complete -> Complete`, or `Setup -> Tallying`, the harness would still pass unless one of the three checked cases was affected.

**Suggested defense**: Assert exact equivalence against the intended transition relation for all 16 phase pairs.

## 27. [ranked-choice/verification.rs] IRV properties are too local to verify election correctness

**Target**: `examples/ranked-choice/contracts/src/verification.rs`, harnesses `h_filter_ballot_len_bounded`, `h_first_active_choice_progress`

**Category**: Missing harness for invariants production depends on

**Severity**: serious

**Scenario**: The harnesses verify ballot filtering length and first active choice for fixed small arrays, but not the full IRV tally, elimination order, tie handling, or reported result consistency.

**Why it succeeds**: The contract accepts the enclave's `TallyMsg` after checking only phase and election ID. A bad enclave result with the wrong winner, wrong total ballot count, or invalid rounds can pass production checks and is not ruled out by these local helper proofs.

**Suggested defense**: Add enclave-side or pure IRV harnesses for winner correctness, tie-breaking, elimination monotonicity, and total ballot accounting. Add contract-side checks for public consistency fields such as `total_ballots <= election.ballot_count`.

## META

Per-file attack counts:

`session_create.rs`: 3  
`session_set_pub_key.rs`: 3  
`state.rs`: 5  
`sealed-auction/state.rs`: 4  
`pingpong/state.rs`: 3  
`transfers/state.rs`: 5  
`ranked-choice/verification.rs`: 4

Recurring patterns:

Tautological struct-field harnesses appear in `pingpong` and parts of `state.rs`. Several harnesses verify pure mirror helpers that production handlers do not call, especially sealed-auction, transfers, and ranked-choice. Bounded assumptions exclude meaningful attacker inputs: fixed 33-byte pubkeys, `pk_len <= 64`, `u64`-bounded amounts for `Uint128` production values, and small fixed arrays for ballot logic. Slow-gated LightClient harnesses likely create a CI verification gap. Attested-result handlers often verify only message identity fields, then trust enclave-supplied public results without local consistency checks.

Recommendation:

Treat Round E as finding a real Kani coverage gap, not merely minor harness polish. Highest-priority fixes are production guard extraction plus handler reuse for verified predicates, a real guard for transfers `update` over-drain, CI execution or refactoring of `kani_slow` LightClient harnesses, and new harnesses for attestation userdata binding. Production-code follow-ups should be filed for transfers drain bounds, pubkey format/length validation, counter overflow checks, and result consistency checks in sealed-auction and ranked-choice.

