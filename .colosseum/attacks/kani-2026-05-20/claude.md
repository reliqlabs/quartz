# Round E Kani harness adversarial review — Claude (subagent, file-access)

- Target files (7, 41 harnesses, 1666 lines):
  - `crates/contracts/core/src/msg/execute/session_create.rs` (2 harnesses, 103 lines)
  - `crates/contracts/core/src/msg/execute/session_set_pub_key.rs` (2 harnesses, 111 lines)
  - `crates/contracts/core/src/state.rs` (6 harnesses incl. 2 behind `#[cfg(kani_slow)]`, 380 lines)
  - `examples/sealed-auction/contracts/src/state.rs` (9 harnesses, 305 lines)
  - `examples/pingpong/contracts/src/state.rs` (6 harnesses, 144 lines)
  - `examples/transfers/contracts/src/state.rs` (8 harnesses, 282 lines)
  - `examples/ranked-choice/contracts/src/verification.rs` (8 harnesses, 341 lines)
- Intent doc: `/Users/mvid/Development/reliq/quartz/CLAUDE.md`
- Date: 2026-05-20
- Round: E
- Adversary: Claude Opus 4.7 (Agent subagent in Claude Code, file-access)

## Per-file verdicts

- VERDICT (msg/execute/session_create.rs): **HOLDS WITH CAVEATS** — both harnesses pin trivial accessor identity on a fixed contract string `"c"`; nonce-bound coverage real, but contract-string discipline (the handler's `addr_validate` + `addr != env.contract.address` check) untouched.
- VERDICT (msg/execute/session_set_pub_key.rs): **HOLDS WITH CAVEATS** — pub_key bound to constant `vec![0x04u8; 33]`; pub_key length / content discipline (e.g. compressed-secp256k1 33-byte constraint, empty rejection) never exercised. SHA-256 inside `user_data()` not covered.
- VERDICT (state.rs framework): **WEAKENS** — `kani_slow`-gated harnesses do not run in CI; `session_pubkey_set_once` is *only* tested with matching nonce → fails to test the nonce-mismatch-after-set composition; `Session::nonce()` panics in production via `expect("correct by construction")` if HexBinary is ever non-32-bytes (no `RawConfig::try_from`-class harness).
- VERDICT (sealed-auction/state.rs): **WEAKENS** — Vickrey tie-break harness only checks 3 equal bids (`[v,v,v]`); admin authorization, queue-clearing in `exec_start_auction`, and the *attested-msg/round_id-binding gap* untested.
- VERDICT (pingpong/state.rs): **BREAKS** — every harness tests struct-field roundtrip; **none** exercise the production handler. Carries forward Round C critical #13 (Rust `execute::ping` unconditionally overwrites, no `ErrSlotOccupied`), invisible to Kani because the harness layer is a strict subset of trivial getter/setter checks.
- VERDICT (transfers/state.rs): **BREAKS** — H1/H2 prove a `safe_drain_len` helper that *does not exist in the contract*. The production `requests.drain(0..msg.quantity as usize)` at `contract.rs:194` has no guard. Carries forward Round C critical #17 (quantity-vs-prefix consistency) and #16 (BankMsg::Send plaintext leak) — neither is reachable from any harness in this file.
- VERDICT (ranked-choice/verification.rs): **WEAKENS** — verifies pure predicates that mirror handler guards, but the actual `exec_create_election` candidate-duplicate check uses `HashSet<&str>` over `String` (not `u8`); `exec_tally` accepts results with arbitrary `result.winner` (no membership-in-candidates check); admin authorization, `BALLOTS` clearing on re-create, and the `(Voting,Tallying)` transition (modeled as allowed but no Rust handler can reach it) all uncovered.

---

## 1. [pingpong/state.rs] Six harnesses test struct-field roundtrip, zero test the contract

- **Target**: `examples/pingpong/contracts/src/state.rs:28-144` (whole `verification` module)
- **Category**: Helper-functions-under-test / spec-vs-implementation drift / missing-harnesses-for-invariants
- **Severity**: critical
- **Scenario**: All six harnesses (`pings_key_stable`, `ping_field_roundtrip`, `pong_field_roundtrip`, `ping_pong_pubkey_symmetry`, `hexbinary_clone_roundtrip`, `ping_clone_preserves_fields`) verify that struct literals preserve their fields under `clone()` and that `HexBinary::from(Vec<u8>)` is total. None of them touch `execute::ping` or `execute::pong` at `contract.rs:61-89`. The production handler does `PINGS.save(deps.storage, ping.pubkey.to_hex(), &ping.message)` unconditionally (no `Map::has` check, no `ErrSlotOccupied` guard). Round C identified this as critical drift: the Quint spec models a `ping` failure-arm that does not exist in Rust. The Kani harness surface here is *strictly weaker* than even the buggy Quint spec — it doesn't model `ping` semantics at all.
- **Why it succeeds**: `ping.pubkey == cloned.pubkey` is true by `#[derive(Clone)]` for any `cw_serde`-derived struct. The comment at lines 22-26 admits "Mutable storage (the PINGS Map) is exercised at the cw_multi_test integration layer; here we verify the building blocks". But there are no pure-logic *guard* predicates to mirror (unlike sealed-auction's `can_submit_bid` or ranked-choice's `can_cast_ballot`). Pingpong has no extracted guard helpers — the handler is two lines of `PINGS.save`. The harness surface therefore has nothing protocol-relevant to verify and falls back to derived-trait sanity.
- **Suggested defense**: Either (a) accept that pingpong is unverifiable at the Kani layer and remove the harnesses (they signal nothing); or (b) extract `can_overwrite_slot(prior: Option<&HexBinary>) -> bool` and `can_pong(prior: Option<&HexBinary>) -> bool` pure helpers, then assert in Kani that `can_overwrite_slot` is *always* true under current contract semantics (which makes the Round C drift visible at the harness level) or *never* true if the contract is patched. As-is, the file gives a false positive verification signal.

## 2. [transfers/state.rs] `safe_drain_len` is a helper-that-does-not-exist; production has no guard

- **Target**: `examples/transfers/contracts/src/state.rs:41-92` (H1, H2) vs `examples/transfers/contracts/src/contract.rs:194`
- **Category**: Helper-functions-under-test
- **Severity**: critical
- **Scenario**: H1 and H2 prove that the *helper* `safe_drain_len(len, quantity)` correctly classifies in-bounds vs out-of-bounds drains. The helper exists *only inside the `verification` module* (state.rs:41-48). The production handler at `contract.rs:194` is `requests.drain(0..msg.quantity as usize)` with **no preceding bounds check**. If `msg.quantity as usize > requests.len()`, `Vec::drain` panics — and since `msg.quantity` comes from the attested `UpdateMsg`, a compromised-but-still-attested enclave (or any bug in enclave-side queue tracking) crashes the contract irrecoverably. The harness's own docstring at lines 95-103 says "The contract today has no such guard, so this harness documents the missing precondition" — Kani is verifying a defense-in-depth predicate that *isn't in the code*.
- **Why it succeeds**: The harnesses pass because `safe_drain_len` is total. They do not, and cannot under their current shape, fail when `contract.rs:194` panics on `quantity > len`. The "Mutation-test catch" notes in the harness docstring describe mutations to the *helper*, not to `contract.rs`.
- **Suggested defense**: Move the guard into the production handler (`if msg.quantity as usize > requests.len() { return Err(InvalidQuantity); }`), then have H1/H2 call that production code path. Or, at minimum, add a harness that constructs a `Vec<Request>` of length `len`, calls the production function with `quantity > len`, and asserts `Result::Err` — currently no such harness exists.

## 3. [transfers/state.rs] No harness covers Round C critical #17 (quantity-vs-prefix consistency)

- **Target**: missing harness for `examples/transfers/contracts/src/contract.rs:182-212` (`execute::update`)
- **Category**: Missing harnesses for invariants the production code depends on / carry-over from Quint reviews
- **Severity**: critical
- **Scenario**: Round C found that the contract has no check that the drained queue prefix is *consistent with* the `withdrawals` list in the attested UpdateMsg. A malicious enclave can set `quantity=0` while supplying nonzero `withdrawals` → contract issues `BankMsg::Send` without draining the queue → replay-on-next-update. Or set `quantity=N` while supplying empty `withdrawals` → silently drop pending requests. The Kani surface has 8 harnesses on this file, *none* of which assert the binding between `quantity`, the drained prefix's variant set (Withdraw vs Deposit vs Transfer), and the issued `BankMsg::Send` list.
- **Why it succeeds**: H7 (`h7_request_dispatch_total`) verifies the *match* is exhaustive but doesn't assert that *every* `Request::Withdraw` in the drained prefix produces exactly one `BankMsg::Send` in `withdrawals`. The mirror between the queue prefix and `withdrawals` is the load-bearing safety property, and it isn't anywhere in the harness set.
- **Suggested defense**: Add `h9_withdrawals_consistent_with_drained_prefix(requests: &[Request], quantity: usize, withdrawals: &[(Addr, Uint128)])`: assert that the set of `Withdraw(addr)` entries in `requests[0..quantity]` equals (as multiset) the addr-prefixes of `withdrawals`. This will *fail* against the current contract (because no such check exists), which is the right outcome — it makes the Round C drift visible.

## 4. [transfers/state.rs] H4 / H8 do not constrain real amount distribution

- **Target**: `examples/transfers/contracts/src/state.rs:155-171` (H4), `267-279` (H8)
- **Category**: Coverage gaps from `kani::any_where` bounds
- **Severity**: serious
- **Scenario**: H4 sums 8 amounts each bounded by `u64::MAX` and proves no overflow. H8 does the same for deposits. Both bounds are explicitly chosen so the sum trivially fits in u128 (`8 * u64::MAX < u128::MAX` by ~2^60 margin). The Rust `Uint128` is u128. The real failure mode (an attacker-controlled sequence of 8 deposits of `u128::MAX/8 + 1` each) is *excluded by construction* via the `as u128` cast from u64.
- **Why it succeeds**: The harness's own comment at line 156-157 admits the bound was chosen for representability (`8 * u64::MAX < u128::MAX`). The actual production type is `Uint128`, which can hold values far exceeding `u64::MAX`. `apply_deposit` in the enclave path doesn't impose u64 bounds. The conservation invariant (sum of balances ≤ u128::MAX) is unverified for u128 values.
- **Suggested defense**: Replace `let a: u64 = kani::any(); amounts[i] = a as u128` with `let a: u128 = kani::any(); kani::assume(a <= MAX_PER_DEPOSIT);` where `MAX_PER_DEPOSIT` reflects a real protocol bound; if no protocol bound exists, the harness needs to prove overflow detection (return `None`) for `u128`-saturated inputs.

## 5. [transfers/state.rs] H7 hides Round C critical #16 (BankMsg::Send plaintext leak)

- **Target**: missing harness for `examples/transfers/contracts/src/contract.rs:201-207`
- **Category**: Carry-over from Quint reviews / privacy invariant
- **Severity**: serious
- **Scenario**: H7 enumerates `Request` variants and asserts the match is total. But the privacy-load-bearing property is that `BankMsg::Send { to_address, amount }` (`contract.rs:204-206`) reveals the withdrawal amount on-chain, which (per Round C critical #16) leaks the user's pre-withdraw balance. Kani isn't the right tool for adversarial-inference proofs, but the harness set could at minimum assert that "for every Withdraw request, the resulting BankMsg::Send amount equals the user's balance" — making the disclosure explicit at the harness layer.
- **Why it succeeds**: The privacy claim is asserted nowhere in the Kani harnesses. The Quint critical was unaddressed at the Quint layer per Round C synthesis; the Kani layer carries forward the gap.
- **Suggested defense**: Even if the leak is accepted by design, add a *documented* harness asserting `forall withdrawal (user, amount): amount > 0 => leak_is_public(user, amount)` so the property is at least surfaced at the verification layer.

## 6. [pingpong/state.rs] Round C critical #12 (vacuous plaintext_private) has no Kani counterpart

- **Target**: missing harness for `examples/pingpong/contracts/src/contract.rs::execute::pong`
- **Category**: Carry-over from Quint reviews
- **Severity**: serious
- **Scenario**: Round C synthesis Critical #12 found `inv_plaintext_private` is vacuous because the encryption is XOR-style and key-reuse leaks plaintext. The harness set has six struct-field-roundtrip harnesses but no harness over the actual encryption helper at `examples/pingpong/enclave/src/request.rs:124`. (request.rs is enclave-side, not contract-side, so the file boundary is admittedly tricky — but the contract's pong handler is the slot-overwrite mechanism that enables the key-reuse pattern.)
- **Why it succeeds**: The harness set's scope is `contracts/src/state.rs`. The pong-handler-driven multi-overwrite-against-same-pubkey scenario is the protocol-relevant property. The harnesses test struct identity, not protocol invariants.
- **Suggested defense**: Either extend the harness scope (a Kani harness over enclave/src/request.rs for ciphertext-non-uniqueness under same-key, two-ping scenario), or accept that Kani cannot verify this privacy property and document the gap in the file header.

## 7. [framework/state.rs] `kani_slow` harnesses don't run in CI; LightClientOpts validation is dormant

- **Target**: `crates/contracts/core/src/state.rs:324-379` (`light_client_opts_threshold_validation`, `light_client_opts_height_bounds`)
- **Category**: `kani_slow` gating
- **Severity**: serious
- **Scenario**: Both LightClientOpts harnesses are gated `#[cfg(kani_slow)]`. There is no `kani_slow` configuration in any Cargo workspace file, CI script, or `.github/` workflow. `grep -rn "kani_slow"` returns only `crates/contracts/core/Cargo.toml:39: unexpected_cfgs = { ... 'cfg(kani_slow)' ... ]}` (which just suppresses the lint warning). The harnesses are unreachable from the default `cargo kani` invocation. The two non-trivial threshold-validation properties (3*num<den boundary, i64::MAX height bound) are therefore *unverified in CI* — they will pass cargo check but never run as proofs.
- **Why it succeeds**: The comment at lines 314-319 explicitly says they're behind the gate because `StdError::msg` constructs a backtrace via `std::backtrace::Backtrace`. The remediation suggested in the comment (`--no-unwinding-checks`) is not standard practice and bypasses Kani's safety. The threshold validation is the only Kani check on the *only* validation logic in `LightClientOpts::new` — and it doesn't run.
- **Suggested defense**: Replace `StdError::msg(format!(...))` in the LightClientOpts error paths with `StdError::generic_err(static_str)` (no backtrace, no allocation, no unwind explosion) so the harnesses can come out from behind `kani_slow`. Alternatively, refactor the validation into a pure `fn validate_threshold(num: u64, den: u64) -> Result<(), &'static str>` helper and Kani-verify that, leaving error-message construction at the call site.

## 8. [framework/state.rs] `Session::nonce()` panics in production but no harness covers the panic path

- **Target**: `crates/contracts/core/src/state.rs:238-240` (`Session::nonce`)
- **Category**: Missing harnesses for invariants the production code depends on
- **Severity**: serious
- **Scenario**: `Session::nonce()` does `self.nonce.to_array().expect("correct by construction")`. The "correct by construction" claim is that `Session` is only ever constructed via `Session::create(nonce: Nonce)` where `Nonce = [u8; 32]`, so the inner `HexBinary` is always 32 bytes. But `Session` is `#[cw_serde]` and the inner `nonce: HexBinary` is `pub` to the deserializer. If a malformed `Session` is ever loaded from storage (e.g., a migration bug, or a manual `Item::save` with non-32-byte HexBinary), the next `.nonce()` call panics the contract. No harness verifies the invariant "every `Session` reachable via `SESSION.load` has 32-byte nonce".
- **Why it succeeds**: `session_nonce_roundtrip` (lines 305-312) only constructs via `Session::create(nonce)` where `nonce: Nonce = kani::any()`, so it tests the success path. The deserialization path is invisible. Kani isn't great at serde, but a focused harness `let raw_bytes: [u8; N] = kani::any(); let s = serde_json::from_slice::<Session>(&raw_bytes)` (or constructing via the type's serde representation) would expose whether arbitrary inputs can produce a `Session` whose `nonce()` panics.
- **Suggested defense**: Either change `Session::nonce()` to return `Result<Nonce, StdError>` (no panic on the load path), or add a `TryFrom<&[u8]>` constructor on `Session` that validates the nonce length at deserialization time, and add a Kani harness covering that branch.

## 9. [framework/state.rs] `session_pubkey_set_once` only tests matching nonce on second set

- **Target**: `crates/contracts/core/src/state.rs:291-303`
- **Category**: Coverage gap / tautological harness
- **Severity**: advisory
- **Scenario**: The harness fixes `nonce: Nonce = kani::any()` once, then calls `session.with_pub_key(nonce, pk1)` (matching) followed by `session.with_pub_key(nonce, pk2)` (also matching). Both calls use the same nonce. The second call's rejection is driven by `self.pub_key.is_none()` being false. But the *interaction* between nonce-mismatch and pub_key-already-set is uncovered. A useful harness would let the second call's nonce be a free `kani::any()` — currently the two-dimensional precondition matrix collapses to a one-dimensional case.
- **Why it succeeds**: The assertion is correct but narrow. It does not catch a regression where (e.g.) the guard is changed to `self.nonce == nonce || self.pub_key.is_none()` (allows double-set if nonce matches, even though pub_key is Some). Under the current harness that mutation would still pass because pub_key is Some.
- **Suggested defense**: Replace the second `with_pub_key(nonce, pk2)` call with `with_pub_key(kani::any(), pk2)` and assert `result.is_none()` regardless of the second-call nonce.

## 10. [framework/msg/execute/session_create.rs] Fixed contract string `"c"` defeats coverage

- **Target**: `crates/contracts/core/src/msg/execute/session_create.rs:84-91, 96-102`
- **Category**: Coverage gap from `kani::any_where` bounds (string discipline)
- **Severity**: serious
- **Scenario**: Both harnesses fix `contract = String::from("c")`. The production handler at `handler/execute/session_create.rs:16-19` calls `deps.api.addr_validate(self.contract())?` and rejects if `addr != env.contract.address`. The harness verifies only that the accessor returns the same `String` it was constructed with — i.e., it verifies `getter == constructor-arg`, a tautology under Rust's by-value semantics. The actual security property (contract-address validation rejects mismatched bech32) is invisible to Kani.
- **Why it succeeds**: The comment at lines 83-84 admits the choice was for tractability ("we're verifying the struct's field-discipline, not String semantics"). But the *user_data* digest at line 60-72 depends on the entire JSON-serialized contract string, including any bech32 prefix. A harness over `user_data()` with a free contract string would exercise SHA-256 over variable-length input — Kani is not the right tool for SHA, but it could still be parameterized over a small fixed length (say 1, 2, or 3 distinct constants) to catch byte-discipline regressions.
- **Suggested defense**: Add a harness `fn session_create_user_data_changes_with_contract()` that constructs two `SessionCreate` values with the same nonce but different contract strings (`"c1"` vs `"c2"`) and asserts `msg1.user_data() != msg2.user_data()`. Bounded SHA-256 input but verifies the digest's contract-field sensitivity. Currently no harness witnesses that `contract` participates in `user_data`.

## 11. [framework/msg/execute/session_set_pub_key.rs] Fixed `vec![0x04u8; 33]` blocks pub_key shape testing

- **Target**: `crates/contracts/core/src/msg/execute/session_set_pub_key.rs:87-95, 100-110`
- **Category**: Coverage gap / spec-vs-implementation drift
- **Severity**: serious
- **Scenario**: Both harnesses fix `pub_key = vec![0x04u8; 33]` (compressed secp256k1, but content irrelevant). The production handler at `handler/execute/session_set_pub_key.rs:13-27` accepts *any* `Vec<u8>` as pubkey — no length check, no 0x02/0x03/0x04 prefix check. The harness's choice of 33 bytes is intentional (matches secp256k1 compressed) but the contract has no such constraint, so the harness is testing what *should* happen but not what *does* happen. A 0-byte pubkey or a 65-byte pubkey would also be accepted by the handler. If the protocol requires 33-byte secp256k1 pubkeys (ECIES bedrock per CLAUDE.md), the lack of a length check is a real gap that this harness *hides* by always passing the well-formed value.
- **Why it succeeds**: The roundtrip is tautological for the well-formed case. The boundary cases (empty pub_key, oversized pub_key, non-secp256k1-shaped bytes) are not in the harness state space.
- **Suggested defense**: Add `let pk_len: usize = kani::any_where(|&n| n <= 65); let pub_key: Vec<u8> = vec![0u8; pk_len];` and assert that production behavior matches the protocol's pub_key-shape requirement — either rejecting empty / non-33-byte input (which would fail the harness and motivate adding the check) or accepting it (which surfaces the shape-permissiveness as a documented property).

## 12. [framework/state.rs] `session_with_pub_key_no_panic` is tautological

- **Target**: `crates/contracts/core/src/state.rs:255-266`
- **Category**: Tautological harness
- **Severity**: advisory
- **Scenario**: The harness calls `session.with_pub_key(check_nonce, pub_key)` and discards the result (`let _result = ...`). Since `with_pub_key` returns `Option<Self>` and never has a panicking path (no `unwrap`, no array indexing on user input, no integer arithmetic), Kani is verifying that *Rust's type system enforces totality on Option-returning functions*. This is true for *every* such function in Rust — the harness is structurally meaningless.
- **Why it succeeds**: The function body at lines 229-236 contains only a struct comparison and a field move. No panic source exists. The only way the harness could fail is via OOM during `vec![0u8; pk_len]` allocation with `pk_len = usize::MAX`, but the bound `n <= 64` excludes that.
- **Suggested defense**: Either remove the harness (it adds nothing the type system doesn't give for free), or strengthen it to verify a non-trivial post-condition (e.g., that the returned `Some(s)` satisfies `s.pub_key.is_some()`).

## 13. [ranked-choice/verification.rs] `candidates_valid` mirror uses `u8` not `String`

- **Target**: `examples/ranked-choice/contracts/src/verification.rs:21-35` vs `contract.rs:67-77`
- **Category**: Helper-functions-under-test
- **Severity**: serious
- **Scenario**: The harness's `candidates_valid(candidates: &[u8])` uses an O(n^2) double loop on `u8` IDs. The production `exec_create_election` uses `HashSet<&str>` over `String` candidate names (`contract.rs:71-76`). The two implementations have different failure modes: the harness mirror's O(n^2) is correct for `Eq` types, but `HashSet::insert` depends on the `Hash` impl for `&str` and the *iteration order* of the input Vec. If a future refactor changed to `HashSet<String>` with case-insensitive comparison, the harness mirror would not catch it. More importantly, the harness mirror does not test the cw-serde-deserialized `Vec<String>` boundary: if a caller submits `vec!["a".to_string(), "a\0".to_string()]`, are these distinct in production? In the mirror (u8 IDs), they would have to be distinct integers. The model elides Unicode discipline.
- **Why it succeeds**: The pure helper's signature `&[u8]` makes it Kani-tractable, but its semantics diverge from `HashSet<&str>` in subtle ways. The "structural property is the same" claim at line 25 is a hand-wave.
- **Suggested defense**: Add a unit-test cross-check: instantiate the production code path with the same input the Kani harness verified (project u8 IDs to single-char strings like `'A' + id`) and assert the result agrees. Currently no such bridge exists, so the proof at the helper layer doesn't transfer to the contract.

## 14. [ranked-choice/verification.rs] `exec_tally` accepts arbitrary `result.winner` — no harness

- **Target**: missing harness for `examples/ranked-choice/contracts/src/contract.rs:157-184`
- **Category**: Missing harness for invariants the production code depends on
- **Severity**: serious
- **Scenario**: `exec_tally` reads `result.winner: String` from the attested TallyMsg and stores it in `ElectionResult` (contract.rs:172) without checking that `result.winner ∈ election.candidates`. A compromised-but-still-attested enclave can supply a winner that wasn't a candidate. The harness set verifies `can_tally` (phase + election_id) but skips the winner-membership check. The IRV-tally helper `first_active_choice` returns `Option<u8>` — and `Option::Some(c)` could in principle be any byte not in the candidate list (the helper is correct, but the harness doesn't assert that the contract enforces the inverse: *winner must be the survivor of the IRV elimination*).
- **Why it succeeds**: No harness asserts `forall msg: exec_tally(msg).is_ok() => msg.winner ∈ election.candidates`. The Kani surface verifies guards, not enclave-output integrity.
- **Suggested defense**: Add a contract-side check `if !election.candidates.iter().any(|c| c == &result.winner) { return Err(InvalidWinner); }`. Then mirror it as `pub fn winner_is_valid(winner: &str, candidates: &[String]) -> bool` and Kani-verify the inclusion predicate.

## 15. [ranked-choice/verification.rs] `phase_transition_allowed` admits unreachable transitions

- **Target**: `examples/ranked-choice/contracts/src/verification.rs:58-69`, h_phase_transition_no_skip at lines 233-251
- **Category**: Spec-vs-implementation drift
- **Severity**: advisory
- **Scenario**: The transition relation allows `(Voting, Tallying)` (line 62), but the production `exec_tally` short-circuits to `Complete` (`contract.rs:178: election.phase = ElectionPhase::Complete`) — no Rust path writes `Tallying`. The transition function over-approximates the actual machine. `h_phase_transition_no_skip` checks three *negative* transitions but does not verify the positive transitions are reachable. A reader of the harness would believe `(Voting, Tallying)` is a real transition; it isn't.
- **Why it succeeds**: The harness is correct-in-the-negative (those bad transitions are indeed rejected) but the positive set is decorative. The Round C handshake P9/P10 / `last_msg_contract` action-tag pattern recurs here: a transition relation listing as "modelled" things the code does not do.
- **Suggested defense**: Remove `(Voting, Tallying)` from the allowed set (or add a Rust handler that performs the explicit transition before completion). Then add a *positive* harness `h_phase_transition_positive_reachability` that for each allowed transition, executes the corresponding handler and asserts the resulting phase matches `to`.

## 16. [ranked-choice/verification.rs] `h_filter_ballot_len_bounded` skips empty ballot

- **Target**: `examples/ranked-choice/contracts/src/verification.rs:265-296`
- **Category**: Coverage gap / bounded constants
- **Severity**: advisory
- **Scenario**: The harness fixes `N=4, M=3` (4-deep ballot, 3 candidates). It does not exercise:
  - `N=0` (empty ballot — degenerate but representable in production if a voter submits an empty ranked list)
  - `M=0` (no candidates — contract rejects this in `exec_create_election` but the helper is generic and should still terminate)
  - `N > M` (e.g., 5-deep ballot with 3 candidates — a voter padding with duplicates)
  - The "all_in" branch is tested, but the partial-in branch is not asserted to produce `kept < N`.
- **Why it succeeds**: The bounded `(N, M)` choice is tractable but excludes both degenerate boundary cases. The contract's `cw_serde` deserializer accepts arbitrary-length `Vec<String>` ballots — the helper's `N` is the on-stack array length, not the protocol's ballot length, so there's no direct contract-to-harness mapping at the size axis.
- **Suggested defense**: Add a parallel harness with `N=0` (empty ballot must yield `kept=0`) and one with `N=8, M=3` (more ballot entries than candidates, must still terminate and yield `kept <= N`).

## 17. [sealed-auction/state.rs] No harness for admin-authorization on `start_auction`

- **Target**: missing harness for `examples/sealed-auction/contracts/src/contract.rs:63-100`
- **Category**: Missing harnesses for invariants
- **Severity**: serious
- **Scenario**: `exec_start_auction` checks `info.sender != config.admin` and rejects (lines 69-71). The phase guard `can_start_auction(&phase)` (state.rs:63) is verified by harness `start_auction_guard_total` — but the *combined* guard (admin AND phase) is not. No harness mirrors the admin authorization. A future refactor that removes the admin check would not be caught at the Kani layer.
- **Why it succeeds**: The phase guard is a pure helper. The admin check is inline in the handler, not extracted to a pure function. The verification module verifies only the extracted helpers.
- **Suggested defense**: Extract `pub fn can_start_auction_authed(sender: &Addr, admin: &Addr, phase: &AuctionPhase) -> bool { sender == admin && can_start_auction(phase) }` and Kani-verify it. Equivalent fixes apply to `exec_resolve` (no admin/attestation-source check beyond the attestation wrapper) and ranked-choice's `exec_create_election` / `exec_open_voting`.

## 18. [sealed-auction/state.rs] `vickrey_tie_break_lowest_index` only tests 3 equal bids

- **Target**: `examples/sealed-auction/contracts/src/state.rs:296-304`
- **Category**: Coverage gap
- **Severity**: advisory
- **Scenario**: The tie-break harness fixes `bids = [v, v, v]` (3 identical bids). It does not test mixed cases like `[v, v, w]` where `v > w` (two-way tie at the top) or `[w, v, v]` (tie at indices 1, 2 — verifies the winner is *not* index 0, which would catch a "always pick last seen" bug). The "smallest-index tie-break" property holds vacuously for `[v,v,v]` because every index has the same value; the failure mode "we picked index 1 instead of 0" requires a value differentiated from a non-winner.
- **Why it succeeds**: With three identical bids, `winner_idx = 0` is set at line 109 of the production code and never updated because no later bid is strictly greater. The harness's `assert_eq!(w, Some(0))` passes — but it would also pass under a (buggy) "winner = last index with max value" mutation, because all three would end up at index 0 only if the implementation has explicit smallest-index logic. A more discriminating harness would have two equal max values among distinct non-max values.
- **Suggested defense**: Replace `let bids = [v, v, v]` with `let mid: u128 = kani::any_where(|&m| m < v); let bids = [v, v, mid];` and assert winner = 0 (not 1). This catches "iterate-with-strict-greater" vs "iterate-with-non-strict-greater" mutations.

## 19. [sealed-auction/state.rs] `vickrey_select` reserve-filtering precondition assumed but unverified

- **Target**: `examples/sealed-auction/contracts/src/state.rs:101-134` (helper) vs harnesses `vickrey_single_bidder_pays_reserve` (262-272), `vickrey_two_bidders_second_price` (276-291)
- **Category**: Coverage gap / spec-vs-implementation drift
- **Severity**: serious
- **Scenario**: The helper docstring at line 95-99 says "reserve-filter is the caller's responsibility". Both bidder-counting harnesses `kani::assume(bid >= reserve)` and `kani::assume(a >= reserve && b >= reserve)` enforce that precondition. But the enclave at `exec_resolve` (contract.rs:132-171) does *not* run a reserve filter before calling the equivalent of `vickrey_select` — the price-output handling is the responsibility of `result.price` from the attested message. A bid below reserve passing through the helper would still produce a winner (the helper has no reserve check itself — line 102 `if bids.is_empty()` is the only short-circuit). Concretely: `vickrey_select(&[10], 100)` returns `(Some(0), 100)` — a winner with bid=10 against reserve=100, paying reserve. That's wrong: a sub-reserve "winner" should not exist.
- **Why it succeeds**: The helper is a pure function whose precondition is enforced by the harnesses but *not* by the production callsite. The Quint spec (per Round B / sealed-auction findings, not in scope here but related) may also assume the filter. The enclave-side pre-filter has no Kani harness.
- **Suggested defense**: Either add the reserve filter inside `vickrey_select` (return `(None, reserve)` when no bid >= reserve), or add an explicit assertion at the helper entry: `debug_assert!(bids.iter().all(|b| *b >= reserve))`, and add a harness `h_vickrey_reserve_violation_diagnostic` that drives sub-reserve input and asserts the diagnostic fires.

## 20. [sealed-auction/state.rs] `can_resolve` verified but `exec_resolve` has no winner-validation harness

- **Target**: missing harness for `examples/sealed-auction/contracts/src/contract.rs:132-171`
- **Category**: Missing harness for invariants
- **Severity**: serious
- **Scenario**: `exec_resolve` accepts an attested `ResolveMsg` and stores `winner: Option<Addr>` plus `price: Uint128`. There is no on-contract check that:
  - The price equals the second-highest bid (the contract can't decrypt bids; this is *enclave-attested*).
  - The winner submitted a bid (`SEALED_BIDS.has(deps.storage, &winner)`).
  - The price ≥ reserve (CONFIG.reserve_price).
  The Kani harnesses verify the *pure helper* `vickrey_select` (which the contract doesn't call) and the *phase + id guard* `can_resolve`. The bridge between "enclave's Vickrey output" and "contract-side sanity" is unverified.
- **Why it succeeds**: The helper proofs do not transfer to the contract because the helper is enclave-side logic and the contract trusts the attestation. The only contract-side anti-tampering check is the attested wrapper's `user_data` match, which proves the message is *what the enclave signed* but not *that the enclave's computation was correct under untrusted inputs*.
- **Suggested defense**: Add contract-side post-conditions: `if result.price < config.reserve_price && result.winner.is_some() { Err(...) }`; `if let Some(w) = &result.winner { if !SEALED_BIDS.has(...) { Err(...) } }`. Then add Kani harnesses for these guards as pure helpers (`pub fn can_accept_resolve_result(...)`).

## 21. [sealed-auction/state.rs] `submit_bid_guard_exact` ignores reserve-price filter

- **Target**: `examples/sealed-auction/contracts/src/state.rs:170-187`
- **Category**: Spec-vs-implementation drift
- **Severity**: advisory
- **Scenario**: The harness models `can_submit_bid(phase, now, end, dup)` but the production `exec_submit_bid` (contract.rs:102-130) does *not* validate the bid against `config.reserve_price`. The contract accepts encrypted ciphertexts of arbitrary content; the enclave filters below-reserve bids at resolve time. The harness's "submit_bid" predicate is correctly minimal for the *contract* (which can't read ciphertext), but a reader might conclude that all submitted bids are valid bids — they aren't. There's no harness asserting that "below-reserve bids decay silently to the reserve in price computation" (this is in `vickrey_select` but the inter-helper composition is never asserted at the harness layer).
- **Why it succeeds**: The harness verifies the right predicate for the production code, but the production code defers an important check to the enclave. This is a layered-correctness gap, not a bug in the harness per se. Worth flagging as a documentation hazard.
- **Suggested defense**: Add a comment in the harness explaining that reserve-price enforcement is a cross-layer property (contract: accept, enclave: filter). Or add an explicit cross-layer harness that takes the contract's accepted bid set and the enclave's filter logic and asserts the joint property.

## 22. [framework/state.rs] No harness for `Config::try_from(RawConfig)` validation

- **Target**: missing harness for `crates/contracts/core/src/state.rs:72-85` (`Config::try_from`)
- **Category**: Missing harness for invariants
- **Severity**: serious
- **Scenario**: `Config::try_from` calls `value.mr_enclave.to_array()?` which fails for non-32-byte input, and propagates `LightClientOpts::try_from` errors. There is no Kani harness over this conversion. The only Config-touching harnesses are the (gated, non-running) `LightClientOpts` harnesses. Production-side, this conversion is called every time CONFIG is loaded (via `attested.rs:183 CONFIG.may_load`). A malformed CONFIG would panic at load time or produce a malformed `Config` whose `mr_enclave()` accessor (state.rs:46-48) returns a `[u8; 32]` zeroed by `to_array`'s failure path — except `to_array` returns `Err`, so this branch is type-safe. The actual risk is that no harness verifies "round-trip RawConfig → Config → RawConfig is identity for valid input, error for invalid".
- **Why it succeeds**: The serde layer is invisible. The validation is delegated to `HexBinary::to_array`, which depends on length. No harness exercises the boundary.
- **Suggested defense**: Add a harness `fn config_try_from_validates_mr_enclave_len()`: generate `let bytes_len: usize = kani::any_where(|&n| n <= 64); let raw = RawConfig { mr_enclave: HexBinary::from(vec![0u8; bytes_len]), ... }; let result = Config::try_from(raw); assert_eq!(result.is_ok(), bytes_len == 32);`. Currently no such harness exists.

## 23. [framework/msg/execute/*] No harness covers `HasUserData::user_data()` digest stability

- **Target**: missing harness for `crates/contracts/core/src/msg/execute/session_create.rs:60-72`, `session_set_pub_key.rs:64-76`
- **Category**: Missing harness for invariants
- **Severity**: advisory
- **Scenario**: `user_data()` is load-bearing — it's what the `Attested<M,A>::handle` wrapper compares against the attestation's user_data (`attested.rs:179-181`). A drift between two `SessionCreate` values with different fields producing the same digest would let attackers forge attestations for fields they didn't commit to. SHA-256 is collision-resistant by assumption, but the *bijection of (msg fields) → (serialized bytes)* is the actual property — if two distinct `RawSessionCreate` values produced the same JSON (e.g., due to optional-field omission), they'd hash to the same user_data. Kani can't prove SHA-256 collision-resistance, but it *can* verify that the JSON serialization is field-distinguishing for tiny inputs.
- **Why it succeeds**: The two session-create harnesses verify accessor identity but not digest stability or sensitivity. The byte layout of `serde_json::to_string(&RawSessionCreate::from(self.clone()))` is invisible to the verification surface.
- **Suggested defense**: Add a harness `fn session_create_user_data_field_sensitivity()` that constructs two `SessionCreate` values differing in *only* the nonce or *only* the contract, computes both `user_data()` values, and asserts they differ. This is bounded-SHA over a fixed small input — within Kani's reach with appropriate unwind.

## META

### Per-file attack counts

- `session_create.rs`: 2 (#10, #23-partial)
- `session_set_pub_key.rs`: 1 (#11)
- `core/state.rs`: 5 (#7, #8, #9, #12, #22) + half of #23
- `sealed-auction/state.rs`: 5 (#17, #18, #19, #20, #21)
- `pingpong/state.rs`: 2 (#1, #6)
- `transfers/state.rs`: 4 (#2, #3, #4, #5)
- `ranked-choice/verification.rs`: 4 (#13, #14, #15, #16)
- **Total**: 23 attacks (3 critical, 12 serious, 8 advisory)

### Recurring patterns

1. **Pure-helper-mirror-instead-of-handler** (#1, #2, #13, #17, #20): the Kani harnesses verify pure mirrors of guard predicates but the production handlers compose those guards inline with admin/authorization/serde-deserialize/storage steps that the harnesses cannot reach. The proofs at the mirror layer do not transfer to the contract. This is the single largest pattern (5 attacks across 4 files) and the root cause of Round C's pingpong and transfers criticals being invisible at the Kani layer.

2. **Bounded constant defeats variation testing** (#10, #11, #18, #16, #21): `String::from("c")`, `vec![0x04u8; 33]`, `[v, v, v]`, `N=4, M=3` — every example file has at least one harness where a load-bearing input is fixed to a single value, collapsing the symbolic input space to a point. The most consequential is #11 (pub_key shape).

3. **Carry-over of Round C critical findings** (#1, #3, #5, #6): three of the three Round C criticals (pingpong vacuous plaintext_private, transfers BankMsg::Send leak, transfers single-vs-drain quantity mismatch) have no corresponding Kani harness. The Kani surface is strictly weaker than the Quint surface for the example specs. Round E should not be the round that *first* reports these to the Quartz team — they should already be tracked from Round C — but the absence of corresponding harnesses is a methodology gap: when a Quint review finds a critical, an open question is whether the Kani layer has a harness that would catch it. Currently: no.

4. **`#[cfg(kani_slow)]` is a CI-invisible gate** (#7): two non-trivial property harnesses are behind a config flag that has no consumer. They will not run under normal `cargo kani`. This is the only "verification artifact that doesn't actually verify" instance, but it's load-bearing because the LightClientOpts validation is the only non-trivial validation logic in the framework's Config.

5. **Tautological / structural harnesses** (#1, #9, #12): four harnesses in `pingpong/state.rs` plus `session_with_pub_key_no_panic` plus `session_pubkey_set_once`-narrow plus most of `core/state.rs::session_*` reduce to checking that Rust's by-value semantics and `#[derive(Clone)]` work — they cannot fail under any non-pathological mutation.

### Recommendation

**Priority 1 — Reconnect harnesses to handlers** (pattern 1): the Kani surface currently verifies the inputs to handler logic, not the handler logic itself. For `exec_submit_bid`, `exec_resolve`, `exec_create_election`, `exec_tally`, `execute::ping`, `execute::pong`, `execute::update`: introduce per-handler `can_<handler>_authed_and_guarded(...) -> bool` total predicates that encapsulate the full guard composition (admin + phase + storage-prereq + msg-fields), and Kani-verify those. The pure-helper pattern (`can_start_auction`, `can_submit_bid`) is correct but incomplete — the helpers cover the easy half of the predicate space.

**Priority 2 — Surface Round C criticals at Kani** (#3, #5, #6): even if Kani cannot fully verify privacy / quantity-prefix-consistency / overwrite-discipline, the harnesses for these contracts should *document* the gaps explicitly so the Round-by-round verification ledger remains audit-traceable. Add file-header comments and one "known-failing" harness per critical that asserts the property the contract should hold and that *will fail* until the contract is fixed.

**Priority 3 — Remove `kani_slow` gate or replace it with `--no-unwinding-checks` policy** (#7): either land the `StdError::generic_err` refactor or invoke Kani with the documented flag in CI. Currently the harnesses behind the gate are decoration.

**Priority 4 — Free the bounded constants** (#10, #11, #16, #18): variable inputs are cheap to add and catch a class of regressions that fixed inputs cannot. The pub_key length harness (#11) is the highest-value: a bounded `kani::any_where(|&n| n <= 65)` exercises the protocol's missing length check and either motivates adding it or documents its absence.

**Priority 5 — Add `Session::nonce` panic-path harness** (#8): the production code carries an `expect()` that can fire on serde-malformed storage. The "correct by construction" claim is a comment; promote it to a proof or remove the `expect` in favor of `Result`.

The 41-harness surface across 1666 lines has *good intent* — guards extracted, totality assertions, mutation-test commentary, kani_slow gating for backtrace-heavy paths. The execution leaves three problems: (a) the pure-mirror layer does not bridge to the handler layer; (b) Round C criticals do not appear at the Kani layer at all; (c) two harnesses behind a never-set config flag don't run. None of these are bugs in individual harnesses — they are gaps in the Kani-verification methodology as applied to this codebase. The Quint review (Round C) was *more thorough on protocol correctness* than the Kani review is *now*. Fixing the pure-helper-to-handler bridge would close that gap.
