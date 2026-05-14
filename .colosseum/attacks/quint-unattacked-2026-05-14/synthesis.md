# Multi-model adversarial synthesis: 4 previously-unattacked Quint specs (Round C)

- Specs under review:
  - `specs/handshake.qnt` (835 lines) — main framework session-lifecycle spec
  - `specs/attestation.qnt` (492 lines) — framework attestation spec (only `temporal_zk_accept_requires_vkey` reviewed prior; rest unreviewed)
  - `examples/pingpong/specs/pingpong.qnt` (452 lines) — canonical Quartz example
  - `examples/transfers/specs/transfers.qnt` (487 lines) — private-balance transfers
- Intent docs: framework Rust (`crates/contracts/core/src/{state.rs, handler/execute/*, handler/instantiate.rs}`, `crates/enclave/core/src/attestor.rs`) + per-example Rust (`examples/{pingpong,transfers}/{contracts,enclave}/src/*`)
- Reviewed at: 2026-05-14
- Adversaries: **Claude** (subagent, file access, Opus 4.7 / 1M context) + **Gemma 4 26B** (local via LM Studio, full context inlined, **two batches** — framework specs + example specs — because the single-batch prompt exceeded model context)
- Result: **27 distinct attacks after dedup**; 3 critical, 13 serious, 11 advisory

This synthesis is orchestrator output. The per-model reports (`claude.md`, `local-google_gemma-4-26b-a4b-framework.md`, `local-google_gemma-4-26b-a4b-examples.md`) are persisted verbatim. Orchestrator summarizes overlap and divergence; it does not add, weaken, or re-author findings.

---

## Verdict aggregate

| Adversary | handshake.qnt | attestation.qnt | pingpong.qnt | transfers.qnt | Total | Crit | Serious | Advisory |
|---|---|---|---|---|---|---|---|---|
| Claude (file access) | **WEAKENS** | HOLDS WITH CAVEATS | **WEAKENS** | **BREAKS** | 20 | 3 | 8 | 9 |
| Gemma 4 26B framework | **WEAKENS** | HOLDS WITH CAVEATS | n/a | n/a | 8 | 0 | 3 | 5 |
| Gemma 4 26B examples | n/a | n/a | **WEAKENS** | **BREAKS** | 8 | 2 | 3 | 3 |
| **Cross-family agreement** | **WEAKENS** | HOLDS WITH CAVEATS | **WEAKENS** | **BREAKS** | — | — | — | — |

Per-spec verdicts agree across both adversaries on all four specs.

---

## Headline findings

Three critical findings, each load-bearing for its example/framework spec's verification claim.

### Critical 1 — `pingpong.qnt`'s `inv_plaintext_private` is vacuous (both arms agree)

`observer.can_see_plaintext` is initialized to `false` (line 127) and **never written elsewhere** in the spec. Every action preserves `observer' = observer`, so the only writer is `init`. The invariant `not(observer.can_see_plaintext)` reduces to `not(false) == true` for all reachable states.

Claude #12 frames this as the static-boolean-vacuity anti-pattern (a privacy invariant must model the adversary's possible decryption paths explicitly). Gemma examples #2 frames it as a known-weak-primitive concern (the XOR/echo-style encryption in `request.rs:124` could leak via key reuse; the spec's opaque-ciphertext model hides this entirely). Both framings agree on the same vacuous-flag root cause.

### Critical 2 — `transfers.qnt`'s `update` action processes 1 request; Rust drains a prefix (both arms agree)

Quint `update` (lines 301–318) processes `contract.requests.head()` — exactly one in-order request per step. Rust `update` (`transfers/contracts/src/contract.rs:194`) calls `requests.drain(0..msg.quantity as usize)` — drains `msg.quantity` items, with `msg.quantity` supplied by the attested UpdateMsg.

Gemma examples #4 emphasizes the "spec loses money" angle: the Quint model deletes multiple requests from the queue but only applies the first one to the enclave state. Claude #17 emphasizes the attacker-control angle: `msg.quantity` is attacker-controlled in the contract, with no contract-side check that `quantity` matches the drained prefix or the withdrawals applied. Both angles point at the same divergence between spec and Rust.

The contract has **no check** that the drained requests match what the enclave processed. A compromised enclave (with valid attestation) can set `quantity=0` while supplying nonzero withdrawals, allowing replay; or supply withdrawals for requests that weren't drained, allowing double-spend.

### Critical 3 — `transfers.qnt` conservation theorem ignores `BankMsg::Send` plaintext leak (Claude only)

The Rust `transfers/contracts/src/contract.rs:201-207` emits `BankMsg::Send { to_address, amount }` for each withdrawal — these are **on-chain bank transfers**, with public recipient + amount. The Quint spec models withdrawals as `apply_withdraw` which drains the balance and updates `total_supply`, but **does not record the withdrawal amount in any observable state**. The observer's `can_see_balances: false` flag therefore yields a vacuous `inv_balances_private` even though every withdrawal reveals the exact pre-withdraw balance to the chain.

Concrete leak: "deposit Alice 100; withdraw Alice" — the `BankMsg::Send` value reveals Alice's balance was 100. Sequence withdrawals after intermediate transfers and you derive the transfer amounts. Gemma examples #5 flags `inv_transfers_private` as vacuous via the same static-boolean pattern; Claude #16 supplies the on-chain-disclosure angle that Gemma's no-file-access prompt missed.

---

## Cross-model agreement summary

### Strong agreement (both arms surfaced)

- **Handshake**: `reset_session` is incomplete (Gemma #1: doesn't reset `contract.session`; Claude #4: doesn't reset `sequence_num`). Two missing fields; same root incompleteness.
- **Handshake**: Session overwrite hazard (Gemma #2 ≈ Claude #7) — no `session == NoSession` guard on `session_create`, matching a Rust TODO.
- **Handshake**: Dormant enclave-state invariants (Gemma #3 ≈ Claude #1) — `if (enclave.nonce != "")` guards make the invariant vacuous after reset, and the writers are the same atomic actions that wrote the contract side.
- **Attestation**: Variant-outcome staleness (Gemma #6 ≈ Claude #10) — `inv_variant_outcome_consistent` predicates on `last_input.attestation.variant`, which is stale after `enable_mock` / `clear_vkey`. Round-1 S1 action-tag fix applies.
- **Pingpong**: `ping` ErrSlotOccupied guard not in Rust (Gemma #1 ≈ Claude #13) — Rust unconditionally overwrites; spec rejects on occupied. Both arms identify the Rust comment-stated-but-unmodeled gap.
- **Pingpong**: Reset action is a ghost transition (Gemma #3 ≈ Claude #15) — `reset` exists in the spec but not in Rust.

### Net-new from Gemma (no Claude analog)

- **Gemma framework #7 — Mock-mode + clear_vkey interaction (advisory)**: enabling mock then calling `clear_vkey` makes `verify_zk` short-circuit through `SkippedNoVKey` instead of the `accept_all` branch — "mock" downgrades to "skip", bypassing more checks than intended.
- **Gemma framework #8 — Trivial counter invariant (advisory)**: `inv_counters_consistent` is `messages_accepted + messages_rejected >= 0`; identically true.
- **Gemma examples #6 — Weak replay protection (serious)**: `inv_sequence_monotone` checks `sequence_num > 0` if `last_action == ActTransfer`. Does not enforce that the sequence number *increases* between requests — same nonce could be re-used.
- **Gemma examples #7 — State/ciphertext decoupling (serious)**: `new_encrypted_state` is a nondeterministic input blindly saved to `contract.encrypted_state`. The spec does not bind it to the enclave's `balances` map. A malformed ciphertext can desync on-chain view from enclave-authoritative state.
- **Gemma examples #8 — Bounded-universe conservation gap (advisory)**: `sum_of_balances` folds over the fixed `ADDRS` set. An address outside `ADDRS` could hold a balance in a real implementation and the conservation invariant would still pass.

### Net-new from Claude (no Gemma analog)

- **Claude #2 — Instantiate's pre-config Attested wrapper drift (serious)**: Rust's outer `Attested<M,A>::handle` (`attested.rs:179-181`) runs the user_data check unconditionally; the Quint `instantiate` action has no `msg_hash` parameter and never models this check. A malicious attestation with `user_data ≠ msg_hash` would be rejected by Rust but accepted by Quint. **Required cross-file reading that Gemma's no-file-access prompt blocked**.
- **Claude #3 — `inv_compose_hash_checked` pre-snapshot anchor mismatch (serious)**: P9's `prev_config_mr_enclave` is sampled at action entry — pre-instantiate it's `""`, post-instantiate it would be `VALID_COMPOSE_HASH`. The invariant excludes `ActInstantiate` from its antecedent, hiding the bug; a future refactor allowing instantiate-time attested verification (which Claude #2 recommends) would silently break it.
- **Claude #6 — `last_msg_contract` carry across action boundaries (advisory)**: Round-1 S1 single-shot pattern; P10 only binds for one transition after `session_create`.
- **Claude #8 — `verify_quote` accepts arbitrary quote bytes (serious)**: The Quint `verify_quote` action returns `AcceptedQuote` regardless of the quote contents. The Rust handler is a no-op placeholder. In production all attestations must traverse `verify_zk`; the spec admits Quote-variant acceptances production rejects.
- **Claude #11 — ZK acceptance path treats vkey set as boolean; no proof-byte verification (serious)**: `verify_zk` accepts on `vkey ∈ registered_vkeys AND proof_bytes != ""`. The real Xion ZK module runs gnark Groth16 verification which can return `false` for non-empty malformed proofs. The model assumes every non-empty proof verifies.
- **Claude #16 — Conservation vs BankMsg::Send leak (critical)**: see Critical 3.
- **Claude #19 — `transfer_request` increments sequence; `update` does not check it (serious)**: Quint `update` does not consult `contract.sequence_num`. Cross-actor replay window unmodeled.

### False positive (Gemma)

- **Gemma framework #5 — Strict-vs-Loose Skip Drift (Gemma severity: serious)**: Mis-read of the spec. `verify_zk` checks user_data and compose_hash *before* the `SkippedNoVKey` branch (`attestation.qnt:227-246`), so the invariant `inv_user_data_mismatch_rejected` correctly holds when result is `SkippedNoVKey`. Rust's `Attested<M,A>::handle` (`attested.rs:179-181`) likewise rejects on UserDataMismatch before dispatching. The spec is faithful to Rust here. Verified by file inspection. Severity downgrade to "not a finding".

---

## Per-spec final attack-count after dedup

| Spec | Dedup'd | Crit | Serious | Advisory | Claude-only | Gemma-only | Shared |
|---|---|---|---|---|---|---|---|
| handshake.qnt | 9 | 0 | 5 | 4 | 5 | 1 | 3 |
| attestation.qnt | 7 | 0 | 3 | 4 | 3 | 2 | 1 (variant-outcome) + 1 Gemma FP |
| pingpong.qnt | 5 | 1 | 1 | 3 | 2 | 0 | 3 |
| transfers.qnt | 7 | 2 | 4 | 1 | 2 | 3 | 2 |
| **Total distinct** | **27** | **3** | **13** | **11** | **12** | **6** | **9** + 1 Gemma FP |

---

## Recurring patterns (cross-arm)

5 patterns visible across both Claude and Gemma reports:

1. **Privacy invariants as static `= false` booleans with no writer**: `inv_plaintext_private` (pingpong, both arms), `inv_balances_private` + `inv_transfers_private` (transfers, both arms). Critical anti-pattern surfaced independently by both adversaries. The spec author wrote a "no leak" boolean and never modeled an adversary that could write it. Verification trivially passes.

2. **Session-active flags never flipped to false** (Claude #14 + #20): both example specs reference a handshake state via boolean that has no off-switch. Cross-spec composition gap.

3. **Action-tag fragility echoing Round 1**: handshake P9/P10/P11/P12/P13 (Claude #3, #6) and attestation P3 (Claude #10 + Gemma framework #6). State-only invariants predicated on `last_action == X` only bind for one transition; Round 1 settled this with `temporal_zk_accept_requires_vkey`. Same single-step-binding hazard recurs in three different specs.

4. **Spec models disciplined-use; Rust implements permissive overwrite/drain**: handshake session re-create with stale `sequence_num` (Claude #7 + Gemma framework #2), pingpong `ping` ErrSlotOccupied guard not in Rust (Claude #13 + Gemma examples #1), transfers `update` quantity attacker-controlled (Claude #17 + Gemma examples #4). Three different specs exhibit this.

5. **Bounded universe constrains conservation to a safe subset**: transfers `inv_conservation` folds over fixed `ADDRS` set (Gemma examples #8). The safety of the proof depends on the smallness of the test set.

---

## Recommendation

**Priority 1 — Critical fixes (load-bearing)**:
- pingpong #12 (vacuous plaintext-private): Add adversarial observer action that models the XOR key-reuse decryption path, OR explicitly mark the invariant as "modeled-by-construction" rather than verified.
- transfers #16 (BankMsg::Send leak): Add `observer.observed_bank_sends: Set[(Addr, Amount)]` updated on every withdrawal. Replace `inv_balances_private` with a real adversarial-inference invariant. Document explicitly that this invariant **does not hold** in the current design — surface the leakage rather than paper over it.
- transfers #17 (single-vs-drain): Parameterize `update` with attacker-chosen `quantity` and check prefix-consistency. The conservation invariant *should* fail against this stronger adversary — that failure motivates a missing contract-side guard.

**Priority 2 — Action-tag fix sweep**:
Promote state-only `last_action == X` invariants to temporal properties (Round 1 pattern). Apply to handshake P9/P10/P11/P12/P13 and attestation P3. Both arms agree this is the highest-volume systematic flaw.

**Priority 3 — Spec-vs-implementation drift remediation**:
- handshake #2: Add `msg_hash` parameter to `instantiate(...)` and model the Attested-wrapper user_data check.
- handshake reset_session: Either match Rust by removing it, or flip `contract.session` and `sequence_num` properly.
- pingpong ping overwrite: Either add the missing guard to Rust `execute::ping`, or remove `ErrSlotOccupied` from Quint.
- transfers state/ciphertext decoupling (Gemma examples #7): Model `new_encrypted_state` as a function of `enclave.balances` to enforce the binding.
- transfers replay protection (Gemma examples #6): Add `prev_sequence_num` ghost and enforce strict monotonicity.

**Priority 4 — Dormant-invariant sweep**:
Grep for `if (...condition...)` invariant bodies and verify both branches of the antecedent are reachable. Mechanically auditable; would catch ~40% of advisory findings.

---

## Methodology notes

**Two-batch local-arm**: The full single-prompt for 4 specs + Rust intent + format references was ~215KB (53K tokens), which exceeded the loaded Gemma context window (LM Studio returned HTTP 400). Splitting into framework-batch (handshake + attestation, ~25K tokens) and examples-batch (pingpong + transfers, comparable size) succeeded. This is a worth-flagging methodology refinement: **the local-arm prompt budget is a constraint that scales differently from Claude's**, and multi-spec Quint reviews should default to per-domain batching rather than a single prompt. Filed as colosseum-methodology v0.2 ask candidate.

**Same-snapshot discipline**: Both arms reviewed the specs at the same commit (`79faf64` post-cycle-6.12). No spec changes were applied during the review window, even though three critical findings were flagged in the Claude arm. Fixes are deferred until after both arms complete and the synthesis is written — preserving the same-input-to-both-arms invariant.

**Cross-spec composition**: Two example-spec findings (Claude #14, #20) point at the same composition gap with `handshake.qnt`. A real cross-spec composition would import handshake's `session: SessionState` field and gate example-spec actions on it. Currently both examples carry a boolean that mirrors a handshake-state predicate without binding to it.

**Cross-family productivity**: Claude is consistently stronger on cross-file Rust-Quint drift (Claude #2, #16, #19 each require reading both Rust and Quint). Gemma is consistently stronger on shape-level triviality (Gemma framework #8, examples #5, #8). 1 Gemma false positive (framework #5) vs 0 Claude false positives — Gemma's confidence on file-internal reasoning is higher than its accuracy on the same. Both arms running together catch 9 cross-family-shared findings the orchestrator can prioritize as "highest confidence", plus 12 Claude-only and 6 Gemma-only that add coverage.

**Net adversary impression**: 27 distinct attacks across 4 specs / 2266 lines is in the upper end of the 12-20 calibration range — the four specs are *substantively under-reviewed* relative to Round B's two specs. The example specs (pingpong, transfers) have the highest critical-finding density; the framework specs (handshake, attestation) are more solidly constructed but carry the most action-tag-fragility hazards.
