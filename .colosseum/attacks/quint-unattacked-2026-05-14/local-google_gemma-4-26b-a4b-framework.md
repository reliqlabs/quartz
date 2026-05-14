# Adversarial review of 2 framework Quint specs — local-model arm (Round C, batch 1)

date: 2026-05-14
round: C.local.framework
adversary: google/gemma-4-26b-a4b

VERDICT (handshake.qnt): WEAKENS
VERDICT (attestation.qnt): HOLDS WITH CAVEATS

## 1. [handshake] Ghost Session via partial state reset
**Category** Phase-machine completeness
**Severity** serious
**Scenario** An operator calls `reset_session` to clear an existing session.
**Why it succeeds** The action `reset_session` (line 365) clears the `enclave` state (`contract_addr`, `nonce`, `pubkey`) but fails to reset the `contract.session` state to `NoSession`. This leaves the contract in a "Ghost Session" state where `contract.session == SessionActive` (or `SessionCreated`), but the enclave-side security parameters are empty. Invariants like `inv_nonce_consistency` (line 436) and `inv_pubkey_consistency` (line 443) bypass this state because they use `if enclave.nonce != ""` guards; if the nonce is empty, the invariant passes vacuously, failing to detect that an "active" session exists without a valid enclave-side nonce.
**Suggested defense** Ensure `reset_session` resets `contract.session` to `NoSession` and `contract.sequence_num` to `-1`.

## 2. [handshake] Session Overwrite Hazard
**Category** Spec-vs-implementation drift
**Severity** serious
**Scenario** An attacker or a buggy client calls `session_create` while an existing session is already `SessionActive`.
**Why it succeeds** The action `session_create` (line 216) lacks a guard to check if `contract.session == NoSession`. It will unconditionally overwrite the current session with a new nonce and state. This matches the current Rust implementation (which contains a `TODO` for this check in `session_create.rs`), but it means the formal spec is modeling an unsafe state transition that allows session hijacking or disruption.
**Suggested defense** Add a precondition to `session_create` requiring `contract.session == NoSession`.

## 3. [handshake] Dormant Nonce Invariant
**Category** Dormant invariants
**Severity** advisory
**Scenario** A bug in the handshake logic causes `enclave.nonce` to be cleared or remain empty during a `SessionCreated` state.
**Why it succeeds** `inv_nonce_consistency` (line 436) is designed to ensure the enclave and contract nonces match. However, it contains a conditional `if (enclave.nonce != "")`. If the enclave nonce is empty (which occurs immediately after `reset_session` or during a failed handshake), the invariant passes vacuously. It fails to enforce that if `contract.session` is `SessionCreated`, the `enclave.nonce` *must* be non-empty and match the contract.
**Suggested defense** Remove the `if (enclave.nonce != "")` check for the `SessionCreated` state to ensure nonces are present when a session is established.

## 4. [handshake] Brittle Config Invariant
**Category** Action-tag refactor hazard
**Severity** advisory
**Scenario** A developer adds a new action to the framework (e.g., `update_config` or `rotate_key`) that modifies the contract configuration.
**Why it succeeds** `inv_config_write_once` (line 394) relies on manual state-snapshotting (`prev_config_set` and `prev_config_mr_enclave`). This is a "state-only" guard that is highly brittle to refactors. If a new action is added and the developer forgets to include these specific `prev_` snapshots in that action's `all` block, the invariant will fail or become vacuous for those transitions.
**Suggested defense** Use a temporal property (`always(next(config_set) implies config_set)`) or a history-based predicate rather than relying on manual snapshots in every action.

## 5. [attestation] Strict-vs-Loose Skip Drift
**Category** Spec-vs-implementation drift
**Severity** serious
**Scenario** An implementation of `verify_zk` (the ZK handler) is "loose" and skips all checks if no `vkey` is configured.
**Why it succeeds** In `verify_zk` (line 163), if `config.zkdcap_vkey == ""`, the action returns `SkippedNoVKey` immediately. However, the spec's invariants (`inv_user_data_mismatch_rejected` line 246 and `inv_compose_hash_mismatch_rejected` line 253) assert that even if the result is `SkippedNoVKey`, the `user_data` and `compose_hash` *must* have matched. This means the spec models a "Strict Skip" (skip ZK but enforce identity), whereas the implementation logic is a "Loose Skip" (skip everything). If the implementation is loose, Apalache will find a counter-example where an attacker provides wrong identity data and gets a `SkippedNoVKey` result.
**Suggested defense** Explicitly decide if "skipping" means "skip ZK-only" or "skip all verification." If it is the latter, update the invariants to allow mismatches when `SkippedNoVKey` is returned.

## 6. [attestation] Vacuous Variant Check
**Category** Vacuous temporal properties
**Severity** advisory
**Scenario** An action is taken where the input message hash is empty (e.g., during `init` or a malformed state transition).
**Why it succeeds** `inv_variant_outcome_consistent` (line 263) contains the guard `if last_input.msg_hash != ""`. If an action is executed where the message hash is empty, the invariant is skipped (`else true`). This means the spec does not actually verify that the `last_result` is consistent with the `variant` for those specific transitions, creating a small hole in the state-machine coverage.
**Suggested defense** Remove the `msg_hash != ""` check or ensure it only applies to non-initial states.

## 7. [attestation] Mock-Mode State Interaction
**Category** Mock-mode disclosure paths
**Severity** advisory
**Scenario** An operator enables mock mode and subsequently clears the VKey configuration.
**Why it succeeds** If `enable_mock` (line 198) is called (`accept_all = true`) and then `clear_vkey` (line 206) is called (`zkdcap_vkey = ""`), the system enters a state where `verify_zk` will hit the `config.zkdcap_vkey == ""` branch (line 163) and return `SkippedNoVKey`. This effectively transforms "Mock Mode" (which is intended to bypass proof checks) into a "Skip Mode" that bypasses identity and compose-hash checks as well (if the implementation follows the same logic as the spec's bypass).
**Suggested defense** Document the expected behavior of `clear_vkey` when `accept_all` is true, or prevent `clear_vkey` from being called if mock mode is active.

## 8. [attestation] Trivial Counter Invariant
**Category** Triviality
**Severity** advisory
**Scenario** A logic error occurs in how `messages_accepted` or `messages_rejected` are incremented.
**Why it succeeds** `inv_counters_consistent` (line 236) checks if `messages_accepted + messages_rejected >= 0`. Since both counters are defined as non-negative and only incremented, this invariant will *always* pass regardless of whether the logic for those increments is correct or if they are being updated in the wrong branches. It adds no actual coverage to the verification.
**Suggested defense** Remove this triviality or replace it with an invariant that checks if the sum of counters matches the total number of actions taken.

## META
- **Shared Deficiency**: Both specs lack an authorization model (e.g., `caller` or `admin`). Actions like `enable_mock`, `clear_vkey`, and `reset_session` are modeled as being callable by any actor in the state space.
- **Methodology Note**: The divergence between Claude (focused on cross-file implementation drift) and Gemma (focused on invariant shape/triviality) remains productive. Claude's ability to find the `reset_session` state-mismatch (Attack 1) and Gemma's ability to identify the triviality of `inv_counters_consistent` (Attack 8) demonstrate that combining "implementation-aware" and "shape-aware" reviews is necessary to catch both logic bugs and vacuous proofs.
- **Summary**: `handshake.qnt` is structurally weaker due to the "Ghost Session" and "Overwrite" hazards, which represent direct security risks. `attestation.qnt` is logically sound but contains "Strict-vs-Loose" modeling risks that could lead to a false sense of security if the implementation is more permissive than the spec.