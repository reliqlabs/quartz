# Adversarial review: temporal_zk_accept_requires_vkey  —  local (google/gemma-4-26b-a4b)

- Spec under review: /Users/mvid/Development/reliq/quartz/specs/attestation.qnt (lines 388-445)
- Intent document: /Users/mvid/Development/reliq/quartz/CLAUDE.md
- Reviewed at: 2026-05-12T15-47-57Z
- Round: 1
- Model: google/gemma-4-26b-a4b
- Elapsed: 181.3s
- Usage: {'prompt_tokens': 5787, 'completion_tokens': 13377, 'total_tokens': 19164, 'completion_tokens_details': {'reasoning_tokens': 12231}}
- Finish reason: stop

---

VERDICT: BREAKS

### 1. Coverage Gap: Mock Mode Bypasses Proof Integrity
**Category**: Coverage gap
**Concrete scenario**: 
1. An administrator calls `enable_mock`, setting `zk_module.accept_all = true`.
2. An attacker submits a `Zk` attestation where `msg.attestation.proof.proof_bytes == ""`.
3. The `verify_zk` action is executed. Because `not(zk_module.accept_all)` is now `false`, the branch `else if (msg.attestation.proof.proof_bytes == "" and not(zk_module.accept_all))` is skipped.
4. The action falls into the final `else` block, setting `last_result = Accepted`.

**Why it succeeds**: 
The temporal property `temporal_zk_accept_requires_vkey` (lines 410-419) only mandates that `config.zkdcap_vkey` was non-empty and registered in the pre-transition state. It does **not** mandate that a valid proof was actually verified. The property is satisfied because the vkey requirement is met, even though the actual ZK proof verification was bypassed by the `accept_all` logic. The property provides a false sense of security regarding the "Acceptance" state by only witnessing the configuration requirement and not the proof integrity.

**Severity**: `serious`

**Suggested defense**: Strengthen the temporal property to ensure that if `last_result` becomes `Accepted`, then either `zk_module.accept_all` was true OR the proof provided in `last_input` was non-empty.

---

### 2. Refinement Mismatch: Success Counter Leakage via `SkippedNoVKey`
**Category**: Refinement mismatch
**Concrete scenario**: 
1. The system is in a state where `config.zkdcap_vkey == ""` (e.g., after calling `clear_vkey`).
2. A user submits a valid `Zk` attestation.
3. The `verify_zk` action is executed. It hits the branch `else if (config.zkdcap_vkey == "")`.
4. The state is updated: `last_result' = SkippedNoVKey` and `messages_accepted' = messages_accepted + 1`.

**Why it succeeds**: 
The intent of the system (and the focus of the temporal property) is to ensure that ZK-based acceptance is tied to a valid verification key. However, the implementation of `verify_zk` (lines 243-251) increments the `messages_accepted` counter even when no verification occurs (`SkippedNoVKey`). The temporal property `temporal_zk_accept_requires_vkey` is silent on this because its antecedent requires `next(last_result) == Accepted`. Consequently, the `messages_accepted` metric is a "dirty" signal that includes unverified/skipped attestations, violating the refinement between the high-level intent of "accepted messages" and the low-level state.

**Severity**: `serious`

**Suggested defense**: Either do not increment `messages_accepted` in the `SkippedNoVKey` branch, or introduce a separate counter for verified vs. skipped attestations to maintain metric integrity.

---

### 3. Triviality: Temporal Property is a Redundant Observer
**Category**: Triviality
**Concrete scenario**: Any valid execution of `verify_zk` that results in `Accepted`.

**Why it succeeds**: 
The temporal property `temporal_zk_accept_requires_vkey` (lines 410-419) is written to "witness" the obligation. However, in the current specification, the `verify_zk` action (lines 216-275) is a strictly sequential `if-else if` chain. The conditions `config.zkdcap_vkey != ""` and `zk_module.registered_vkeys.contains(...)` are **preconditions** for reaching the `else` block that sets `last_result = Accepted`. 

Because the action is atomic and the conditions are checked within the same transition that produces `Accepted`, the temporal property is tautologically true by construction of the action. It does not "protect" against anything that the action itself doesn't already prevent; it merely observes the internal logic of the `verify_zk` branch. It fails to provide independent verification of the system's safety, acting instead as a redundant check on the action's own implementation.

**Severity**: `cosmetic`

**Suggested defense**: The property is acceptable as a formal check, but the author should recognize it adds no safety margin beyond what the action's logic already provides.

---

**META**
- **Categories attacked**: Coverage gap, Refinement mismatch, Triviality.
- **Categories not attacked**: Under-specification (covered via Refinement Mismatch), Over-specification, Ambiguity, Contradiction, Edge case (covered via Mock Mode/Empty Proof), Composition failure, Temporal-state mismatch.
- **Artifacts wanted**: The implementation of `verify_quote` (to ensure it doesn't accidentally trigger the ZK temporal property) and the full `verify_any` implementation.
- **Estimated confidence**: High