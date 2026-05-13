# Adversarial review: temporal_zk_accept_requires_vkey  —  local (google/gemma-4-26b-a4b)

- Spec under review: /Users/mvid/Development/reliq/quartz/specs/attestation.qnt (lines 388-445)
- Intent document: /Users/mvid/Development/reliq/quartz/CLAUDE.md
- Reviewed at: 2026-05-12T16-42-27Z
- Round: 1
- Model: google/gemma-4-26b-a4b
- Elapsed: 165.5s
- Usage: {'prompt_tokens': 5788, 'completion_tokens': 11513, 'total_tokens': 17301, 'completion_tokens_details': {'reasoning_tokens': 10277}}
- Finish reason: stop

---

VERDICT: BREAKS

### 1. Temporal-State Mismatch (The "Dormant Invariant" Flaw)

**Category**: Temporal-state mismatch

**Concrete scenario**: 
1. The system is in the `init` state: `last_result = SkippedNoVKey`, `config.zkdcap_vkey = VALID_VKEY`.
2. A user calls `verify_zk` with a valid ZK attestation. 
3. The state transitions to: `last_result = Accepted`, `config.zkdcap_vkey = VALID_VKEY`. 
   - The temporal property `temporal_zk_accept_requires_vkey` is evaluated at the previous step. Since `last_result != Accepted` and `next(last_result) == Accepted`, the implication is checked and passes.
4. A user calls `clear_vkey`. 
5. The state transitions to: `last_result = Accepted`, `config.zkdcap_vkey = ""`.
6. A developer introduces a bug in a future action (e.g., `verify_zk` or a new `bypass_verification`) that allows the state to transition from `last_result = Accepted` to `last_result' = Accepted` even when `config.zkdcap_vkey == ""`.

**Why it succeeds**: 
The temporal property uses the guard `last_result != Accepted` (line 412). Once the system reaches the `Accepted` state, this guard becomes `false` for all subsequent steps. Because no action in the specification (including `clear_vkey`) resets `last_result` to anything other than `Accepted` or `SkippedNoVKey`, the property becomes **permanently dormant** once a single successful attestation has occurred. The "real obligation" is only checked at the moment of entry into the `Accepted` state, failing to ensure that the condition holds for all subsequent accepted states or transitions.

**Severity**: `critical` (The property fails to provide continuous safety, which is the primary purpose of a temporal invariant).

**Suggested defense**: Remove the `last_result != Accepted` guard and express the property as a state-based invariant: `always(last_result == Accepted implies (config.zkdcap_vkey != "" and ...))`.

---

### 2. Coverage Gap (The `SkippedNoVKey` Bypass)

**Category**: Coverage gap

**Concrete scenario**:
1. The system is in a state where `config.zkdcap_vkey = ""`.
2. A user calls `verify_zk` with a valid ZK attestation variant.
3. According to the `verify_zk` action (lines 241-248), because `config.zkdcap_vkey == ""`, the result is set to `last_result' = SkippedNoVKey` and `messages_accepted' = messages_accepted + 1`.

**Why it succeeds**:
The intent of the system (as seen in `messages_accepted` increments) is to track all successful attestation processing. However, the temporal property `temporal_zk_accept_requires_vkey` (lines 410-419) specifically guards only the transition where `next(last_result) == Accepted`. It is completely silent regarding the `SkippedNoVKey` result. Consequently, a ZK attestation can be "accepted" (incrementing the success counter) without any VKey being configured, and the temporal property will be vacuously satisfied. The spec fails to witness the "obligation" for a significant subset of successful ZK attestation paths.

**Severity**: `serious` (The property does not actually cover the full scope of "ZK acceptance" as defined by the system's own success counters).

**Suggested defense**: Expand the property to cover all results that increment `messages_accepted`, or redefine "acceptance" in the temporal property to include `SkippedNoVKey`.

---

### 3. Triviality (Redundant Logic)

**Category**: Triviality

**Concrete scenario**:
Any attempt to find a violation of the temporal property using the current `verify_zk` action.

**Why it succeeds**:
The temporal property is a tautology relative to the `verify_zk` implementation. The `if-else` chain in `verify_zk` (lines 216-275) explicitly checks `config.zkdcap_vkey == ""` and `not(zk_module.registered_vkeys.contains(...))` before it is even possible to reach the `else` block that sets `last_result' = Accepted`. Because the action is atomic and the property merely mirrors the control flow of the action, the temporal property adds zero additional formal constraint to the system. It is "correct" only because it repeats the implementation's own logic, providing no independent verification of the intent.

**Severity**: `cosmetic` (Does not break correctness, but provides a false sense of security and adds maintenance overhead).

**Suggested defense**: If the property is intended to be a high-level requirement, it should be decoupled from the specific implementation details of `verify_zk` to ensure it can catch implementation errors.

---

**META**
- **Categories attacked**: Temporal-state mismatch, Coverage gap, Triviality.
- **Categories not attacked**: Under-specification (addressed via coverage gap), Over-specification, Ambiguity, Contradiction, Edge case, Composition failure, Refinement mismatch.
- **Artifacts wanted**: The implementation of `verify_quote` (to ensure no other path to `Accepted` exists) and the full implementation of `verify_any`.
- **Estimated confidence**: High.