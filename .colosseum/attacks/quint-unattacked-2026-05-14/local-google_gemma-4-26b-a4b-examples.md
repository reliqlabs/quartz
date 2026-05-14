# Adversarial review of 2 example Quint specs — local-model arm (Round C, batch 2)

date: 2026-05-14
round: C.local.examples
adversary: google/gemma-4-26b-a4b

VERDICT (pingpong.qnt): WEAKENS
VERDICT (transfers.qnt): BREAKS

## 1. [pingpong] Spec-vs-implementation drift (Overwrite behavior)
**Category**  Spec-vs-implementation drift
**Severity**  critical
**Scenario**  A user calls `ping` using a `user_pubkey` that already exists in the `PINGS` map.
**Why it succeeds**  The Quint spec (`pingpong.qnt:136-145`) implements a guard that returns `ErrSlotOccupied` if the slot is not `Empty`. However, the Rust implementation (`examples/pingpong/contracts/src/contract.rs:63`) calls `PINGS.save(...)` unconditionally. In CosmWasm, `Map::save` overwrites any existing value for that key. The spec models a "disciplined" state machine that prevents overwrites, whereas the actual contract allows them. This means Apalache will verify properties (like `inv_message_slot_consistency`) under the assumption that messages are never overwritten, while the implementation can actually experience state-clobbering.
**Suggested defense**  Align the Quint `ping` action with the Rust implementation by removing the `if (cur != Empty)` check, or add a guard in the Rust contract to match the spec's intended discipline.

## 2. [pingpong] Weak privacy assumption (XOR-encryption)
**Category**  Privacy / disclosure invariants
**Severity**  serious
**Scenario**  An observer monitors `seen_ciphertexts` and attempts to derive plaintext.
**Why it succeeds**  The spec defines `inv_plaintext_private` (`pingpong.qnt:263`) as a simple boolean check: `not(observer.can_see_plaintext)`. This is a "black-box" privacy model that assumes if the observer hasn't been explicitly given the plaintext, they don't have it. However, as noted in the spec comments, the protocol uses XOR-encryption. If an observer sees multiple ciphertexts or can influence the ephemeral key, they may derive the plaintext via XOR properties. The spec models the *outcome* of security (no plaintext visible) but fails to model or test the *vulnerability* of the underlying primitive.
**Suggested defense**  Model the encryption as a function where secrecy is conditional on key-uniqueness or entropy, rather than a global boolean state.

## 3. [pingpong] Dormant/Unreachable "Reset" action
**Category**  Dormant invariants
**Severity**  advisory
**Scenario**  The system state transitions via the `reset` action to clear a slot.
**Why it succeeds**  The `reset` action (`pingpong.qnt:213`) is explicitly noted as "not literally an on-chain action." By including it in the Quint state machine, you introduce a "ghost" transition that does not exist in the Rust contract. This can mask bugs: for example, if the contract fails to clear state (leading to storage bloat), Apalache will not catch it because the spec allows a `reset` that clears the state.
**Suggested defense**  Remove the `reset` action from the spec if it is not part of the on-chain logic, or model it as an external administrative action with specific authorization requirements.

## 4. [transfers] Broken `update` logic (Interface and Drain mismatch)
**Category**  Phase-machine completeness
**Severity**  critical
**Scenario**  An `update` action is triggered to process multiple queued requests (`quantity > 1`).
**Why it succeeds**  There is a massive divergence in how `update` is modeled. First, the Quint action signature (`transfers.qnt:236`) is missing the `quantity` parameter present in the Rust `UpdateMsg`. Second, even if it were present, the logic (`transfers.qnt:246-247`) only calculates `e_new` for the *single* request at the head of the queue (`contract.requests.head()`) and then performs a `tail()` (removing only one element). The Rust implementation (`examples/transfers/contracts/src/contract.rs:163`) uses `requests.drain(0..msg.quantity as usize)`, which processes and removes *N* requests. The Quint spec models a system that "loses" money: it deletes multiple requests from the queue but only applies the first one to the enclave state.
**Suggested defense**  Refactor the `update` action to take `quantity: int` and use a `fold` or recursive loop to iterate through the first `N` requests, updating both the `enclave.balances` and `enclave.total_supply` for every request in the batch.

## 5. [transfers] Trivial privacy invariant (Shape)
**Category**  Invariant-shape / triviality
**Severity**  advisory
**Scenario**  An observer attempts to access transfer amounts.
**Why it succeeds**  `inv_transfers_private` (`transfers.qnt:316`) checks `not(observer.can_see_transfer_amounts)`. In the entire spec, no action (`deposit`, `withdraw`, `transfer_request`, or `update`) ever sets this observer field to `true`. Consequently, the invariant is a tautology; it will pass even if the contract logic were fundamentally broken and leaked amounts to the observer, because the "leak" is not modeled in the state space.
**Suggested defense**  Define conditions under which `can_see_transfer_amounts` becomes `true` (e.g., if the `encrypted_state` is empty or a specific observer-key is used) and verify that those conditions are never met by unauthorized actors.

## 6. [transfers] Weak replay protection (Monotonicity)
**Category**  Replay / nonce hygiene
**Severity**  serious
**Scenario**  An attacker attempts to replay a `transfer_request` using the same sequence number.
**Why it succeeds**  `inv_sequence_monotone` (`transfers.qnt:326`) only checks that `contract.sequence_num > 0` if the last action was a transfer. This is insufficient for replay protection; it does not ensure that the sequence number *increases* with every request. An attacker could potentially submit multiple different requests with the same `sequence_num` (e.g., 1), and as long as it is greater than zero, the invariant holds.
**Suggested defense**  Introduce a `prev_sequence_num` ghost variable and enforce `contract.sequence_num > prev_sequence_num`.

## 7. [transfers] Spec-vs-impl drift (State/Ciphertext decoupling)
**Category**  Spec-vs-implementation drift
**Severity**  serious
**Scenario**  An `update` action is called with a malicious or incorrect `new_encrypted_state`.
**Why it succeeds**  In the Quint spec (`transfers.qnt:248`), `new_encrypted_state` is a nondeterministic input that is blindly saved to the contract state. In reality, this ciphertext must be a valid encryption of the enclave's new internal state. The spec fails to model the binding between `enclave.balances` and `contract.encrypted_state`, allowing a state where the on-chain "view" of the state is completely decoupled from the enclave's authoritative balances.
**Suggested defense**  Model `new_encrypted_state` as a function of the new `enclave.balances` (e.g., `encrypt(enclave.balances)`) to ensure the spec enforces that the on-chain state is a valid representation of the enclave state.

## 8. [transfers] Bounded-universe conservation gap
**Category**  Bounded-universe accuracy
**Severity**  advisory
**Scenario**  A bug in the implementation allows a balance to be created for an address not in `ADDRS`.
**Why it succeeds**  `inv_conservation` (`transfers.qnt:296`) relies on `sum_of_balances`, which is calculated by folding over the fixed set `ADDRS` (`transfers.qnt:136`). If a bug in the Rust code allowed an address *outside* this set to hold a balance, `sum_of_balances` would ignore it, and the conservation invariant would still pass (as long as `total_supply` also ignored it). The spec is only "safe" because its universe is artificially constrained to the same small set as the model.
**Suggested defense**  Ensure `sum_of_balances` iterates over all keys present in the `enclave.balances` map, or use a larger/more generic universe for verification.

## META
The review identified 8 distinct attacks across two specs. **Pingpong** is weakened by significant spec-vs-impl drift regarding how the contract handles existing keys (overwrite vs error) and by modeling non-existent actions (`reset`). **Transfers** is broken due to a critical logic error in the `update` action where it fails to iterate through the batch of requests defined by `quantity`, effectively "losing" funds in the model. Both specs exhibit common patterns of "tautological invariants" (privacy checks that are always true by definition) and "bounded-universe" vulnerabilities where the safety of the proof depends on the smallness of the test set rather than the correctness of the logic.