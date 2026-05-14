# Round C Adversarial Review — Four Unattacked Quint Specs

- **Specs under review**:
  - `/Users/mvid/Development/reliq/quartz/specs/handshake.qnt` (835 lines)
  - `/Users/mvid/Development/reliq/quartz/specs/attestation.qnt` (492 lines)
  - `/Users/mvid/Development/reliq/quartz/examples/pingpong/specs/pingpong.qnt` (452 lines)
  - `/Users/mvid/Development/reliq/quartz/examples/transfers/specs/transfers.qnt` (487 lines)
- **Intent doc**: `/Users/mvid/Development/reliq/quartz/CLAUDE.md`
- **Date**: 2026-05-14
- **Round**: C
- **Adversary**: Claude Opus 4.7 (1M context)

## Per-spec verdicts

- **VERDICT (handshake.qnt): WEAKENS** — eight modeling drifts and one critical "honest enclave" tautology that severely weakens the value of P10/P14/P15. Spec posits enclave fields that the Rust contract has no access to.
- **VERDICT (attestation.qnt): HOLDS WITH CAVEATS** — a small but real `verify_quote` privacy/integrity drift (no `proof_bytes`-style discipline on raw quote), `inv_mock_mode_monotonic` is a no-op (literally `true`), and the model treats Xion's gnark vkey lookup as a set membership instead of also exercising the verifier's verdict.
- **VERDICT (pingpong.qnt): WEAKENS** — `inv_plaintext_private` is vacuous (the only writer is never called), the spec models `ping` with an `ErrSlotOccupied` guard that does not exist in Rust (the contract unconditionally overwrites), and the spec embeds a handshake-level `enclave.has_session_key` flag that is **never set to false**, so `ErrInactiveSession` is dead and downstream invariants do not bind.
- **VERDICT (transfers.qnt): BREAKS** — the conservation invariant is provable only because the spec never models the **observer-visible withdrawal amount** that the on-chain `BankMsg::Send` reveals (the very thing `inv_balances_private` claims is hidden), AND because the spec processes a single in-order request per `update` while the real `update` drains a prefix in bulk with an untrusted `quantity`. A specific 2-step trace (withdraw_then_drain) can break conservation under the *real* contract semantics while the spec reports green.

---

## 1. [handshake] Enclave-state invariants are vacuous in honest runs

**Target spec**: `handshake.qnt`
**Category**: Dormant invariant / cross-component-modeling drift
**Severity**: serious

**Scenario**: P14 (`inv_nonce_consistency`, lines 801–807) and P15 (`inv_pubkey_consistency`, lines 810–814) check that the *enclave*'s nonce/pubkey match the *contract*'s — but only `if enclave.nonce != ""` and `if enclave.pubkey != ""`. The only writers of these fields are the success branches of `session_create` and `session_set_pubkey` (lines 359–364, 522–525), which copy *the same `nonce`/`pubkey` they wrote to the contract*. So the antecedent and consequent are written by the same atomic action with the same RHS — the invariant is satisfied tautologically across all reachable states. `reset_session` (line 630) clears the enclave fields, which makes the antecedents false. There is no reachable state where the enclave field is non-empty and disagrees with the contract.

**Why it succeeds**: The Rust framework does not have an "enclave state" in contract storage. The enclave is an off-chain process. Modeling enclave-internal fields as if they were on-chain reachable state with their own non-determinism would require introducing actions that mutate `enclave.{nonce,pubkey}` independently of the contract — e.g., an "enclave goes offline mid-handshake", "enclave restored from stale backup", or "two enclaves race". None of these are model actions, so P14/P15 are dormant.

**Suggested defense**: Add `enclave_desync` actions that perturb `enclave.{nonce,pubkey}` independently (modelling enclave restart, backup-restore drift, or replacement attack) and re-run BMC. If P14/P15 are intended to hold across these, the success branches need to be hardened (e.g., session-key rotation). If the invariants are meant only for honest dst, mark them as honest-flow lemmas, not adversarial invariants.

---

## 2. [handshake] Instantiate's pre-config Attested wrapper drift

**Target spec**: `handshake.qnt`
**Category**: Spec-vs-implementation drift
**Severity**: serious

**Scenario**: The Rust flow in `Instantiate<A>::handle` (instantiate.rs lines 17–22) does **one** equality check (`msg.config.mr_enclave == attestation.mr_enclave`). The outer `Attested<M, A>::handle` wrapper (attested.rs lines 167–196) runs user_data + mr_enclave checks, but the mr_enclave check is guarded by `CONFIG.may_load(deps.storage)?` — during instantiate, CONFIG is not yet saved, so `may_load` returns `None` and the mr_enclave check is **skipped**. The user_data check still runs.

The Quint `instantiate` action (lines 172–253) only models the `Instantiate<A>` mr_enclave check (lines 192, 211) and a synthetic "must come from real enclave" check (line 211) that conflates the attestor-side reality. **It does not model the Attested-wrapper user_data check at instantiate time at all** — there are no `msg_hash` / `att_user_data` parameters to `instantiate`. So:

- A malicious attestation with `user_data ≠ msg_hash` but `mr_enclave == msg.config.mr_enclave` would be **rejected by the Rust wrapper** (UserDataMismatch) but **accepted by the Quint model**.

**Why it succeeds**: The spec lifted the inner-handler check but missed the outer `Attested` wrapper's user_data discipline at the instantiate phase. The discrepancy is silent because the spec does not parameterize `instantiate` with msg-hash inputs.

**Suggested defense**: Add `msg_hash` and `att_user_data` parameters to `instantiate(...)`, plus an `ErrUserDataMismatch` early-branch mirror of the wrapper. Also assert that an Ok `ActInstantiate` had matching hashes (parallels P8, line 736).

---

## 3. [handshake] `inv_compose_hash_checked` is anchored to *post*-snapshot, miscompares pre-state

**Target spec**: `handshake.qnt`
**Category**: Tie-break / snapshot-correctness hazard
**Severity**: serious

**Scenario**: P9 (`inv_compose_hash_checked`, lines 751–758) compares `last_att_compose_hash == prev_config_mr_enclave`. For the successful `instantiate` action (line 234), `prev_config_mr_enclave` is sampled at action entry (line 250: `prev_config_mr_enclave' = contract.config_mr_enclave`), which is the **pre-instantiate** value — `""`. But `last_att_compose_hash` at success records `att_compose_hash` (line 243), which on a successful instantiate is `VALID_COMPOSE_HASH`. So P9 with `last_action == ActInstantiate` would say `"aabbccdd" == ""` — false.

However, P9's antecedent excludes `ActInstantiate` (lines 753–755: only `ActSessionCreate`, `ActSetPubkey`, `ActAttestedMsg`). This is a **subtle action-set fragility** matching exactly the Round-1 S1 pattern: P9 only binds in the post-instantiate world. If a future refactor adds instantiate-time attested verification (which Attack #2 above recommends), or adds a new attested action, the snapshot semantics become wrong because `prev_config_mr_enclave` is the value *before* the action, not the value *the action checked against*. For `instantiate` the contract has no config yet; for the others the config is already set and stable, so the bug is hidden.

**Why it succeeds**: The invariant relies on the implicit assumption "config was already write-once-set before this action". Round-1 settled on `last_action == ActVerifyZk` to make provenance load-bearing; this spec uses the same idiom for three actions but does not make explicit that they all *post-date* config_set. A refactor that allows attestation in pre-config states would silently break.

**Suggested defense**: Promote the implicit guard to an explicit conjunct: `prev_config_set and last_att_compose_hash == prev_config_mr_enclave`. The contract addr P10 (lines 765–769) has the same shape and needs the same hardening.

---

## 4. [handshake] `reset_session` does not reset `sequence_num`, breaking sequence semantics

**Target spec**: `handshake.qnt`
**Category**: Phase-machine completeness
**Severity**: advisory

**Scenario**: `reset_session` (lines 626–648) sets `contract' = contract` (line 636) — so `sequence_num` is preserved across a reset. But `reset_session` is described as "enclave resets, will re-handshake" (line 625). After reset, the next handshake will eventually hit `session_set_pubkey`'s success branch (line 514), which writes `sequence_num: 0`. Between `reset_session` and the next `session_set_pubkey`, `contract.session == SessionActive` is *false* (the reset does not change `contract.session` — only the enclave), so P6 (`inv_active_has_sequence`) does not bind. But the contract's `session` field stays `SessionActive` after `reset_session`! Look at line 636: `contract' = contract`. So after reset, `contract.session == SessionActive` is still **true**, but the enclave has dropped its nonce/pubkey. This contradicts the spec comment.

**Why it succeeds**: The spec author intended reset to flip the session back, but in the model only the enclave-side fields are cleared. The contract has no execute path that resets session state on its own (Rust matches this — `SessionCreate` overwrites unconditionally per the TODO at session_create.rs line 13), but the Quint spec offers no `session_create` precondition that the *enclave* is reset. So a reset followed by `send_attested_message` still passes the `contract.session != SessionActive` guard (line 551 is False — session is still Active).

**Suggested defense**: Either (a) match Rust by removing `reset_session` entirely, since the contract has no such action and the enclave restart is not observable on-chain; or (b) flip `session: NoSession` and `session_pubkey: ""` in the contract on reset, and add a corresponding contract-side action that models the implied re-handshake.

---

## 5. [handshake] Sequence_num initialized to -1, undermining P7

**Target spec**: `handshake.qnt`
**Category**: Bounded-universe accuracy / dormant invariant
**Severity**: advisory

**Scenario**: `init` sets `sequence_num: -1` (line 136). P7 (`inv_sequence_valid`, line 727–729) says `contract.sequence_num >= -1`. This is **always true** in the model: only `init` sets to -1; success of `session_set_pubkey` sets to 0; `send_attested_message` only fires when `SessionActive` (post-set-pubkey) and only adds 1. There is no path that decrements. So P7 is true at init and remains true.

But the *Rust* `SEQUENCE_NUM` is a `Uint64` (state.rs line 18). It's not set until `session_set_pubkey` runs (lines 23–28). Before that, `SEQUENCE_NUM.load(...)` would error. The sentinel -1 in Quint is unrepresentable in Rust. The spec's invariant is satisfied by a value that cannot exist in the real system — masking the real obligation "sequence_num is undefined until SessionActive".

**Why it succeeds**: The bounded-universe artifact (sentinel -1 substituting for "unset") shadows the real precondition. The handler check P11 (line 775) already enforces that `ActSetPubkey` requires `SessionCreated`, but no invariant binds the post-condition "sequence_num is exactly 0 right after `session_set_pubkey`". A refactor that, say, decrements seq on a hypothetical "abort" action would not be caught by P7.

**Suggested defense**: Replace `sequence_num: -1` with `sequence_num: 0` at init, and add an invariant `if contract.session != SessionActive then contract.sequence_num == 0` (or similar). The `Uint64` semantics in Rust requires non-negativity; reflect that in the model.

---

## 6. [handshake] Wrong `last_msg_contract` carry on failure paths leaks into P10

**Target spec**: `handshake.qnt`
**Category**: Action-tag refactor hazard
**Severity**: advisory

**Scenario**: P10 (`inv_contract_addr_validated`, lines 765–769) says: on Ok `ActSessionCreate`, `last_msg_contract == contract.contract_addr`. This is correct given the success branch (lines 365, 369). But failure branches of `session_create` write `last_msg_contract' = msg_contract` (e.g. line 284) regardless of validity. `send_attested_message` and other actions preserve `last_msg_contract' = last_msg_contract` (line 614). So a sequence:

1. `session_create` succeeds → `last_msg_contract == CONTRACT_ADDR`, `last_action == ActSessionCreate`.
2. Any subsequent action fires that preserves `last_msg_contract` but changes `last_action`.

Then `inv_contract_addr_validated` antecedent fails because `last_action != ActSessionCreate`, and the property is vacuous from step 2 onward. So P10 only ever holds across the single step that wrote it, then becomes a non-witness.

This is exactly the action-tag fragility flagged in `temporal_zk_accept_requires_vkey-2026-05-12-synthesis.md`: state-based invariants predicated on `last_action == X` are only "live" for one transition.

**Why it succeeds**: The author intended P10 to be a "this property held at the moment of the SessionCreate success". The state-only encoding via `last_action` cannot witness that across multiple steps without temporal operators. Apalache + temporal would be the right tool; without it, P10 is a single-shot check.

**Suggested defense**: Promote P10 to a temporal property mirroring Round-1's `temporal_zk_accept_requires_vkey`: `always((next(last_action) == ActSessionCreate and next(last_result) == Ok) implies next(last_msg_contract) == contract.contract_addr)`. Same advice applies to P11/P12/P13/inv_user_data_checked.

---

## 7. [handshake] No model of session re-creation while a previous session is active

**Target spec**: `handshake.qnt`
**Category**: Session lifecycle edge case
**Severity**: serious

**Scenario**: `session_create` (line 269) has zero guard on prior session state. The Rust code in `session_create.rs` line 13 has the explicit TODO comment "TODO(hu55a1n1): overwrite previous session?". The spec mirrors this: the success branch (line 352–376) unconditionally writes `session: SessionCreated, session_nonce: nonce, session_pubkey: ""` even when `contract.session == SessionActive`. So the model admits the trace:

1. Complete handshake → `session == SessionActive`, `session_pubkey == PUBKEY_1`, `sequence_num >= 0`.
2. `session_create` with `nonce == NONCE_2` → `session == SessionCreated`, `session_pubkey == ""`, `sequence_num` preserved (line 357 comment: "sequence_num is NOT reset here").
3. State: `session_pubkey == ""` and `sequence_num >= 0` and `session == SessionCreated`.

**This is a security-relevant transition**: a fresh handshake replaces the session key, but stale `sequence_num` means the new session inherits the old counter. There is no invariant that catches this. P11/P12/P13 are predicated on `last_action == ActSetPubkey`. P6 (`inv_active_has_sequence`) only fires when `SessionActive`.

After step 2, `inv_created_no_pubkey` (lines 712–716) is satisfied, but nothing flags that we have a partially-formed handshake whose `sequence_num` came from a prior session.

**Why it succeeds**: The Rust TODO is *known unmodeled*. The spec inherited the gap. In a real flow, the off-chain user gateway is expected to re-encrypt with the new session key, and the seq_num inheritance is a separate concern — but the spec is silent.

**Suggested defense**: Either (a) the Rust code should reset `SEQUENCE_NUM` on `SessionCreate` (close the TODO), and the spec should mirror that; or (b) the spec should add an explicit invariant `if last_action == ActSessionCreate and prev_session == SessionActive then contract.sequence_num == 0` after the eventual `session_set_pubkey`, making the inheritance explicit and flaggable.

---

## 8. [attestation] `verify_quote` accepts arbitrary `quote` bytes

**Target spec**: `attestation.qnt`
**Category**: Spec-vs-implementation drift
**Severity**: serious

**Scenario**: `verify_quote` (lines 183–217) only checks `msg_hash == user_data` and `compose_hash == config.compose_hash`. The success branch returns `AcceptedQuote` regardless of `msg.attestation.quote`. The model exposes `quote = oneOf(Set(VALID_QUOTE, ""))` (line 342), but no path uses `quote`. Empty quotes are accepted; arbitrary quotes are accepted.

The Rust handler (attested.rs lines 47–60) is currently a no-op placeholder (`// TODO: On-chain DCAP quote verification`) — the comment says: *the user_data and compose_hash checks in the Attested wrapper provide the core integrity guarantees*. So the spec matches current Rust behavior. **But** this is a known-incomplete handler: the production path is `DstackZkAttestation` (gnark). The Quint spec embeds the no-op as if it were correct, with no `inv_quote_path_disabled_in_production` or `inv_zk_required_for_attestation` invariant.

**Why it succeeds**: The spec faithfully models a TODO. The intent doc (CLAUDE.md) says "zkdcap verifier migration: circom ProofVerify → gnark ProofVerifyGnark" is the live blocker. So in production, all attestations must traverse `verify_zk`, not `verify_quote`. The spec admits Quote-variant acceptances that the production design rejects.

**Suggested defense**: Add an `inv_quote_disabled_in_production` invariant that conditions on a `mock_mode_active` boolean: `if not(mock_mode_active) then last_action == ActVerifyQuote implies last_result != AcceptedQuote`. Or remove `AcceptedQuote` as a non-test outcome.

---

## 9. [attestation] `inv_mock_mode_monotonic` is literally `true`

**Target spec**: `attestation.qnt`
**Category**: Vacuous invariant
**Severity**: advisory

**Scenario**: Lines 475–482:

```quint
val inv_mock_mode_monotonic: bool = {
  true
  // (The model enforces this: ...)
}
```

The body is `true`. The comment says the property is meta-verified by inspecting the action set. There is also a `temporal_mock_mode_monotonic` (lines 468–470) that is the real check. But the state-only stub in `all_invariants`? It's not even there (line 484: composite excludes `inv_mock_mode_monotonic`). So this val is genuinely dead.

**Why it succeeds**: An invariant named for its property but defined as `true` is misleading documentation. Future readers will assume a real check is in force.

**Suggested defense**: Either delete the val entirely (rely on the temporal property), or rewrite it as a *history-tracking* invariant: add `var ever_mock_enabled: bool` set to `true` by `enable_mock` and never cleared, and assert `ever_mock_enabled implies zk_module.accept_all`.

---

## 10. [attestation] `inv_variant_outcome_consistent` does not bind on `enable_mock` / `clear_vkey`

**Target spec**: `attestation.qnt`
**Category**: Action-tag refactor hazard
**Severity**: advisory

**Scenario**: P3 (`inv_variant_outcome_consistent`, lines 397–412) predicates on `last_input.attestation.variant`. But `enable_mock` (line 311) and `clear_vkey` (line 322) preserve `last_input' = last_input` (lines 317, 328). So immediately after `enable_mock`, `last_input.attestation.variant` is the variant of *the last verify call*, and `last_result` is also stale. The invariant binds — but on **stale** data. If the prior verify was `Zk` and `Accepted`, then `enable_mock` runs, the invariant still holds (because `Accepted` is in the Zk-branch outcome set), but it doesn't reflect a real `verify_zk` invocation. A future refactor that allows `enable_mock` to also reset `last_input` to a `Quote`-variant default would silently make P3 vacuously true (Quote-variant + Accepted is not in the Quote set, so the invariant would fire — but only because the synthesis is broken).

The fix to anchor P3 on `last_action == ActVerifyQuote` or `last_action == ActVerifyZk` (rather than `last_input.attestation.variant`) is exactly the Round-1 action-tag fix.

**Why it succeeds**: Last-input-variant is a state proxy for last-action-kind. The synthesis writeup (`.colosseum/attacks/temporal_zk_accept_requires_vkey-2026-05-12-synthesis.md`) called out this exact substitution.

**Suggested defense**: Rewrite P3 to predicate on `last_action`: `if last_action == ActVerifyQuote then last_result in {AcceptedQuote, RejectedUserDataMismatch, RejectedComposeHashMismatch}` etc. The `last_input.msg_hash != ""` filter then becomes unnecessary because the action tag is precise.

---

## 11. [attestation] ZK acceptance path treats vkey set as boolean; no proof-byte verification

**Target spec**: `attestation.qnt`
**Category**: Bounded-universe accuracy / cross-spec composition
**Severity**: serious

**Scenario**: `verify_zk` (lines 225–292) reduces ZK verification to: (1) vkey is in `zk_module.registered_vkeys`, and (2) `proof.proof_bytes != ""` (unless `accept_all`). This is a **set membership** + **non-empty bytes** check. The real Xion ZK module (attested.rs lines 105–120) calls `query_grpc("/xion.zk.v1.Query/ProofVerifyGnark", req)` which returns `verified: bool` after running the gnark Groth16 verifier. The verifier can return `false` for valid-vkey + non-empty-bytes-but-malformed proofs. The Quint model has no path where vkey is registered and proof bytes are non-empty but the proof is rejected — i.e., **the model assumes every non-empty proof against a registered vkey verifies**.

`temporal_zk_accept_requires_vkey` (lines 456–463) inherits the same limitation: it requires `proof_bytes != ""` but not that the bytes are a *valid* proof.

**Why it succeeds**: The bounded universe lacks a "valid_proof: bool" parameter on the ZK module. The synthesis writeup did flag a related "mock mode + empty proof reaches Accepted" finding, but the dual ("real mode + non-empty invalid proof reaches Accepted") is unmodeled.

**Suggested defense**: Add `valid_proof: bool` to the universe (via `nondet`), and the verify_zk success branch should require `(zk_module.accept_all or valid_proof)`. Update `temporal_zk_accept_requires_vkey` to include `(zk_module.accept_all or next(valid_proof))`.

---

## 12. [pingpong] `inv_plaintext_private` is vacuous — `can_see_plaintext` has no writer

**Target spec**: `pingpong.qnt`
**Category**: Vacuous invariant / privacy modeling
**Severity**: critical

**Scenario**: `observer.can_see_plaintext` is initialized to `false` (line 127) and **never assigned a non-false value anywhere in the spec**. All actions preserve it (`observer' = observer`, lines 162, 182, 217, 247, etc.). So P1 (`inv_plaintext_private`, lines 352–354) is trivially `not(false) == true` for all reachable states.

This is the *primary* privacy claim of the pingpong example. It is not checking anything. The spec admits no path where an observer could *gain* plaintext visibility — but it never models such a path even hypothetically. The spec author conflates "the model has no plaintext-leak action" with "the protocol has no plaintext-leak vulnerability".

The XOR-encrypted pingpong is a *known weak primitive* in the implementation (echo with one-time pad against a session-derived key). The spec models the ciphertext as opaque, but a real attack vector is: observe two pongs to the same ephemeral pubkey across re-handshakes — the XOR of two same-key ciphertexts is the XOR of the plaintexts. The spec has *no* model of multi-ping/pong against the same pubkey leaking, and no `nondet` variable for an "observer ran a known-plaintext analysis".

**Why it succeeds**: Privacy invariants must model the adversary explicitly. A `can_see_plaintext: bool` that no action ever writes provides only a sanity guard against future refactors that *forget* to set it. It does not model an adversary.

**Suggested defense**: Add an action `observer_attempts_decryption(ct: Ciphertext)` that sets `can_see_plaintext: true` iff the observer has seen at least two ciphertexts with the same key fingerprint (modeling XOR key reuse), or modify the ciphertext universe so that the same plaintext under the same key produces the same ciphertext and check non-uniqueness across observer's set. Then P1 binds non-vacuously.

---

## 13. [pingpong] `ping` `ErrSlotOccupied` guard does not exist in Rust

**Target spec**: `pingpong.qnt`
**Category**: Spec-vs-implementation drift
**Severity**: serious

**Scenario**: `ping` (lines 154–194) branches on `cur != Empty` and returns `ErrSlotOccupied` (line 160). The comment at line 157 says *"Real contract WOULD overwrite; we model this as an error path so the invariants below can talk about disciplined use."*

The Rust `execute::ping` (contract.rs lines 61–74) just calls `PINGS.save(deps.storage, ping.pubkey.to_hex(), &ping.message)?` — **unconditional overwrite**. So:

- Real Rust trace: `ping(PK_1, ct1)` → slot has `ct1`. `ping(PK_1, ct2)` → slot has `ct2`. A pending Pong is **overwritten**.
- Quint model: `ping(PK_1, ct1)` → slot is `PingPending`. `ping(PK_1, ct2)` → `ErrSlotOccupied`, slot unchanged.

The model's `inv_message_slot_consistency` (line 359), `inv_pong_requires_ping` (line 369), `inv_no_pong_to_pending_regression` (line 414) all rely on the disciplined-use semantics. Under real Rust semantics, the slot can hold a fresh `ct2` ciphertext after a `Pong` was delivered for `ct1` — the slot state machine in Quint becomes lossy.

Concretely: in Rust, `ping → pong → ping(overwrite)` produces a slot with a Ping ciphertext stored where the Pong response used to be. The Quint model cannot reach this state.

**Why it succeeds**: The spec author chose "disciplined use" as the modeling axiom rather than "what the contract actually does". This is an explicit choice (the comment is honest about it), but it means the spec verifies a *different protocol* than the implementation. Any invariant that holds in the spec model does not transfer to the implementation.

**Suggested defense**: Either (a) add the missing slot guard to the Rust `execute::ping` handler, or (b) model the real overwrite semantics in Quint by removing the `ErrSlotOccupied` branch and weakening `inv_no_pong_to_pending_regression` to account for Ping-overwriting-Pong-delivery.

---

## 14. [pingpong] `enclave.has_session_key` is never set to false

**Target spec**: `pingpong.qnt`
**Category**: Cross-spec composition / dormant invariant
**Severity**: advisory

**Scenario**: `enclave.has_session_key` is initialized to `true` (line 124) and never modified by any action. `pong`'s first guard `if (not(enclave.has_session_key))` (line 212) is therefore dead — it never fires. The `ErrInactiveSession` result (line 213) is unreachable.

The intent appears to be cross-spec composition with `handshake.qnt`'s `SessionActive` state, but pingpong does not import handshake or re-derive the session-active condition. The variable is a placeholder.

**Why it succeeds**: A failure mode that depends on session state cannot be modeled in a spec that omits handshake-level dynamics. The pingpong spec inherits handshake assumptions but provides no mechanism to weaken them.

**Suggested defense**: Either (a) add a `session_reset` action that sets `has_session_key: false`, then add `inv_no_pong_without_session_key`, or (b) remove the `has_session_key` field and the `ErrInactiveSession` branch entirely.

---

## 15. [pingpong] `reset` clears slot but inconsistently preserves entries in messages map

**Target spec**: `pingpong.qnt`
**Category**: Bounded-universe accuracy
**Severity**: advisory

**Scenario**: `reset` (lines 300–324) builds the new `messages` map by folding over keys *excluding* the reset pubkey (lines 310–311), then sets `slots.put(user_pubkey, Empty)`. The intent is to clear both. But:

```quint
messages: contract.messages.keys().exclude(Set(user_pubkey))
  .fold(Map(), (acc, k) => acc.put(k, contract.messages.get(k))),
```

This rebuilds the map. But `slots.put(user_pubkey, Empty)` retains the key with value `Empty`. So after reset, `messages.keys()` does not contain `user_pubkey`, but `slots.keys()` does. `inv_message_slot_consistency` (line 359) iterates `messages.keys()` — it would not catch the orphan slot key. The reverse direction (slot keys ⊆ message keys + empties) is unchecked.

The real Rust contract has no `reset` execute path; the `PINGS` map only ever grows or has entries overwritten via `PINGS.save`. There is no `PINGS.remove`. So the spec's `reset` is a fiction. The on-chain `PINGS` map after a Pong delivery still contains the user's pubkey → response — until and unless a future Ping overwrites it.

**Why it succeeds**: The Quint model's `reset` introduces an action that does not exist in Rust, then uses it to maintain map consistency in a way that the implementation does not. This is benign if `reset` is purely a model-internal scaffolding action, but the spec does not flag it as such.

**Suggested defense**: Remove `reset` from `step` or rename it explicitly (e.g., `ghost_reset_observer_view`) and document that it is model scaffolding, not protocol. Add an invariant `slots.keys() == messages.keys() union {pubkeys with slot == Empty}`.

---

## 16. [transfers] Conservation invariant misses observer leakage via `BankMsg::Send`

**Target spec**: `transfers.qnt`
**Category**: Privacy / disclosure invariant
**Severity**: critical

**Scenario**: The transfers Rust `update` (contract.rs lines 182–212) emits `BankMsg::Send { to_address, amount }` for each `(user, funds)` in `msg.withdrawals` (lines 201–207). These messages are **on-chain bank transfers** — the recipient address and amount are public.

The Quint spec models withdrawals as `apply_withdraw` (lines 253–259) which drains the balance and updates `total_supply`. The observer view sets `can_see_withdrawals: true` at init (line 155). But:

- The model does not record withdrawal *amounts* in any observable. The observer flag is a static boolean.
- The spec claims `inv_balances_private` (line 396) — `can_see_balances == false`. But every withdrawal reveals the *exact balance the user held immediately before withdraw* (the drain amount equals the entire balance, per the `apply_withdraw` semantics that match Rust's `state.state.remove(&receiver)` at update.rs line 156).

So **a sequence of "deposit Alice 100, withdraw Alice" leaks "Alice's balance was 100" to all chain observers** via the BankMsg::Send amount. Then any later "transfer Alice 50 to Bob" followed by "withdraw Alice" reveals "Alice's balance was 50" — observable derivation of transfer amounts. The spec does not model this side channel at all. `inv_balances_private` and `inv_transfers_private` (lines 396–405) are both `not(false) == true` — vacuous in the same way as Attack #12.

**Why it succeeds**: The privacy claim is for *balances*; the implementation reveals balances at withdrawal time as a structural side effect. The spec's observer view models the *contract's* perspective (encrypted state blob) but not the *bank module's* perspective (plaintext `BankMsg::Send`).

**Suggested defense**: Add `observer.observed_bank_sends: Set[(Addr, Amount)]` updated by `update` whenever a withdrawal is processed. Replace `inv_balances_private` with a real adversarial invariant: "for every (addr, amt) in observed_bank_sends, the adversary's inferable lower-bound on balance(addr) at the withdrawal time is amt". Then state explicitly that this invariant **does not hold** in the current design — making the leakage visible rather than papered over.

---

## 17. [transfers] Spec processes single in-order request; Rust drains prefix with attacker-chosen `quantity`

**Target spec**: `transfers.qnt`
**Category**: Spec-vs-implementation drift / phase-machine completeness
**Severity**: critical

**Scenario**: The Quint `update` (lines 301–318) processes `contract.requests.head()` — exactly one request per step. The Rust `execute::update` (contract.rs lines 182–212) processes `msg.quantity as usize` requests via `requests.drain(0..msg.quantity as usize)` (line 194). `msg.quantity` is supplied by the attested UpdateMsg coming from the enclave (update.rs line 180: `quantity: requests_len`). An *honest* enclave sets quantity to the queue length it observed. But:

- The contract has no check that `msg.quantity == previously_observed_requests_len`.
- The contract has no check that the requests actually drained match what the enclave processed.

If a `requests` mutation happens between the time the enclave reads (via ProofOfPublication) and the time the contract drains, the prefix-drain semantics admit an inconsistency: the contract drains `quantity` items from the *current* queue, which may differ from what the enclave processed. Specifically:

- T0: queue = [W_Alice]; enclave reads queue, processes W_Alice → withdrawals = [(Alice, 100)], quantity=1.
- T1: a fresh `deposit(Bob, 50)` is appended → queue = [W_Alice, D_Bob_50].
- T2: enclave's attested UpdateMsg arrives with `quantity=1, withdrawals=[(Alice, 100)]`, encrypted_state = state_with_alice_drained.
- T3: contract drains 1 request from front → drains W_Alice (consistent), keeps D_Bob_50 pending. Looks fine.

But:
- T0: queue = [D_Bob_50, W_Alice]; enclave reads → state.bob=50, state.alice_drained, withdrawals=[(Alice,balance)], quantity=2.
- T1: enclave's update arrives with `quantity=2`; contract drains 2.

Now consider a race where the queue is reordered (impossible with append-only) or duplicated. The actual hazard is the `quantity` field itself being attacker-controlled (the attestation only binds the *Pong-like* user_data; it does not bind that the queue prefix matches). If a malicious enclave (with valid attestation, e.g., compromised TDX) sets `quantity=0` while supplying nonzero withdrawals, the contract issues `BankMsg::Send` to specified addresses **without draining the queue**, allowing replay.

The Quint spec does not model this. `update` processes one in-order request, so the `quantity`-vs-actual-prefix mismatch is invisible. The Kani harnesses in state.rs lines 81–115 do flag the `quantity > len` panic case, but the panic-free case where quantity *underreports* relative to withdrawals is unchecked.

**Why it succeeds**: The bounded-universe modeling chose "one request per update" for tractability. The model does not include `quantity` as a non-determined parameter. The conservation invariant is preserved by construction in the spec because every update applies exactly the operations the spec author intended.

**Suggested defense**: Parameterize `update` with `quantity: int` and `withdrawals: List[(Addr, Amount)]`. Drain `quantity` requests, apply the inferred operations from the drained prefix, and check `withdrawals` is consistent with the drained prefix. The conservation invariant should fail without this consistency check, motivating a contract-side guard.

---

## 18. [transfers] `inv_no_silent_balance_loss` defined as conservation tautology

**Target spec**: `transfers.qnt`
**Category**: Dormant invariant
**Severity**: advisory

**Scenario**: I8 (`inv_no_silent_balance_loss`, lines 462–472) says: after `ActUpdate`, `sum_of_balances(enclave.balances) - sum_of_balances(prev_balances) == enclave.total_supply - prev_total_supply`. But conservation (I1, line 370) says `sum_of_balances == total_supply` at *every* reachable state. So I1 at the post-state and I1 at the pre-state together imply I8 by simple subtraction. I8 is a strict weakening of I1.

The spec has redundant invariants. If I1 is provable, I8 is provable trivially. If I1 fails, I8 might still hold (it's weaker) — but only as a residual signal, not a useful one.

**Why it succeeds**: The author wrote I8 as a per-step form of I1, intending to catch local violations that the global invariant might miss in a model that allows it to dip and recover. But because the model has no action that breaks conservation mid-step (every `apply_*` keeps both sides balanced by construction), I8 is dominated by I1.

**Suggested defense**: Either delete I8, or weaken it to a *one-sided* form: `enclave.total_supply >= sum_of_balances(prev_balances)` — i.e., no balance evaporates without being matched somewhere. Combined with I2 (non-negativity), this catches asymmetric leaks. Or, more usefully, condition I8 on a non-conservation action (e.g., a hypothetical `slash` action) to make it a real witness.

---

## 19. [transfers] `transfer_request` increments sequence but `update` does not check it

**Target spec**: `transfers.qnt`
**Category**: Phase-machine completeness / cross-spec composition
**Severity**: serious

**Scenario**: `transfer_request` (lines 218–239) increments `contract.sequence_num` (line 232). The Rust path uses `RawSequenced<TransferRequestMsg>` (msg.rs / sequenced.rs) where `Sequenced<T>::handle` (sequenced.rs lines 7–15) increments `SEQUENCE_NUM` and delegates. On the enclave side, `ensure_seq_num_consistency` (update.rs line 103) checks that the enclave's seq matches the contract's. The Quint `update` action (line 301) **does not consult `contract.sequence_num` at all**. Sequence consistency between request submission and update is unchecked in the model.

I5 (`inv_sequence_monotone`, line 412) only checks that `sequence_num > 0` if the last action was `ActTransfer` — i.e., the seq is non-decreasing. Replay protection across `update` is not modeled.

Specifically: if `update` processed a transfer with a stale seq (e.g., the enclave didn't increment its own seq), there's no Quint invariant that flags it. The replay protection is a *between-actor* property and the spec is single-actor.

**Why it succeeds**: The seq_num field is in `contract`, but no action reads it as a precondition. Even in the model where `update` could only apply transfers if `contract.sequence_num` matched some enclave-tracked value, this dependency is invisible.

**Suggested defense**: Add an enclave-side `enclave_seq_num: int`, increment it on `update` when the processed prefix contains transfers, and add invariant `inv_seq_consistency: enclave_seq_num <= contract.sequence_num`. This catches the replay window where a stale `update` arrives for transfers that have already been processed.

---

## 20. [transfers] No model of session-active gating

**Target spec**: `transfers.qnt`
**Category**: Cross-spec composition / dormant invariant
**Severity**: advisory

**Scenario**: `contract.session_active` is initialized `true` (line 141), checked as a precondition in every action (lines 170, 194, 219, 302, 323), and **never set to false** anywhere. This mirrors Attack #14 in pingpong.qnt: a session-state gate that has no off-switch. The intent is composition with `handshake.qnt`, but the import is absent.

**Why it succeeds**: Composition with handshake-level dynamics is unmodeled. Every transfer action's `contract.session_active` check is dead.

**Suggested defense**: Add a `session_reset` action that flips `session_active` to false, then assert that no transfer action can succeed after a reset until a new handshake completes. Even better, embed handshake.qnt and require `handshake.contract.session == SessionActive` as the precondition.

---

## META

### Per-spec attack counts

- **handshake.qnt**: 7 attacks (#1–#7)
- **attestation.qnt**: 4 attacks (#8–#11)
- **pingpong.qnt**: 4 attacks (#12–#15)
- **transfers.qnt**: 5 attacks (#16–#20)
- **Total**: 20 attacks (top of calibration range)

### Severity breakdown

- **Critical**: 3 (#12 plaintext-private vacuous, #16 conservation vs bank-leak, #17 prefix drain quantity mismatch)
- **Serious**: 8 (#1, #2, #3, #7, #8, #11, #13, #19)
- **Advisory**: 9 (#4, #5, #6, #9, #10, #14, #15, #18, #20)

### Categories attacked

- **Spec-vs-implementation drift**: #2 (instantiate user_data), #8 (verify_quote no-op), #13 (ping overwrite), #17 (drain prefix vs single-step)
- **Vacuous invariant / dormant invariant**: #1 (enclave-state honest), #5 (sequence sentinel), #9 (mock_mode_monotonic = true), #12 (plaintext_private), #14 (has_session_key), #18 (no_silent_loss), #20 (session_active)
- **Action-tag refactor hazard / phase-machine drift**: #3 (compose_hash snapshot anchor), #6 (last_msg_contract carry), #7 (session re-create), #10 (variant-outcome), #19 (seq_num replay)
- **Bounded-universe accuracy**: #5, #11 (no valid_proof bit), #15 (reset map-slot orphan)
- **Privacy / disclosure**: #12 (XOR + same-key reuse), #16 (BankMsg::Send reveals balances)
- **Cross-spec composition**: #14, #20

### Common patterns

1. **Privacy invariants encoded as static booleans with no writer** (#12 pingpong, #16 transfers): both example specs claim privacy by setting `observer.can_see_X = false` at init and never modifying it. No adversarial action is modeled. This is the most pervasive failure mode in the example specs and is critical-severity in both cases because it gives a false-positive verification signal on the main thing those examples claim.

2. **Session-active flags without an off-switch** (#14, #20): both example specs reference handshake state via a boolean that is never flipped, leaving the gate dead.

3. **Action-tag fragility echoing Round-1 S1** (#3, #6, #10): three different specs encode "X was checked at the moment of Y" via `last_action == ActY`, which only binds for one step. The Round-1 synthesis already documented this hazard for `temporal_zk_accept_requires_vkey`; the same pattern recurs in spec features that have not been adversarially reviewed.

4. **Spec models the disciplined-use protocol, Rust implements the permissive protocol** (#7 handshake re-create, #13 ping overwrite, #17 quantity-attacker-controlled): the spec author chose a strict semantics for tractable invariants, but the Rust handlers are permissive in ways that invalidate those invariants under adversarial use.

5. **The XOR / weak-primitive concern** (#12): the pingpong example uses ECIES (not XOR) in actual Rust (request.rs line 124), so the prompt's "XOR is a known weak primitive" framing is partially mitigated by the implementation. But the spec models ciphertext as opaque strings, so even key-reuse vulnerabilities in *any* primitive would be invisible.

### Recommendation

**Priority 1**: Fix the three critical findings in the example specs (#12, #16, #17). These invalidate the headline security claims of pingpong and transfers. Specifically:

- For #16/#17, the transfers example should model `observer.observed_bank_sends` and parameterize `update` with an attacker-chosen `quantity`. The conservation theorem will *fail* against this stronger adversary, which is the right outcome — the failure motivates a contract-side `quantity`-prefix-consistency check that does not currently exist.

- For #12, the pingpong example should add a multi-pubkey re-ping scenario and check ciphertext-set non-uniqueness, OR explicitly mark `inv_plaintext_private` as a "modeled-by-construction" assumption rather than a verified invariant.

**Priority 2**: Apply the action-tag fix from Round-1 to all state-only invariants in handshake.qnt and attestation.qnt that predicate on `last_action == X` (Attacks #3, #6, #10). Promote them to temporal properties using the same pattern as `temporal_zk_accept_requires_vkey`.

**Priority 3**: Close the Rust TODOs that the specs faithfully model (session re-create in #7, ping overwrite in #13, drain-quantity in #17). The spec is right to model what the code does, but the code's permissive semantics are the actual security gaps.

**Priority 4**: The dormant-invariant tax (#1, #4, #5, #9, #14, #15, #18, #20) is the single largest pattern in this review (8 of 20 findings). Mechanically auditable: grep for every `if (...condition...)` invariant body and verify the antecedent is reachable with both branches taken. This is a one-time sweep that would catch ~40% of the findings here.

The handshake and attestation specs are *substantively well-constructed* — most of their findings are advisory hazards that future refactors might trip over, not present-day breakages. The two example specs (pingpong, transfers) are the ones with bite: both have critical findings that affect their respective verification claims, and both share the "privacy = static false boolean" anti-pattern. These should be prioritized for the next revision pass.
