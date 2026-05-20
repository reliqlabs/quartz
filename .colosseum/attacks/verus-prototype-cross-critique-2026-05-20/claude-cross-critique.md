# Cross-critique by Claude (subagent, file-access)

- Reviewed at: 2026-05-20
- Reviewer: Claude Opus 4.7 (Agent subagent in Claude Code, file-access via Read/Grep)
- Note: same model family as the original adversary; the "diversification" here comes from fresh reasoning over the actual code rather than from a different model family. Other voices in this cross-critique pass (openai/gpt-5.5, gpt-oss-120b, kimi-k2-6, nemotron-3-120b, gemini-3-1-flash-lite) provide the family-diverse coverage.

## Critical 4 vote: DEFEND

The original Claude's claim is grounded in code reality. The on-chain handler does not bind `zkdcap_public_inputs` to either the wrapper's `compose_hash` or `user_data`.

Verified at `crates/contracts/core/src/handler/execute/attested.rs:80-124` (the production `DstackZkAttestation::handle`):

- L88 loads `CONFIG` to get `zkdcap_vkey` (name only — no `mr_enclave`-bound checking here)
- L94-99 builds `QueryVerifyGnarkRequest` using `self.zkdcap_proof` and `self.zkdcap_public_inputs` verbatim
- L105-111 dispatches the gRPC query to `/xion.zk.v1.Query/ProofVerifyGnark`
- L116-120 only checks `verify_resp.verified == true`

Crucially, there is no code path that:
1. extracts ReportData (the 64 bytes encoding `user_data`) from `public_inputs` and compares it to `self.user_data`, OR
2. extracts the RTMR3 digest (or whatever map yields `compose_hash`) from `public_inputs` and compares it to `self.compose_hash`.

The Attested wrapper at `attested.rs:167-196`:
- L179-181 checks `msg.user_data() == attestation.user_data()` — but `attestation.user_data()` reads the self-declared `self.user_data` field on the attestation struct (`msg/execute/attested.rs:323-327`), not anything extracted from the proof.
- L183-187 checks `config.mr_enclave() == attestation.mr_enclave()` — but `attestation.mr_enclave()` reads `self.compose_hash` (`msg/execute/attested.rs:329-333`), again a self-declared field.

So both wrapper-level pre-checks compare against attacker-controlled struct fields. The proof's actual cryptographic commitments are never cross-checked against these fields.

Verifying the circuit side at `zkdcap/circuits/dcap-gnark/circuit/types.go:100-107`: the public inputs ARE `MrTd, Rtmr0..3, ReportData, TcbStatus, Timestamp` (all tagged `gnark:",public"`), and `circuit/dcap.go:64-88` shows these are bound to the signed quote during `Define`. So the proof DOES attest to specific MrTd/RTMR/ReportData values — the cryptography is sound. The gap is on-chain: nothing checks that the attacker-supplied `public_inputs` bytes deserialize into the same `compose_hash`/`user_data` the wrapper claims. An attacker can pair a valid proof for enclave-instance-A with a wrapper-level claim "this is enclave-instance-B" (matching the configured `mr_enclave`) — both wrapper pre-checks pass (they only check the self-declared fields are self-consistent), and the ZK module verifies that the proof IS valid Groth16 for the given public_inputs.

The Verus spec at `verus-prototype/attested.rs:281-318` is consistent with this gap: the `zk_query_verify_succeeded(proof, public_inputs, vkey_name)` predicate's contract is exactly "the ZK module returned verified=true for these arguments." There is no spec-level predicate `proof_journal_binds(public_inputs, expected_compose_hash, expected_user_data)`, and no ensures clause on the Ok branch tying `public_inputs` back to `wrapper.spec_att_mr_enclave()` or `wrapper.spec_att_user_data()`.

The suggested defense is appropriate but needs precise wording: the production code must, BEFORE submitting to the ZK module (or after, equivalently), parse the gnark public_inputs (32-byte big-endian field elements concatenated) into the typed slots — at least ReportData[0:32] for user_data and a digest-of-RTMR3 (or whatever the agreed compose_hash function is) — and assert equality with the wrapper-claimed fields. Additionally, the wrapper should reject zkdcap_public_inputs whose length doesn't match the vkey's declared public-input count. The Verus spec needs a matching predicate added to the Ok-branch ensures of `zk_query_verify_succeeded`.

One caveat for the defense scope: the exact map `compose_hash := f(RTMR0..3)` is a dstack-specific function and currently lives only in `crates/enclave/core/src/attestor.rs:151-176` (which fetches a precomputed hash from the dstack agent, not from the RTMRs directly). The on-chain handler would need that function reproduced over the public_inputs RTMRs, OR the gnark circuit would need to expose compose_hash itself as a public input (cheaper, single hash to compare). The latter is the cleaner fix — keeps the on-chain check to a single 32-byte equality.

## Critical 5 vote: THIRD_OPTION

The core observation is valid (the temporal property "contract-stored pub_key == derive(enclave's current sk)" is not proved by Theorem 1) but the original framing is overstated in two ways and undersold in one.

**Overstated 1**: the suggested defense ("Import on `DefaultKeyManager` mutates sk and breaks the binding") is technically true but largely irrelevant to the production path. Per `CLAUDE.md`, the production default is `DstackKeyManager`, not `DefaultKeyManager`. Looking at `crates/enclave/core/src/key_manager/dstack.rs:165-182`, `DstackKeyManager::import` does ALSO mutate `self.sk` (re-derives from the stored `key_path` via the dstack KMS), so the same temporal hazard exists, but the failure mode is different:
- DefaultKeyManager: import semantics arbitrary bytes → fresh sk, any value
- DstackKeyManager: import semantics path-redirect → fresh sk = `KMS.derive(new_path)`

In both cases, after a successful `import`, `km.sk` differs from its pre-import value, so any pub_key already published to the contract (via `session_set_pub_key` — confirmed live at `crates/enclave/core/src/handler/session_set_pubkey.rs:91` calling `ctx.key_manager().await.pub_key().await`) is stale w.r.t. the new sk.

**Overstated 2**: framing this as a `DefaultKeyManager`-specific bug. The right scope is "any KeyManager whose Import implementation mutates sk after pub_key has been published." That's a property of the `Import` trait contract, not a property of `DefaultKeyManager` per se.

**Undersold**: the original Claude characterizes this as primarily an ECIES-decryption-failure or signature-verification-failure issue. The more dangerous scenario is silent: if `import` is callable while the enclave is running and a contract session already binds the old pub_key, a future signed message produced by the post-import sk will fail signature verification on-chain (denial of service), but inbound ECIES messages still encrypt to the old pub_key — meaning the post-import enclave can no longer decrypt them either. This is symmetric DoS, not a confidentiality break — but it is still a liveness break that the binding invariant should rule out.

**Refined claim**: the verification gap is not that `pub_key_matches_sk` is wrong (the theorem as stated is correct at the spec level — for any `km`, `pub_key(&km)` is determined by `km.sk`). The gap is that the prototype models only the intra-state binding and not the temporal/cross-state binding. The temporal property requires modelling:

1. A ghost field `published_pub_key: Option<VerifyingKey>` on a state record that includes both the enclave's km and the contract's SESSION-stored pub_key, AND
2. An invariant `published_pub_key == Some(pk) ==> pk == verifying_key_spec(km.sk)` that holds across all transitions in the model.

The `Import::import` operation must then either (a) be precondition-guarded by `published_pub_key == None`, OR (b) atomically refresh `published_pub_key` (which in production would require an out-of-band re-publish step — a second `session_set_pub_key` after import, which the current handler `crates/contracts/core/src/handler/execute/session_set_pub_key.rs:11-22` does not allow because it errors if pub_key is already set).

**Refined defense recommendation**: rather than the Verus-side ghost field alone, the production gap is more important — there is no key-rotation flow at all. The cleanest fix is a `session_rotate_pub_key` execute message on the contract that allows replacing the SESSION pub_key with a fresh attested `session_set_pub_key` (gated on a fresh attestation matching `mr_enclave`). The Verus prototype should then model both `import` AND `rotate` as transitions, and prove the invariant across the joint transition. Without the production rotate path, `Import::import` is a footgun and the safest short-term fix is to remove or gate the `Import` impl on `DstackKeyManager` (e.g., document it as "for cold-restart recovery only, never call on a live enclave").

Note also: the prototype as written does NOT model import as a `&mut self` operation at all (`verus-prototype/key_manager.rs:171-174` returns a fresh `SigningKey` rather than writing one back). This means even the local intra-state binding is not weakened by import in the model — the model simply doesn't see import as a state transition. That's the precise spec defect: import should be a `&mut DefaultKeyManager` exec fn whose postcondition characterizes `km'.sk` in terms of the input bytes, and the theorem suite should include a "no-stale-pubkey" invariant connecting `published_pub_key` to `km.sk` across import.

## Net recommendation

Both findings should land in the upstream PR, but with different shapes.

**Critical 4 (DEFEND, lands as-is)**: add on-chain public_inputs binding. Concrete shape — add a parse step in `DstackZkAttestation::handle` (production, `attested.rs:80-124`) that extracts the expected ReportData (64 bytes) and compose_hash slots from `self.zkdcap_public_inputs` and rejects if they do not match `self.user_data` and `self.compose_hash` respectively. Easiest if the gnark circuit additionally exposes compose_hash as a single public input; otherwise compute it from the four RTMR slots already in the public inputs. The Verus spec gains a `proof_journal_binds` uninterpreted predicate required on the Ok branch of `zk_query_verify_succeeded`. This is a real exploit primitive — a malicious enclave operator with one valid proof for any deployed `compose_hash` they control can spoof acceptance for a different deployed `compose_hash` they don't.

**Critical 5 (THIRD_OPTION, lands reformulated)**: the upstream PR should NOT focus on `DefaultKeyManager::import` mutation as the bug (that's a side-effect of the deeper modelling gap). It should:
1. Document the temporal binding invariant explicitly in `verus-prototype/key_manager.rs` as a follow-up TODO theorem requiring a multi-state model (the current single-state model cannot express it).
2. Either (a) remove the `Import` impl on both `DefaultKeyManager` and `DstackKeyManager` (low cost, high safety — backup_restore can rebuild the KeyManager from scratch rather than mutating), OR (b) add a `session_rotate_pub_key` execute message on the contract and document that `Import::import` MUST be followed by a rotate before the enclave handles any subsequent traffic.
3. Update Theorem 1's docstring to clarify it proves intra-state binding only, and that cross-state (temporal) binding is a future-work theorem requiring a state-machine model.

**Needs further investigation before commit**:
- For Critical 4, confirm with the zkdcap team whether the gnark circuit can add a `ComposeHash` public input (single 32-byte slot, computed inside the circuit from RTMR3) without regenerating all deployed vkeys — if so, the on-chain check is a single equality; if not, the on-chain code must reproduce dstack's compose_hash function from RTMR0..3.
- For Critical 5, confirm whether `Import::import` is invoked anywhere in the current production startup or recovery flow (the `lib.rs:255-330` Backup/Import chain). If it's only used during initial cold-boot before any `pub_key` is published, the temporal hazard is moot and option (a) (remove the impls) is essentially free.
