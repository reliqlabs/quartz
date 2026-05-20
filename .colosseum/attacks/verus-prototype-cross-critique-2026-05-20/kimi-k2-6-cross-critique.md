# burnt/kimi-k2-6 (kimi-k2-6) — verus-prototype Critical 4 + 5 cross-critique

- Elapsed: 270.3s
- Model: burnt/kimi-k2-6

---

# Cross-critique by kimi-k2-6

## Critical 4 vote: DEFEND

Claude's reasoning is grounded and the attack is reachable.

Production `DstackZkAttestation::handle` at `crates/contracts/core/src/handler/execute/attested.rs:94-99` constructs the `QueryVerifyGnarkRequest` using `self.zkdcap_proof` and `self.zkdcap_public_inputs` verbatim, with no extraction or equality check against the wrapper-validated fields. The wrapper at `attested.rs:183-186` checks `config.mr_enclave() != attestation.mr_enclave()` where `attestation.mr_enclave()` returns `self.compose_hash` (`msg/execute/attested.rs:238`) — a self-declared field, not a value extracted from the proof's public inputs. The ZK module verifies "this proof is valid for these public inputs"; it has no knowledge that the wrapper claimed `compose_hash = X` while the proof's public inputs encode `compose_hash = Y`.

The Verus prototype `dstack_zk_handle` at `crates/contracts/core/verus-prototype/attested.rs:425-462` faithfully models this omission: its Ok-branch postcondition (`attested.rs:429-437`) terminates at `zk_query_verify_succeeded(msg.zkdcap_proof, msg.zkdcap_public_inputs, raw.zkdcap_vkey)` with no clause linking `msg.zkdcap_public_inputs` back to `wrapper.spec_att_user_data()` or `RawConfig.mr_enclave`. An attacker can submit a valid Groth16 proof for enclave A (public inputs encode A's data) while setting `user_data` and `compose_hash` to match enclave B's expected values. The wrapper checks the self-declared fields, the ZK module checks the proof against the public inputs, and the contract accepts — even though the proof does not attest to the claimed enclave. This is the central security property of the zkdcap pipeline, and both production and prototype omit it.

Claude's suggested defense (add a `proof_journal_binds` uninterpreted predicate and require it on the Ok branch) is the correct fix shape.

## Critical 5 vote: THIRD_OPTION

The core observation is valid but the framing as a reachable critical attack on `DefaultKeyManager` is overstated.

The Verus prototype does not model `Import::import` as a mutation: `import_sk` at `crates/enclave/core/verus-prototype/key_manager.rs:171-174` is a pure function returning a fresh `SigningKey` with no write-back to a `DefaultKeyManager`. The theorem `pub_key_matches_sk` at lines 184-194 is indeed a tautology (`forall |k| verifying_key_spec(k.sk) == verifying_key_spec(k.sk)`), proving nothing about the binding between `pub_key` and `sk`.

However, the specific stale-pub_key attack scenario is not clearly reachable for the modeled type (`DefaultKeyManager`) under normal production operation. Production `try_restore` is invoked once at startup (`host.rs:210`), before the handshake wait (`host.rs:223`). The `pub_key` published to the contract (`session_set_pubkey.rs:91`) is sent after restore. For `DefaultKeyManager`, legitimate `export` + `import` preserves the same key (the roundtrip property addressed by Critical 1). The stale-pub_key scenario requires `import` with *different* data after handshake, which has no production code path.

The more severe instance of this issue is in `DstackKeyManager` (production default, `dstack.rs:56-62`), where `derive_from_dstack` can fall back to a random key on KMS unavailability during restore — producing a different `sk` without updating the contract's stored pub_key. But `DstackKeyManager` is entirely unmodeled (synthesis Critical 19), so the Verus prototype is silent on it.

Refined claim: the Verus prototype should model `DefaultKeyManager` as mutable (with a `pub_key_published` ghost field as Claude suggests) and fix the tautological theorem, but the severity is "serious" (modeling gap that prevents proving temporal invariants) rather than "critical" (no demonstrated reachable exploit path in the modeled system).

## Net recommendation

Critical 4 should land as a production+spec fix: the `DstackZkAttestation` handler must extract or verify-equal `compose_hash` and `user_data` against the zkdcap public inputs (or journal) before accepting the proof, and the Verus prototype's `dstack_zk_handle` Ok-branch postcondition must include a `proof_journal_binds` predicate linking the public inputs to the expected values. Critical 5 should land as a prototype-only fix: model `DefaultKeyManager` mutation with a ghost `pub_key_published` field, fix the tautological `pub_key_matches_sk` theorem, and prioritize modeling `DstackKeyManager` (where the KMS-fallback key-change scenario is the real operational concern) rather than treating the `DefaultKeyManager` gap as a critical exploit.

