# burnt/gpt-oss-120b (gpt-oss-120b) — verus-prototype Critical 4 + 5 cross-critique

- Elapsed: 113.5s
- Model: burnt/gpt-oss-120b

---

**Cross‑critique by OpenCode**

## Critical 4 vote: DEFEND  

The Verus spec `dstack_zk_handle` (lines 425‑462 of `crates/contracts/core/verus‑prototype/attested.rs`) only requires that, when a vkey is set, the external call `zk_query_verify_succeeded(msg.zkdcap_proof, msg.zkdcap_public_inputs, raw.zkdcap_vkey)` succeeds. It never relates `msg.zkdcap_public_inputs` (or the proof) to the wrapper’s `user_data` or `compose_hash`.  

The production handler `DstackZkAttestation::handle` (lines 74‑124 of `crates/contracts/core/src/handler/execute/attested.rs`) forwards `self.zkdcap_proof` and `self.zkdcap_public_inputs` unchanged to the ZK module (lines 95‑99). No check is performed that the public inputs encode the wrapper’s `user_data` and `compose_hash`.  

The outer `Attested` wrapper (lines 178‑186 of the same file) validates `msg_data == attestation.user_data` and, if config is present, `config.mr_enclave() == attestation.mr_enclave()`. These checks bind the *declared* fields, not the fields hidden inside the ZK proof. Consequently an attacker can supply a valid proof for a different enclave instance while keeping the declared `user_data`/`compose_hash` consistent with the wrapper, and the verification will still succeed.  

Thus the attack surface described is reachable, and the spec omission is real. Claude’s suggested defense—introducing an uninterpreted predicate `proof_journal_binds(proof, public_inputs, expected_compose_hash, expected_user_data)` and requiring it in the `Ok` branch—is appropriate.

## Critical 5 vote: DEFEND  

The prototype defines `pub_key(km)` with a postcondition that the returned key equals `verifying_key_spec(km.sk)` (lines 150‑152 of `crates/enclave/core/verus‑prototype/key_manager.rs`). The theorem `pub_key_matches_sk` (lines 184‑190) restates this invariant for any `km`.  

In the prototype, `import_sk` is a pure function returning a fresh `SigningKey` (lines 171‑174); it does **not** mutate a `DefaultKeyManager`. Consequently the spec never models the mutable `Import::import` implementation.  

Production code (`impl Import for DefaultKeyManager` lines 53‑55 of `crates/enclave/core/src/key_manager/default.rs`) mutates `self.sk` in place. After an import, any previously cached `PubKey` value becomes stale, but the spec still asserts `pub_key(&km).0 == verifying_key_spec(km.sk)` only for the *current* `km.sk`. No temporal guarantee is made that the contract’s published public key stays in sync after a mutation. Hence the binding invariant can be violated in practice, exactly as Claude described.  

Claude’s proposed fix—adding a ghost field `pub_key_published` (or otherwise modeling the publish step) and proving that `import` either invalidates or atomically updates it—addresses the missing temporal link.

## Net recommendation  

Both findings expose real gaps between the Verus specifications and the production Rust implementation. The upstream PR should incorporate:

1. **ZK binding predicate** – add a spec‑level predicate linking `zkdcap_public_inputs` (and the proof) to the wrapper’s `user_data` and `compose_hash`, and enforce it in `dstack_zk_handle` and the production `DstackZkAttestation::handle`.  
2. **Key‑manager temporal invariant** – extend the key‑manager model with a ghost field (or explicit publish step) that tracks the currently published public key, and prove that `Import::import` either clears or updates this field so the invariant holds after mutation.

Implementing these fixes will close the critical attack surfaces and bring the production code into alignment with the Verus security model.

