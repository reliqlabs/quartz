# openai/gpt-5.5 (gpt-5-5) — verus-prototype Critical 4 + 5 cross-critique

- Elapsed: 83.2s
- Model: openai/gpt-5.5

---

I’ll verify the cited prototype and production paths directly, then vote each finding against the actual code rather than the quoted claims.
# Cross-critique by GPT-5.5

## Critical 4 vote: DEFEND

The finding is valid.

The Verus prototype’s `DstackZkAttestation` model contains only `zkdcap_proof` and `zkdcap_public_inputs` as opaque fields, with no `user_data`, `compose_hash`, or journal field to relate back to the wrapper checks (`crates/contracts/core/verus-prototype/attested.rs:390-393`). Its verifier success predicate is only `zk_query_verify_succeeded(proof, public_inputs, vkey)` (`attested.rs:397-401`), and the Ok postcondition only requires either skipped verification or verifier success on those opaque inputs (`attested.rs:431-437`). There is no clause binding `msg.zkdcap_public_inputs` to `wrapper.spec_att_user_data()` or `RawConfig.mr_enclave`.

Production has the same gap. `DstackZkAttestation` carries self-declared `user_data`, self-declared `compose_hash`, proof bytes, public inputs, and a journal (`crates/contracts/core/src/msg/execute/attested.rs:252-263`). `HasUserData` returns the self-declared `user_data` (`attested.rs:323-326`), and `Attestation::mr_enclave` returns the self-declared `compose_hash` (`attested.rs:329-332`). The generic wrapper checks only those accessors against the message and config (`crates/contracts/core/src/handler/execute/attested.rs:178-186`).

The ZK handler then sends only `self.zkdcap_proof`, `self.zkdcap_public_inputs`, and `vkey_name` to `/xion.zk.v1.Query/ProofVerifyGnark` (`handler/execute/attested.rs:94-110`). It ignores `self.user_data`, `self.compose_hash`, and `self.zkdcap_journal`; after `verified == true`, it accepts (`handler/execute/attested.rs:113-123`). The comment says the journal contains the fields the contract needs (`msg/execute/attested.rs:261-263`), but the handler never decodes or checks it.

So Claude’s attack shape is grounded: a proof/public-input pair can verify for one attestation statement while the wrapper accepts separately supplied `user_data` and `compose_hash`. The contract currently has no code-level equality check that the verified statement is the same statement accepted by the wrapper.

The suggested defense is directionally right: the spec needs a predicate stronger than “the verifier said yes,” and production needs an actual binding check. The production fix should not be only a new uninterpreted predicate; it must decode or otherwise commit-check the zkdcap journal/public inputs and compare the attested `report_data` and compose hash against `self.user_data` and `self.compose_hash` before returning `zkdcap_verified`.

## Critical 5 vote: THIRD_OPTION

The core observation is valid, but Claude’s framing is too strong and the proposed repair is in the wrong layer.

Valid part: production `DefaultKeyManager::pub_key` derives a public key from the current `self.sk` (`crates/enclave/core/src/key_manager/default.rs:28-31`), and `Import::import` mutates that same `self.sk` in place from caller-supplied bytes (`default.rs:49-56`). `DstackKeyManager` has the same shape: `pub_key` derives from current `self.sk` (`crates/enclave/core/src/key_manager/dstack.rs:143-150`), while import can replace `self.sk` after re-deriving from an imported path (`dstack.rs:164-180`). A previously stored contract key is not automatically updated by either key manager.

The prototype also does not model mutating import. It explicitly splits import into `import_sk(bytes) -> Result<SigningKey, KmError>` (`crates/enclave/core/verus-prototype/key_manager.rs:156-174`), so it proves only a pure decode/roundtrip fact, not a state transition on `DefaultKeyManager`.

But Claude overstates what the named theorem proves. `pub_key` itself has a useful snapshot postcondition, `r.0 == verifying_key_spec(km.sk)` (`key_manager.rs:150-153`). The theorem named `pub_key_matches_sk`, however, does not state that property for `km`; its ensures clause is a tautological forall, `verifying_key_spec(k.sk) == verifying_key_spec(k.sk)` (`key_manager.rs:184-190`). So the issue is not just “snapshot theorem does not survive import”; the named theorem is currently vacuous, while the exec function has the actual snapshot contract.

The reachability is also narrower than Claude states. The normal backup path exports the current key manager (`crates/enclave/core/src/lib.rs:286-289`) and restore imports that backup (`lib.rs:317-324`). For `DefaultKeyManager`, export returns `self.sk.to_bytes()` (`default.rs:59-65`), so the intended restore path should preserve the public key if the backup is honest. For `DstackKeyManager`, export stores the key path (`dstack.rs:153-160`) and import re-derives from that path (`dstack.rs:168-180`). Claude’s arbitrary “different sk after import” scenario requires either untrusted/corrupt backup data or a lifecycle path that imports a different backup after the contract has already recorded a pubkey.

The real temporal risk is at the host/session layer: `try_restore` imports store, key manager, attestor, and context, then sends `HandshakeComplete` without proving or checking that the restored key still matches the contract-held session pubkey (`lib.rs:317-338`). The contract stores the session pubkey in `SessionSetPubKey::handle` (`crates/contracts/core/src/handler/execute/session_set_pub_key.rs:13-21`) from the message field hashed into `user_data` (`crates/contracts/core/src/msg/execute/session_set_pub_key.rs:63-75`). There is no modeled invariant tying that stored contract value to the post-restore key manager state.

Refined claim: the prototype should model key-manager import as a state transition and prove either key preservation for backup/restore or session invalidation/re-registration after a key-changing import. A `pub_key_published` ghost field inside `DefaultKeyManager` is not the best abstraction because the published key lives in contract/session state, not inside the key manager. The better fix is a small lifecycle model: `publish_pub_key`, `backup`, `restore/import`, and a ghost `contract_pub_key`, with an invariant that restore either preserves `verifying_key_spec(km.sk) == contract_pub_key` or marks the session unhandshaken.

## Net recommendation

Land Critical 4 as a real fix in the upstream PR: add production binding of `zkdcap_public_inputs`/journal to `user_data` and `compose_hash`, then reflect that with a stronger Verus predicate. For Critical 5, do not land Claude’s exact `pub_key_published` field fix. Land a refined prototype fix: make `pub_key_matches_sk` non-vacuous, model mutating import/restore, and prove backup restore preserves the contract-published key or forces re-handshake/session invalidation.

