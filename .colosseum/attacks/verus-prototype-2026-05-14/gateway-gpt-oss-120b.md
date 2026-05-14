# gpt-oss-120b (gateway) — verus-prototype Round D

- **Elapsed**: 87.0s
- **Finish reason**: stop
- **Usage**: {"prompt_tokens": 22565, "completion_tokens": 7220, "total_tokens": 29785, "prompt_tokens_details": {"cached_tokens": 0}}

---

**VERDICT (instantiate.rs): BREAKS**  
**VERDICT (attested.rs): BREAKS**  
**VERDICT (session_create.rs): BREAKS**  
**VERDICT (session_set_pub_key.rs): BREAKS**  
**VERDICT (encryption.rs): BREAKS**  
**VERDICT (key_manager.rs): BREAKS**  

---  

### 1. instantiate.rs – Under‑specification of `Config` fields  
**Category:** Under‑specification  
**Severity:** critical  
**Scenario:** A transaction supplies a `CoreInstantiate` whose `config` has `mr_enclave = 0xAA…`, `light_client_opts` with an invalid `trust_threshold` (e.g., numerator > denominator), and `zkdcap_vkey = Some("bad".to_string())`.  
**Why it succeeds:**  
- Spec `Config` (lines 9‑15) only contains `mr_enclave : u64`.  
- Spec `core_instantiate_handle` (lines 71‑84) proves `CONFIG.save` stores `msg.config().as_raw()`, which discards `light_client_opts` and `zkdcap_vkey`.  
- Production `CoreInstantiate::handle` (src/handler/instantiate.rs lines 23‑30) stores the full `RawConfig` with all fields.  
Thus the verified property “`CONFIG` now holds `Some(msg.config)`” does **not** guarantee that the full configuration is correctly persisted; a malformed `light_client_opts` could be accepted by the spec but cause a runtime panic in production (`LightClientOpts::new` validation).  
**Suggested defense:** Extend the Verus `Config` model to include all fields (`light_client_opts`, `zkdcap_vkey`) and add corresponding invariants that mirror `LightClientOpts::new` checks.

---  

### 2. instantiate.rs – Coverage gap for storage failures  
**Category:** Coverage gap  
**Severity:** serious  
**Scenario:** The underlying blockchain node runs out of gas while executing `CONFIG.save`, causing `save` to return `Err(Error::Std)` and leaving storage unchanged.  
**Why it succeeds:**  
- `Item::save` in the prototype (lines 41‑53) unconditionally writes `storage.config = Some(...)` and returns `Ok(())`.  
- The spec’s post‑condition (lines 44‑48) only mentions the `Err` case when the result is `Err(_)`, but that case is unreachable in the stub.  
- Production `Item::save` (via `cw_storage_plus::Item::save`) can fail on serialization or out‑of‑gas, which the spec never models.  
Consequently the verified theorem “`Instantiate::handle Ok ⇒ CONFIG holds …`” cannot be trusted when a storage error occurs.  
**Suggested defense:** Replace the body‑verified stub with an `#[verifier::external_body]` version that nondeterministically returns `Ok(())` or `Err(Error::Std)` and updates the post‑condition accordingly.

---  

### 3. instantiate.rs – Over‑specification of error‑branch invariants  
**Category:** Over‑specification  
**Severity:** serious  
**Scenario:** `msg.msg_mr_enclave == msg.att_mr_enclave`, but `CONFIG.save` fails (as in scenario 2). Production returns `Err(Error::Std)` while the spec’s `instantiate_handle` (lines 86‑106) only allows `Err(Error::Std)` when the inner handler returns `Err`, not when the outer save fails.  
**Why it succeeds:**  
- The spec’s `ensures` clause for `Err(_)` (line 95) states `final(storage).config == old(storage).config`.  
- Because the stub never produces `Err`, the proof never checks the case where `core_instantiate_handle` returns `Err(Error::Std)` **after** a successful enclave‑match check.  
Thus the spec claims that any `Err(Error::Std)` must arise from the inner handler, which is false in production.  
**Suggested defense:** Refactor `core_instantiate_handle` to propagate the `Result` from `CONFIG.save` directly, and adjust the outer `instantiate_handle` post‑condition to allow `Err(Error::Std)` with unchanged storage regardless of the source.

---  

### 4. attested.rs – Inner‑handler error propagation omitted  
**Category:** Under‑specification  
**Severity:** critical  
**Scenario:** `ConcreteMsg.handle` (line 45) in production is replaced by `CoreInstantiate.handle`, which may return `Err(Error::Std)` due to a storage failure while writing a new `Session`. The wrapper `attested_handle` (lines 106‑138) should propagate this error, but the prototype’s `ConcreteMsg.handle` (line 48) is defined to always return `Ok`.  
**Why it succeeds:**  
- The spec’s comment (line 31) admits “we lose the ability to prove that an inner‑handler error propagates to the wrapper”.  
- Consequently the theorem “`Attested::handle Ok ⇒ user_data match …`” holds vacuously because the `Ok` branch is the only reachable one.  
In production, a failure in the inner handler would cause the wrapper to return `Err(Error::Std)`, violating the spec’s guarantee that a successful wrapper implies successful inner calls.  
**Suggested defense:** Model `ConcreteMsg.handle` and `ConcreteAtt.handle` as `#[verifier::external_body]` functions that may return `Err(Error::Std)`, and update the wrapper’s post‑condition to require propagation of any such error.

---  

### 5. attested.rs – Over‑simplified `zkdcap_vkey` representation  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** Deploy a contract with `zkdcap_vkey = Some("".to_string())`. Production treats this as a configured key and attempts a gRPC query, which fails and returns `Err(Error::ZkdcapVerificationFailed)`. The prototype models `zkdcap_vkey` as a `u64` where `0 ⇒ None` (lines 19‑27). An empty string is encoded as a non‑zero `u64` (e.g., hash of the string), so the spec believes a key is present even though it is effectively empty.  
**Why it succeeds:**  
- `Config::zkdcap_vkey` (lines 22‑27) maps any non‑zero `u64` to `Some(v)`.  
- Production’s `Config::zkdcap_vkey` (state.rs lines 71‑78) returns `Option<&str>` based on the actual `Option<String>`.  
Thus the spec can claim “vkey is set ⇒ verification succeeds” while production may treat an empty string as a malformed key and reject it, breaking the correspondence.  
**Suggested defense:** Model `zkdcap_vkey` as `Option<String>` (or at least `Option<bool>` indicating presence) and add a predicate that treats empty strings as `None`.

---  

### 6. attested.rs – DstackZkAttestation failure modes collapsed  
**Category:** Disjunction‑vs‑decomposition collapse  
**Severity:** serious  
**Scenario:** The external body `zk_query_verify` (lines 71‑84) can return `Err(_)` for three distinct reasons: encode failure, gRPC transport failure, or decode failure. The spec’s post‑condition for `Err(Error::ZkdcapVerificationFailed)` (lines 94‑103) only requires that `vkey` be set, ignoring which concrete failure occurred.  
**Why it succeeds:**  
- The `ensures` clause (line 96) states `&&& raw.zkdcap_vkey != 0` without distinguishing the three error sources.  
- Production propagates the same `Error::ZkdcapVerificationFailed` for all three cases, but downstream reasoning (e.g., retry policies) may need to know whether the failure was transient (network) or permanent (bad proof). The spec cannot express this, limiting its usefulness.  
**Suggested defense:** Refine the error type to distinguish `EncodeFailed`, `GrpcFailed`, and `DecodeFailed`, and adjust the `ensures` clause to reflect the specific cause.

---  

### 7. session_create.rs – `Api::addr_validate` stub always succeeds  
**Category:** Under‑specification  
**Severity:** critical  
**Scenario:** Submit a transaction with `msg.contract = "invalid_bech32"`; `api.addr_validate` in production returns `Err(Error::Std)`, causing the handler to abort with `Error::Std`. The prototype’s stub (lines 31‑44) always returns `Ok(s)`.  
**Why it succeeds:**  
- The external body definition (line 33) guarantees `Ok(a) ⇒ a == s && a == b` where `b` is the oracle result, but the oracle is unconstrained; the implementation simply returns `Ok(s)`.  
- Consequently the proof never considers the `Err` branch, yet the verified theorem (line 69) includes an `Err(_)` case that is unreachable in the model.  
Thus the spec does not constrain the handler’s behavior on malformed addresses.  
**Suggested defense:** Make `addr_validate` an `#[verifier::external_body]` that nondeterministically returns `Ok(address)` or `Err(Error::Std)`, and add a post‑condition linking the `Ok` result to the oracle.

---  

### 8. session_create.rs – `Item::save` body‑verified stub hides serialization errors  
**Category:** Coverage gap  
**Severity:** serious  
**Scenario:** The blockchain node runs out of storage quota, causing `SESSION.save` to return `Err(Error::Std)`. Production propagates this error, leaving `SESSION` unchanged. The prototype’s `Item::save` (lines 53‑66) writes `storage.session = Some(...)` and always returns `Ok(())`.  
**Why it succeeds:**  
- The stub’s post‑condition (line 58) mentions an `Err` case, but the body never produces it, so the proof cannot reason about the error path.  
- The verified property (line 71) that “`Err(_) ⇒ storage unchanged`” is vacuously true because `Err` never occurs.  
**Suggested defense:** Replace the body‑verified implementation with an `#[verifier::external_body]` that may return `Err(Error::Std)` and specify the unchanged‑storage condition.

---  

### 9. session_set_pub_key.rs – `Item::may_load` stub never fails  
**Category:** Coverage gap  
**Severity:** serious  
**Scenario:** Deserialization of a stored `Session` fails (corrupted data), causing `SESSION.may_load` to return `Err(Error::Std)` in production. The prototype’s `may_load` (lines 38‑53) always returns `Ok(storage.session.clone())`.  
**Why it succeeds:**  
- The `ensures` clause (line 41) allows any `Err(_)` but the body never produces it, making the error path unreachable in the proof.  
- Consequently the wrapper’s post‑condition (line 71) that “`Err(_) ⇒ storage unchanged`” cannot be exercised.  
**Suggested defense:** Model `may_load` as an `#[verifier::external_body]` that may nondeterministically return `Err(Error::Std)` and keep the unchanged‑storage invariant.

---  

### 10. session_set_pub_key.rs – `Item::save` stub always succeeds  
**Category:** Coverage gap  
**Severity:** serious  
**Scenario:** The underlying storage layer rejects the write (e.g., quota exceeded), returning `Err(Error::Std)`. Production propagates the error, leaving `SESSION` unchanged. The prototype’s `save` (lines 55‑66) always writes and returns `Ok(())`.  
**Why it succeeds:**  
- Same reasoning as attack 8: the `Err` branch is unreachable, so the verified theorem (line 71) cannot guarantee correct behavior when `save` fails.  
**Suggested defense:** Use an `#[verifier::external_body]` version of `save` that may return `Err(Error::Std)` and enforce the unchanged‑storage post‑condition.

---  

### 11. encryption.rs – ECIES round‑trip axiom assumes encryption never fails  
**Category:** Impossibility‑hypothesis vacuity  
**Severity:** critical  
**Scenario:** Pass an invalid `VerifyingKey` (e.g., point not on curve) to `encrypt`; production’s `ecies::encrypt` returns `Err(CryptoError::Ecies)`. The prototype’s `ecies_roundtrip_axiom` (lines 106‑119) asserts `ecies_encrypt_spec(... ) is Ok` for *any* `sk` and `pt`.  
**Why it succeeds:**  
- The axiom’s hypothesis is unsatisfiable in the concrete cryptographic world (invalid keys cause `Err`), making the theorem vacuously true. The verified property “`encrypt` always succeeds” does not hold in production.  
**Suggested defense:** Replace the axiom with a weaker one that only guarantees success for keys that satisfy a predicate `valid_key(sk)`, and add a precondition to `encrypt` that the key is valid.

---  

### 12. encryption.rs – Serde round‑trip axiom assumes serialization never fails  
**Category:** Impossibility‑hypothesis vacuity  
**Severity:** serious  
**Scenario:** Serialize a `Message` containing a `u64` that exceeds JSON number limits (hypothetical) or a custom type that `serde_json` cannot handle, causing `serde_json::to_vec` to return `Err`. Production would propagate `CryptoError::Serde`. The prototype’s `serde_roundtrip_axiom` (lines 121‑134) asserts `serde_to_vec_spec(v) is Ok` for any `Message`.  
**Why it succeeds:**  
- The axiom’s antecedent is false for unsupported payloads, so the theorem is vacuous and does not constrain the real implementation.  
**Suggested defense:** Strengthen the axiom to require `serde_to_vec_spec(v) is Ok` only when `v` satisfies a predicate `serde_supported(v)`; expose this predicate in the `encrypt_json`/`decrypt_json` specifications.

---  

### 13. encryption.rs – External‑body wrappers lack explicit error‑case contracts  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** `ecies_encrypt` (lines 71‑84) returns `Err(CryptoError::Ecies)`. The external body definition provides no `ensures` clause linking the error to any spec predicate. Consequently the proof cannot reason about when `encrypt` may fail.  
**Why it succeeds:**  
- The stub is declared `#[verifier::external_body]` without an `ensures` clause, so Verus treats the result as an uninterpreted value constrained only by the surrounding proof. This hides the possibility of failure from the verified theorems.  
**Suggested defense:** Add an `ensures` clause to each external body that explicitly relates `Err(e)` to a predicate (e.g., `!valid_key(pk)` for encryption, `!serde_supported(v)` for serialization).

---  

### 14. key_manager.rs – Signing‑key round‑trip axiom assumes perfect decode  
**Category:** Impossibility‑hypothesis vacuity  
**Severity:** serious  
**Scenario:** Corrupt the byte vector returned by `signing_key_to_bytes` (e.g., truncate it). Production’s `SigningKey::from_slice` returns `Err(KmError::BadScalar)`. The prototype’s `signing_key_bytes_roundtrip_axiom` (lines 84‑106) assumes *any* `bytes` produced from `to_bytes` can be decoded back to a key with the same public key.  
**Why it succeeds:**  
- The axiom’s hypothesis is false for malformed byte strings, making the theorem vacuously true and providing no guarantee that `import_sk` will succeed.  
**Suggested defense:** Strengthen the axiom to require that `bytes` be exactly the output of `signing_key_to_bytes(sk)` and that `signing_key_from_slice` succeeds, or model the failure case explicitly.

---  

### 15. key_manager.rs – `verifying_key_exec` external body lacks post‑condition  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** `verifying_key_exec` (lines 61‑70) is declared `#[verifier::external_body]` with no `ensures`. Production’s `VerifyingKey::from(&SigningKey)` is deterministic, but the spec does not capture this, allowing a model where the same `SigningKey` could map to different `VerifyingKey`s in different calls.  
**Why it succeeds:**  
- Without an `ensures` clause, Verus cannot enforce functional consistency; the later theorem `pub_key_matches_sk` (lines 112‑124) relies on the post‑condition of `pub_key`, but that post‑condition only mentions `verifying_key_spec(km.sk)`, which is uninterpreted. Hence the proof does not guarantee that `pub_key` truly reflects the current private key.  
**Suggested defense:** Add an `ensures` clause to `verifying_key_exec` stating `r == verifying_key_spec(*sk)` (already present) **and** that the function is pure (i.e., same input yields same output), or model it as a pure function in the spec.

---  

### 16. key_manager.rs – Import function’s error case is unmodeled  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** Call `import_sk` with a byte vector of incorrect length (e.g., 10 bytes). Production’s `SigningKey::from_slice` returns `Err(KmError::BadScalar)`. The prototype’s `import_sk` (lines 94‑103) simply forwards the external body result without any `ensures` linking the error to the malformed input.  
**Why it succeeds:**  
- The external body `signing_key_from_slice` (lines 73‑78) has no contract, so the spec cannot reason about when `import_sk` fails, nor can it guarantee that a successful import yields a key matching the original.  
**Suggested defense:** Provide an `ensures` clause for `signing_key_from_slice` that relates `Err(_)` to a predicate `!valid_bytes(bytes)` and `Ok(sk)` to `bytes == signing_key_to_bytes(sk)`.

---  

### 17. attested.rs – `ConcreteAtt.handle` always returns `Ok` hides potential `Error::Std` from inner attestation logic  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** Replace `ConcreteAtt` with a real attestation that performs a gRPC query (e.g., `DstackZkAttestation`). That query may fail, returning `Err(Error::ZkdcapVerificationFailed)`. The prototype’s `ConcreteAtt.handle` (line 48) is a total `Ok`.  
**Why it succeeds:**  
- The wrapper `attested_handle` (lines 106‑138) assumes the inner call cannot fail, so the theorem “`Ok ⇒ user_data match …`” does not account for inner failures. In production, a failed inner attestation would cause the wrapper to return an error, violating the spec’s guarantee that a successful wrapper implies successful inner calls.  
**Suggested defense:** Model `ConcreteAtt.handle` as an `#[verifier::external_body]` that may return `Err(Error::ZkdcapVerificationFailed)` and adjust the wrapper’s post‑condition to propagate any such error.

---  

### 18. session_set_pub_key.rs – No modeling of concurrent re‑entry race conditions  
**Category:** Composition failure  
**Severity:** advisory  
**Scenario:** Two transactions concurrently invoke `session_set_pub_key` with the same `nonce` but different `pub_key`s. Production’s storage may interleave reads/writes, causing one transaction to succeed and the other to see the updated session, leading to `BadSessionTransition`. The prototype’s sequential `handle` (lines 71‑92) assumes atomicity and does not model concurrency.  
**Why it succeeds:**  
- The spec treats `SESSION.may_load` and `SESSION.save` as atomic operations with a single mutable `Storage` reference, ignoring possible interleavings. Hence the verified property “`Ok ⇒ session was None and nonce matched`” does not hold under concurrent execution.  
**Suggested defense:** Introduce a ghost lock or a sequential consistency model for `Storage` and prove that concurrent invocations preserve the invariant, or explicitly state that the handler is not re‑entrant.

---  

### 19. session_create.rs – Missing validation of `msg.contract` format  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** Submit a `SessionCreate` with `msg.contract = 0` (invalid address). Production’s `api.addr_validate` rejects it, returning `Err(Error::Std)`. The prototype’s `addr_validate` (lines 31‑44) never fails, so the proof never considers this branch.  
**Why it succeeds:**  
- The stub’s `ensures` clause (line 33) allows an `Err`, but the implementation always returns `Ok`. Consequently the verified theorem cannot guarantee that an invalid address leads to an error.  
**Suggested defense:** Make `addr_validate` an `#[verifier::external_body]` that may return `Err(Error::Std)` for malformed inputs, and add a precondition on `msg.contract` reflecting the address format.

---  

### 20. encryption.rs – `encrypt_json`/`decrypt_json` do not enforce matching key‑pair usage  
**Category:** Under‑specification  
**Severity:** serious  
**Scenario:** Call `encrypt_json` with a public key derived from `sk1`, then call `decrypt_json` with a different private key `sk2`. Production’s ECIES decryption will fail, returning `Err(CryptoError::Ecies)`. The spec’s `encrypt_json` (lines 139‑162) and `decrypt_json` (lines 164‑186) only assert existence of some `bytes` satisfying the round‑trip axioms, without tying the same key pair across the two calls.  
**Why it succeeds:**  
- The post‑conditions use existential quantifiers (`exists |bytes| …`) that allow the verifier to pick different `bytes` for each call, effectively decoupling the key pair. Hence the theorem “`decrypt_json` recovers the original `Message`” holds vacuously even when the wrong key is used.  
**Suggested defense:** Strengthen the specifications to require that the `bytes` used in `decrypt_json` are exactly the ciphertext produced by the preceding `encrypt_json` call with the *same* public key, and that the private key corresponds to that public key via `verifying_key_spec`.

---  

## META  

- **Categories attacked:** Under‑specification, Coverage gap, Over‑specification, Over‑specification (disjunction‑vs‑decomposition collapse), Impossibility‑hypothesis vacuity, Composition failure, Temporal‑state mismatch (implicit in missing error propagation).  
- **Categories with no evidence:** Triviality (the specs are non‑trivial), Ambiguity (no ambiguous syntax found).  
- **Artifacts desired but not provided:** Full production test suites exercising storage failures, address validation failures, and ECIES error paths; concrete `prost` encode/decode failure cases; concurrency stress tests for session handlers.  
- **Confidence in verdict:** high – the identified mismatches are concrete, line‑referenced, and directly break the correspondence between verified properties and production behavior.