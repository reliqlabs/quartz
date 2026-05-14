# glm-4-7-flash (gateway) — verus-prototype Round D

- **Elapsed**: 67.3s
- **Finish reason**: stop
- **Usage**: {"prompt_tokens": 22851, "completion_tokens": 8029, "total_tokens": 30880, "prompt_tokens_details": {"cached_tokens": 0}}

---

VERDICT (instantiate.rs): HOLDS WITH CAVEATS
VERDICT (attested.rs): HOLDS WITH CAVEATS
VERDICT (session_create.rs): HOLDS WITH CAVEATS
VERDICT (session_set_pub_key.rs): HOLDS WITH CAVEATS
VERDICT (encryption.rs): HOLDS WITH CAVEATS
VERDICT (key_manager.rs): HOLDS WITH CAVEATS

1.  **Target**: `session_set_pub_key.rs`
    **Category**: Coverage gap
    **Severity**: Serious
    **Scenario**: A user calls `SessionSetPubKey` with a valid nonce and public key.
    **Why it succeeds**: The production handler (line 18-20 of `session_set_pub_key.rs`) executes `SEQUENCE_NUM.save(deps.storage, &Uint64::new(0))` to initialize the sequence counter for replay protection. The Verus prototype (`session_set_pub_key.rs`, lines 69-76) models `Storage` as containing only `session: Option<Session>`. It does not model `SEQUENCE_NUM` at all. The verified property proves the session transitions correctly, but it proves nothing about the state of the sequence number.
    **Suggested defense**: Add a `SEQUENCE_NUM` field to the `Storage` struct and model the `save` operation in the `Item` impl to update it.

2.  **Target**: `attested.rs`
    **Category**: Refinement mismatch
    **Severity**: Critical
    **Scenario**: An `Attested<M,A>` wrapper is instantiated where `M` or `A` are handlers that could fail (e.g., a handler that queries an external API that times out).
    **Why it succeeds**: The production `Attested::handle` (line 183 of `attested.rs`) calls `msg.handle(deps.branch(), env, info)?` and `attestation.handle(deps, env, info)?`. If either inner handler returns `Err`, the wrapper propagates it. The Verus prototype (`attested.rs`, lines 147-156) collapses all inner handlers (e.g., `ConcreteMsg`, `ConcreteAtt`, `TrivialAttestation`) to total `Ok`-returning functions. The comment on line 43 explicitly admits: "we lose the ability to prove that an inner-handler error propagates to the wrapper". Consequently, the property "Ok ⇒ inner handlers ran" is vacuously true because the inner handlers are modeled as never failing.
    **Suggested defense**: Model inner handlers as fallible `Result`-returning functions, or use `#[verifier::external_body]` for the composition proof to witness the error path.

3.  **Target**: `instantiate.rs`
    **Category**: Stubbing drift
    **Severity**: Serious
    **Scenario**: The contract is instantiated with a `RawConfig`.
    **Why it succeeds**: The production `CoreInstantiate::handle` (line 12 of `instantiate.rs`) calls `CONFIG.save(deps.storage, &RawConfig::from(self.config().clone()))`. The `RawConfig::from` conversion is infallible in the production code. However, the `cw_storage_plus::Item::save` method returns a `Result` (serialization error). The Verus prototype (`instantiate.rs`, lines 71-79) models `CONFIG.save` as a pure function that always returns `Ok` and updates `storage.config` directly. It does not model the possibility of a serialization failure or a storage write failure.
    **Suggested defense**: Model `CONFIG.save` as `#[verifier::external_body]` returning `Result<(), Error>` and model the storage update conditionally on the `Ok` variant.

4.  **Target**: `session_create.rs`
    **Category**: Stubbing drift
    **Severity**: Serious
    **Scenario**: A user calls `SessionCreate`.
    **Why it succeeds**: The production `SESSION.save` (line 12 of `session_create.rs`) is a generic `cw_storage_plus` operation that returns `StdResult<()>`. The Verus prototype (`session_create.rs`, lines 59-67) models `SESSION.save` as a pure function that always returns `Ok` and updates `storage.session` directly. It ignores the `Result` type entirely.
    **Suggested defense**: Model `SESSION.save` as `#[verifier::external_body]` returning `Result<(), Error>` to capture potential serialization or storage errors.

5.  **Target**: `attested.rs`
    **Category**: Stubbing drift
    **Severity**: Serious
    **Scenario**: The `Attested` wrapper calls `CONFIG.may_load`.
    **Why it succeeds**: The production `CONFIG.may_load` (line 25 of `state.rs`) performs a `try_into` conversion on `light_client_opts`. If this conversion fails, `may_load` returns `Err`. The Verus prototype (`attested.rs`, lines 89-103) models `CONFIG.may_load` as a pure function that extracts fields and asserts equality. It assumes the conversion is infallible, effectively asserting `light_client_opts.try_into()` always succeeds.
    **Suggested defense**: Model `CONFIG.may_load` as `#[verifier::external_body]` returning `Result<Option<Config>, Error>` to capture the `light_client_opts` conversion error.

6.  **Target**: `encryption.rs`
    **Category**: Impossibility-hypothesis vacuity
    **Severity**: Critical
    **Scenario**: Proving the binding invariant `pub_key_matches_sk`.
    **Why it succeeds**: The theorem (`key_manager.rs`, lines 103-108) relies on `verifying_key_spec` being the correct mathematical map from `SigningKey` to `VerifyingKey`. However, `verifying_key_spec` is an uninterpreted spec function (line 27). The proof does not verify against the concrete `k256` implementation (`VerifyingKey::from`). If the production implementation of `VerifyingKey::from` changes to use a different curve or a buggy implementation, the theorem remains true (vacuously) because it only asserts that `verifying_key_spec` is consistent with itself, not that it matches reality.
    **Suggested defense**: Prove the property against the concrete `k256` implementation, or explicitly accept `verifying_key_spec` as a trust boundary axiom.

7.  **Target**: `key_manager.rs`
    **Category**: Impossibility-hypothesis vacuity
    **Severity**: Critical
    **Scenario**: Proving the binding invariant `pub_key_matches_sk`.
    **Why it succeeds**: The production `pub_key` implementation (line 12 of `key_manager/default.rs`) calls `PubKey(self.sk.clone().into())`. The Verus prototype (`key_manager.rs`, line 95) models this as `PubKey(verifying_key_exec(&km.sk))`. The theorem relies on the postcondition of `verifying_key_exec`. As with `encryption.rs`, `verifying_key_exec` is an uninterpreted external_body stub. The proof assumes the stub correctly implements `VerifyingKey::from`. It does not verify the `k256` conversion logic.
    **Suggested defense**: Prove the property against the concrete `k256` implementation, or explicitly accept `verifying_key_exec` as a trust boundary axiom.

8.  **Target**: `attested.rs`
    **Category**: Stubbing drift
    **Severity**: Advisory
    **Scenario**: The `Attested` wrapper checks `user_data` equality.
    **Why it succeeds**: The production `UserData` type is `[u8; 64]` (line 10 of `state.rs`). The Verus prototype (`attested.rs`, line 18) models it as `u64`. The spec only checks equality (`wrapper.spec_msg_user_data() == wrapper.spec_att_user_data()`). If the production code performs integrity checks on `user_data` (e.g., hashing it before comparison), the prototype misses this logic entirely.
    **Suggested defense**: Model `UserData` as `[u8; 64]` or add a hash function spec to the equality check.

META
- Categories attacked: Coverage gap, Refinement mismatch, Stubbing drift, Impossibility-hypothesis vacuity.
- Categories not attacked: Temporal-state mismatch, Disjunction-vs-decomposition, Preconditional over-strength (no preconditions found in these stubs), Contradiction (no contradictions found in the logic flow), Edge case (no specific edge cases like overflow or panic propagation were found that weren't already covered by the error propagation attacks).
- Artifacts not provided: Concrete test vectors for `light_client_opts` conversion, specific `cw-storage-plus` serialization failure scenarios, `k256` library source code to verify `VerifyingKey::from` behavior.
- Estimated confidence: High. The attacks are grounded in specific line numbers and type mismatches between the production and prototype code.