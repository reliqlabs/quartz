# qwen3.6-27b-mlx (local) — verus-prototype Round D

- **Elapsed**: 1332.3s
- **Finish reason**: stop
- **Usage**: {"prompt_tokens": 24747, "completion_tokens": 8205, "total_tokens": 32952, "completion_tokens_details": {"reasoning_tokens": 6066}}

---



VERDICT (instantiate.rs): BREAKS
VERDICT (attested.rs): WEAKENS
VERDICT (session_create.rs): HOLDS WITH CAVEATS
VERDICT (session_set_pub_key.rs): BREAKS
VERDICT (encryption.rs): WEAKENS
VERDICT (key_manager.rs): BREAKS

1. **Target**: `instantiate.rs` (Verus) vs Production `handler/instantiate.rs`
**Category**: Coverage gap / Refinement mismatch
**Severity**: critical
**Scenario**: Production `Instantiate<A>::handle` (line 14) delegates to `self.0.handle(deps, env, info)`, which invokes the `Attested<CoreInstantiate, A>` wrapper. That wrapper performs a `user_data` equality check and a conditional `CONFIG.may_load` mr_enclave verification before delegating to `CoreInstantiate`. The Verus prototype completely strips the `Attested` wrapper, checking only a direct `msg_mr_enclave == att_mr_enclave` equality and calling `core_instantiate_handle` directly.
**Why it succeeds**: The spec proves a handler that bypasses two critical integrity checks (`user_data` match and storage-backed `CONFIG` load) present in production. An adversary can craft a message where `msg.config().mr_enclave() == attestation.mr_enclave()` but `user_data` mismatches or `CONFIG` is absent/corrupted; production rejects it, but the verified spec admits it as valid. The prototype's comment (line 43) explicitly admits monomorphising away the wrapper, but fails to note that this drops mandatory security checks.
**Suggested defense**: Model the `Attested` wrapper's control flow explicitly in `instantiate_handle`, or prove a refinement lemma showing that the stripped-down check implies the full wrapper's checks under all valid instantiation preconditions.

2. **Target**: `session_set_pub_key.rs` (Verus) vs Production `handler/execute/session_set_pub_key.rs`
**Category**: Coverage gap
**Severity**: critical
**Scenario**: Production handler (lines 18-20) initializes `SEQUENCE_NUM` to `Uint64::new(0)` and saves it to storage immediately after setting the public key. The Verus prototype's `handle` function loads, updates, and saves `SESSION`, but contains zero references to `SEQUENCE_NUM`.
**Why it succeeds**: Subsequent handlers in the contract rely on `SEQUENCE_NUM` for replay protection and message ordering. By omitting this storage write, the spec proves a state transition that leaves the contract in an uninitialized sequence state. Production will reject subsequent operations expecting a valid sequence number, but the verified model assumes none exists or tracks it. This breaks compositional correctness for any downstream handler that reads `SEQUENCE_NUM`.
**Suggested defense**: Add a `SEQUENCE_NUM` storage slot to the Verus model and assert its initialization to `0` in the `Ok` postcondition of `handle`.

3. **Target**: `key_manager.rs` (Verus)
**Category**: Triviality / Contradiction
**Severity**: critical
**Scenario**: The `signing_key_bytes_roundtrip_axiom` (line 78) is declared with `requires true,`. It asserts that for *any* `SigningKey`, *any* byte sequence `bytes`, and *any* decoded key, `verifying_key_spec(decoded) == verifying_key_spec(sk)`.
**Why it succeeds**: This is mathematically false. The axiom claims a universal property that does not hold for arbitrary inputs, making the theorem vacuously assert a broken invariant. The comment admits this is a placeholder ("here we accept them as hypotheses..."), but `requires true` forces Verus to treat it as an unconditional truth. The proof passes not because the key manager is correct, but because the spec asserts a false universal equality to satisfy the type checker.
**Suggested defense**: Replace `requires true` with explicit preconditions tying `bytes` to `signing_key_to_bytes_spec(sk)` and `decoded` to `signing_key_from_slice_spec(bytes)`, or move the linkage into a proper spec function rather than a vacuous axiom.

4. **Target**: `attested.rs` (Verus)
**Category**: Triviality
**Severity**: serious
**Scenario**: The `zk_query_verify` function (lines 138-145) is marked `#[verifier::external_body]` and asserts `Ok(true) => zk_query_verify_succeeded(...)`. The predicate `zk_query_verify_succeeded` is declared as an uninterpreted spec function.
**Why it succeeds**: This creates a tautological trust boundary. The postcondition merely defines the uninterpreted function to be true whenever `Ok(true)` is returned. It proves nothing about the actual gRPC call, protobuf encoding/decoding, or cryptographic verification performed by production. The spec claims to verify "gRPC query reported verified=true", but it actually proves a label assignment. An adversary can replace the production gRPC client with a stub that always returns `Ok(true)`, and the verified property still holds.
**Suggested defense**: Either axiomatize the concrete cryptographic verification primitive (e.g., Groth16 soundness) or explicitly mark this as a "trusted oracle" with a documented security assumption, rather than presenting it as a verified property.

5. **Target**: `attested.rs` (Verus) vs Production `handler/execute/attested.rs`
**Category**: Composition failure
**Severity**: serious
**Scenario**: Production `Attested::handle` (line 186) calls `msg.handle(deps.branch(), env, info)?`. The `deps.branch()` call creates a sub-transaction view in CosmWasm, ensuring that if the message handler succeeds but the attestation handler fails (or vice versa), storage mutations are handled according to CosmWasm's atomic rollback semantics. The Verus prototype passes a single mutable `storage: &mut Storage` reference to both handlers and explicitly admits (line 43) "we lose the ability to prove that an inner-handler error propagates".
**Why it succeeds**: The spec ignores transactional atomicity. In production, a failure in either inner handler triggers a full rollback of storage changes for the entire transaction. The Verus model allows partial state mutation on error paths because it lacks rollback semantics and treats `storage` as a simple mutable reference. This breaks the guarantee that failed attestations leave storage completely unchanged, which is critical for state consistency and retry logic.
**Suggested defense**: Model `deps.branch()` using a ghost transaction log or explicit rollback mechanism, and prove that any `Err` return restores `storage` to its pre-call state.

6. **Target**: `encryption.rs` (Verus) vs Production `enclave/core/encryption.rs`
**Category**: Stubbing drift
**Severity**: serious
**Scenario**: Production `encrypt` (line 15) calls `ecies::encrypt(&pubkey.to_sec1_bytes(), plaintext)`. The `.to_sec1_bytes()` call serializes the `VerifyingKey` into a specific byte format (compressed/uncompressed SEC1). The Verus prototype passes the abstract `VerifyingKey` struct directly to `ecies_encrypt`, completely omitting the serialization step.
**Why it succeeds**: If `to_sec1_bytes()` fails, panics, or produces a format mismatch (e.g., production expects compressed but receives uncompressed), the underlying `ecies` crate will reject decryption or produce garbage. The Verus spec passes because it abstracts away the serialization boundary entirely. This hides a real failure path where cryptographic roundtrips break due to encoding mismatches, not algorithmic flaws.
**Suggested defense**: Model `to_sec1_bytes` as a spec function or external body with a roundtrip axiom, and ensure `ecies_encrypt_spec` operates on the serialized byte representation rather than the abstract key handle.

7. **Target**: `session_create.rs` (Verus)
**Category**: Stubbing drift / Ambiguity
**Severity**: serious
**Scenario**: The `addr_validate` stub (lines 63-70) asserts `(Ok(a), Ok(b)) => a == s && a == b`, forcing the validated address to be identical to the input string. Production relies on `cosmwasm_std::Api::addr_validate`, which canonicalizes addresses (e.g., normalizing bech32 prefixes, case folding) and may reject syntactically valid but semantically invalid strings.
**Why it succeeds**: The spec assumes a pure identity validation function. In production, `addr_validate` can transform the input or reject it based on chain-specific rules. If a caller passes a non-canonical but valid address, production accepts and canonicalizes it, but the Verus model's `a == s` constraint would classify this as a spec violation or fail to match the canonicalized form against `env.contract.address`. This creates a divergence between verified control flow and actual chain behavior.
**Suggested defense**: Replace the identity constraint with a canonicalization spec function `addr_canonicalize(s)` and assert `a == addr_canonicalize(s)`, allowing the model to account for address normalization.

META
- Categories attacked: Coverage gap, Refinement mismatch, Triviality, Composition failure, Stubbing drift, Ambiguity.
- Categories not attacked: Edge case (no boundary inputs like overflow/empty collections are central to these handlers), Temporal-state mismatch (state modeling is largely synchronous and matches intent shape, though rollback semantics are missing), Disjunction-vs-decomposition collapse (not applicable to these control-flow specs).
- Artifacts wanted: Production `cw-storage-plus` serialization bounds, CosmWasm `DepsMut::branch()` rollback guarantees documentation, concrete `zkdcap_vkey` format constraints.
- Estimated confidence in verdict: high. The attacks are grounded in direct line-by-line comparisons between production control flow/error handling and the Verus stubs/axioms. Multiple critical gaps (missing wrapper checks, missing sequence init, vacuous axioms) fundamentally break the trust claim that these prototypes constrain production behavior.