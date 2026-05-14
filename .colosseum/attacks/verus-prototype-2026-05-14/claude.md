# Round D — Verus Prototype Adversarial Review (Claude)

- **Target files** (6, 1431 LOC):
  - `crates/contracts/core/verus-prototype/instantiate.rs` (264)
  - `crates/contracts/core/verus-prototype/attested.rs` (388)
  - `crates/contracts/core/verus-prototype/session_create.rs` (247)
  - `crates/contracts/core/verus-prototype/session_set_pub_key.rs` (118)
  - `crates/enclave/core/verus-prototype/encryption.rs` (228)
  - `crates/enclave/core/verus-prototype/key_manager.rs` (186)
- **Intent doc:** Verus-prototype STATUS.md ("standalone — not integrated into production build"; `cw_storage_plus + cosmwasm-std stubbed via external_body`)
- **Date:** 2026-05-14
- **Round:** D
- **Adversary:** Claude Opus 4.7 (1M context)

## Per-file verdicts

- VERDICT (instantiate.rs): **WEAKENS** — `RawConfig::from(Config)` conversion (production `light_client_opts` and `HexBinary`) is collapsed to a one-field record; the spec proves a tautology over an empty TryFrom.
- VERDICT (attested.rs): **BREAKS** — the wrapper's monomorphisation removes the only interesting failure mode (inner-handler error propagation) and discharges the dropped property with a vacuous `external_body` escape hatch; the ZK handler's spec lets a verified-true response satisfy the contract regardless of whether the proof's public inputs match the wrapper's `compose_hash`/`user_data` — a real exploit path.
- VERDICT (session_create.rs): **WEAKENS** — addr_validate stubbed as identity drops the canonicalisation step where bech32 normalises a host-supplied address into the chain's canonical form, and the Storage save model gives `cw_storage_plus::Item<T>::save` a contract it cannot keep.
- VERDICT (session_set_pub_key.rs): **BREAKS** — does not model `SEQUENCE_NUM.save(..., Uint64::new(0))`; on the production Ok branch, the SEQUENCE_NUM is force-reset to 0 (a replay-protection wipe), and the Verus prototype's Ok postcondition does not mention it at all.
- VERDICT (encryption.rs): **HOLDS WITH CAVEATS** — the roundtrip axiom is a literal restatement of the proof obligation, with no constraint on confidentiality or ciphertext non-malleability; the `Message` monomorphisation loses everything serde_json can do wrong (untagged enums, `flatten`, `#[serde(skip)]`).
- VERDICT (key_manager.rs): **BREAKS** — the binding invariant is proved over a frozen `DefaultKeyManager` value, not over mutation; the production `Import::import` does `self.sk = SigningKey::from_slice(&data)?`, after which the previously-published `PubKey` no longer corresponds to `km.sk`. The "stored sk matches published pk" property does not survive an import. The Dstack variant (production code path) is not modelled at all.

---

## 1. [attested.rs] DstackZk handler does not bind `zkdcap_public_inputs` to wrapper's `compose_hash` / `user_data`

- **Target:** `attested.rs:281-359` (Verus); `crates/contracts/core/src/handler/execute/attested.rs:80-124` (production)
- **Category:** stubbing drift / missing security property
- **Severity:** **critical**
- **Scenario:** An attacker submits `Attested<M, DstackZkAttestation>` where:
  - `attestation.user_data = expected_user_data` (matches msg.user_data — passes wrapper line 252 check),
  - `attestation.compose_hash = config.mr_enclave` (passes wrapper lines 256–264 check),
  - but `zkdcap_proof` / `zkdcap_public_inputs` are a *valid* Groth16 proof for a *different* enclave instance — one whose actual report_data and compose_hash differ from the wrapper's claimed values. The ZK module's `ProofVerifyGnark` only verifies the proof against the supplied public inputs; it has no knowledge that the wrapper claimed `compose_hash = X` while the proof's public inputs encode `compose_hash = Y`.
- **Why it succeeds:** The Verus spec at line 314 is `Ok(true) => zk_query_verify_succeeded(proof, public_inputs, vkey_name)`. The spec contract terminates at "the verifier said yes on these inputs." There is **no spec clause** linking `public_inputs` back to either `wrapper.spec_att_user_data()` or the loaded `RawConfig.mr_enclave`. The production handler at `attested.rs:94-99` constructs the protobuf request using `self.zkdcap_proof` and `self.zkdcap_public_inputs` verbatim — there is no on-chain equality check that `public_inputs == sha256(report_data || compose_hash || tcb_status)` or any sub-extraction confirming the proof attests to the claimed `compose_hash`. The wrapper's `compose_hash` check (line 184 of production) compares `config.mr_enclave()` to `attestation.mr_enclave() = self.compose_hash` — a *self-declared* field on the attestation, not one extracted from the proof. This is the central security property of the entire zkdcap pipeline ("the proof attests to *this* enclave") and **the Verus spec does not encode it**.
- **Suggested defense:** Add a spec-level uninterpreted predicate `proof_journal_binds(proof, public_inputs, expected_compose_hash, expected_user_data)` and require it on the Ok branch. The production handler must extract or verify-equal these fields against the zkdcap journal/public inputs before accepting the proof. The prototype's omission models the production omission.

## 2. [attested.rs] Attested<M,A> wrapper monomorphisation discards inner-handler error propagation

- **Target:** `attested.rs:34-46, 165-191, 266-279` (Verus); `crates/contracts/core/src/handler/execute/attested.rs:167-196` (production)
- **Category:** stubbing drift / spec collapse
- **Severity:** **serious**
- **Scenario:** The Verus prototype monomorphises `M = ConcreteMsg`, `A = ConcreteAtt`, each with a `handle` whose postcondition is literally `ensures r is Ok` (lines 173-176, 188-191). The production `Attested<M,A>::handle` calls `Handler::handle(msg, deps.branch(), env, info)?` (line 189 of production) and `Handler::handle(attestation, deps, env, info)?` (line 190). Both `?` operators are real failure exits — when `M = CoreInstantiate`, `msg.handle` calls `CONFIG.save(deps.storage, &RawConfig::from(self.config().clone())).map_err(Error::Std)?`. A production storage save failure during the inner call returns `Err(Error::Std)` from the wrapper, *after* both equality checks have succeeded but with `deps.branch()` semantics (a re-entrant DepsMut) leaving the outer caller's storage in a partially-committed state.
- **Why it succeeds:** The Verus prototype's Ok-branch postcondition at line 238 collapses to a tautology because `ConcreteMsg::handle` and `ConcreteAtt::handle` are total `Ok`. The prototype's comment at line 43 admits "we lose the ability to prove that an inner-handler error propagates to the wrapper. We compensate by adding an `external_body` fallible variant `concrete_att_handle_maybe_err` for one of the proofs" — and yet **there is no `concrete_att_handle_maybe_err` in the file**. The advertised compensation does not exist. The author left the comment but not the code.
- **Suggested defense:** Either (a) re-add the `external_body` fallible variant and add an explicit `Err(_) => true ⇒ inner_failed` clause to the wrapper spec, or (b) accept that the prototype is silent on the most common production failure mode and label the spec accordingly. The current docstring is misleading.

## 3. [attested.rs] `deps.branch()` semantics not modelled — two-handler storage interleaving lost

- **Target:** `attested.rs:266-278` (Verus); `crates/contracts/core/src/handler/execute/attested.rs:189-190` (production)
- **Category:** stubbing drift / cosmwasm-std stub mismatch
- **Severity:** **serious**
- **Scenario:** Production sequences `Handler::handle(msg, deps.branch(), env, info)?` followed by `Handler::handle(attestation, deps, env, info)?` — both handlers share the *same underlying* `DepsMut<'_>`. If `msg.handle` writes to storage (e.g. `CoreInstantiate` saves CONFIG) and `attestation.handle` reads that storage (e.g. a future `DstackZkAttestation` variant that reads CONFIG to fetch `zkdcap_vkey`), the second handler observes the partial state from the first. The Verus model passes `&mut Storage` through two no-op handlers; there is no notion of an inner write being visible to an inner read.
- **Why it succeeds:** Verus's `&mut Storage` parameter is a single linear reference; the prototype's call pattern `wrapper.msg.handle(storage); wrapper.attestation.handle(storage);` happens to be sequential and would observe partial state if the inner handlers wrote, but the spec never witnesses this because both inner handlers are stubbed total-Ok. Production's `deps.branch()` actually returns a fresh `DepsMut` that *shares* the storage pointer — so the prototype's serial-sharing model is structurally right but vacuous, and the spec doesn't preclude a future inner-handler that violates branch-isolation expectations.
- **Suggested defense:** Add a ghost-state spec clause to the wrapper: `Ok ⇒ ∃ intermediate. msg.handle(old) → intermediate ∧ attestation.handle(intermediate) → final`. Spell out the sharing semantics.

## 4. [attested.rs] `CONFIG.may_load` Err branch swallowed under `e is Std`

- **Target:** `attested.rs:116-136, 256-264` (Verus); `crates/contracts/core/src/handler/execute/attested.rs:183` (production)
- **Category:** Option/Result discipline, error-mapping drift
- **Severity:** **advisory**
- **Scenario:** Verus models `Item::may_load` as `Result<Option<Config>, Error>` where the `Err` arm has `e is Std`. Production code is `CONFIG.may_load(deps.storage)?` (line 183 of production) — the `?` propagates a `cosmwasm_std::StdError`, but the *only* failure mode for `cw_storage_plus::Item::may_load` is deserialisation failure (corrupt storage). The Verus prototype's body returns `Ok(Some(...))` or `Ok(None)` unconditionally — the Err arm is unreachable from this body. The `match` at lines 256-264 has an `Err(e) => return Err(e)` arm that is *also* unreachable but pretends to model deserialisation failure.
- **Why it succeeds:** The contract `Err(e) => e is Std` is technically satisfiable by an empty Err branch, so Verus accepts it, but the inner-handler implication "if storage is corrupt, the wrapper returns Err(Std) before checking mr_enclave" is never witnessed. A production attacker who can cause CONFIG to be corrupt (e.g. via a half-completed migration) gets `Err(Std)` *before* any user_data or mr_enclave check fires — the prototype proves the user_data check happens first (line 252), but production sequences user_data then `may_load?`. Both orderings happen to be safe (any Err short-circuits), but the prototype's spec does not pin which mismatch the attacker sees first.
- **Suggested defense:** Either give `may_load` a non-vacuous failure path (a `#[verifier::external_body]` variant that nondeterministically returns Err) or add a comment that the prototype assumes serialise-infallibility for `RawConfig`.

## 5. [instantiate.rs] `RawConfig::from(Config)` drift hides a TryFrom failure

- **Target:** `instantiate.rs:55-82, 200-206` (Verus); `crates/contracts/core/src/state.rs:62-85` (production)
- **Category:** stubbing drift / spec collapse
- **Severity:** **serious**
- **Scenario:** Production `RawConfig` has three fields (`mr_enclave: HexBinary`, `light_client_opts: RawLightClientOpts`, `zkdcap_vkey: Option<String>`). `TryFrom<RawConfig> for Config` (state.rs:72-85) is **fallible**: it calls `value.mr_enclave.to_array()?` (errors if not 32 bytes) and `value.light_client_opts.try_into()` (errors if `trust_threshold` is malformed — state.rs:118-128 has multiple validation rules: `numerator > denominator`, `denominator == 0`, `3 * numerator < denominator`, `trusted_height > i64::MAX`). The Verus prototype collapses Config to `{ mr_enclave: u64 }` and makes `as_raw()` **infallible** (line 79-81). The proof obligation "CONFIG holds Some(spec_as_raw)" is then a tautology over a one-field copy.
- **Why it succeeds:** The Kani harnesses in production `state.rs:324-355` cover the trust_threshold validation, but the Verus prototype claims to be "the spec level mirror" of the instantiate handler and silently drops the validation requirement that production performs on the *deserialise* side. The Verus prototype's `core_instantiate_handle` would succeed for inputs that production would reject at deserialisation before the handler is even called. The verified property `CONFIG holds Some(self.config)` cannot be lifted to production without re-stating that the input passed `TryFrom<RawConfig>::try_from`.
- **Suggested defense:** Either fold the light_client_opts validation into the Verus `Config::new` spec, or qualify the prototype's claim as "given a well-formed Config domain value, the handler stores its raw projection."

## 6. [instantiate.rs] `CONFIG.save` modelled as body-verified despite production using cw-storage-plus over dyn Storage

- **Target:** `instantiate.rs:117-148` (Verus); `crates/contracts/core/src/state.rs:16` and call site `crates/contracts/core/src/handler/instantiate.rs:27-29` (production)
- **Category:** external_body trust-boundary hole
- **Severity:** **serious**
- **Scenario:** Production `CONFIG.save` is `cw_storage_plus::Item<RawConfig>::save(&self, store: &mut dyn Storage, data: &RawConfig) -> StdResult<()>`. The body serialises via serde_json::to_vec and writes to the dyn Storage trait object. Failure modes: (1) serialisation panics on `Vec<u8>` allocation under wasm memory pressure, (2) the underlying KV store rejects oversized values, (3) prefix collisions if multiple Items share key prefixes. Verus's `Item::save` (lines 138-148) is body-verified over `storage.config = Some(...)`, which assumes the storage slot is a *typed Option<RawConfig>* — that is **not** what cw-storage-plus is. The spec contract holds for the *model* but says nothing about the production semantic.
- **Why it succeeds:** The comment at instantiate.rs:120-122 admits this: "The real cw-storage-plus Item<T>::save is generic over Serialize and dyn Storage, which Verus cannot model; production would use the external_body variant." But the prototype **does not actually use the external_body variant** — it uses Variant A (body-verified) for the proof. The "production-faithful Variant B" is documented in `session_create.rs` but is similarly commented out. The proof's strength is therefore over the model, not the production code.
- **Suggested defense:** Switch the prototype to Variant B for the verified result count, or explicitly label all "saves succeed" proofs as model-relative.

## 7. [instantiate.rs] `lemma_wrapper_ok_implies_inner_ran` proves a triviality

- **Target:** `instantiate.rs:249-260` (Verus)
- **Category:** verified-count inflation
- **Severity:** **advisory**
- **Scenario:** The lemma asserts `post_config != pre_config || pre_config == Some(...)`. Its `requires` clause already gives `post_config == Some(msg.inner.spec_config().spec_as_raw())`, so the conclusion `post_config != pre_config OR pre_config == Some(msg.inner.spec_config().spec_as_raw())` is `True OR (pre_config == post_config)` — a tautology of propositional logic, not a witness that "the inner ran."
- **Why it succeeds:** The lemma's name overstates its content. The comment at line 247 says "kept as a separate proof function to give an extra `verified` count" — this is honest but it means the "9 verified" headline is partly padding.
- **Suggested defense:** Replace with a lemma whose conclusion is non-trivial given the requires, e.g. `pre_config.is_none() ∨ pre_config == Some(...)`; or remove and drop the verified count by 1.

## 8. [session_create.rs] `addr_validate` stub drops bech32 canonicalisation

- **Target:** `session_create.rs:84-103, 117` (Verus); `crates/contracts/core/src/handler/execute/session_create.rs:16-19` (production)
- **Category:** stubbing drift / cosmwasm-std semantics
- **Severity:** **serious**
- **Scenario:** Production `deps.api.addr_validate(&self.contract)?` takes a `&str`, runs the chain's bech32 decoder, and returns an `Addr` (a string-newtype). It is **not** identity — it lowercases, normalises padding, and rejects malformed bech32. The Verus stub at lines 88-102 is `Ok(s)` (identity). The spec-level `addr_oracle` (line 117) is uninterpreted but the body returns identity, so the Ok branch is `a == s && a == b` which forces `addr_oracle(s) = Ok(s)`. The prototype's Ok postcondition (line 227) is `addr_oracle(msg.spec_contract()) == Result::<u64, ()>::Ok(env.contract.address)`.
- **Why it succeeds:** In production, the attacker can supply `self.contract = "XION1ABC..."` (uppercase). The chain's addr_validate returns the canonical lowercase `Addr("xion1abc...")`. The comparison `addr != env.contract.address` then evaluates *post-canonicalisation*. The Verus spec, modelling validate as identity, witnesses `msg.spec_contract() == env.contract.address` — but production's success condition is `canonicalise(msg.contract) == env.contract.address`. The two propositions are not equivalent under any string normalisation. The prototype proves the *wrong* postcondition.
- **Suggested defense:** Model addr_validate as `Result<Addr, Error>` where `Addr` is an opaque type and the result is `Ok(canonical(s))`; require the postcondition to mention `canonical(s) == env.contract.address`.

## 9. [session_create.rs] Storage error path commented unreachable but proven anyway

- **Target:** `session_create.rs:153-162, 239-242` (Verus); production cw_storage_plus
- **Category:** spec-vs-body mismatch
- **Severity:** **advisory**
- **Scenario:** The Verus `Item::save` body at lines 159-162 always returns `Ok(())`. The ensures clause at 154-158 spells out both Ok and Err post-conditions, with Err preserving storage. Verus accepts this because `Err` is dead code in the body. The handler's match at lines 239-242 has an `Err(e) => Err(e)` arm that is similarly dead. The comment at lines 135-141 acknowledges "in practice the Err arm is unreachable for `Session`."
- **Why it succeeds:** The proven property "Err ⇒ storage unchanged" holds vacuously. A production-realistic failure (e.g. memory exhaustion during serialisation) would surface as a wasm trap, not an `Err(Std)` — neither the prototype nor production handles that path. The prototype's Err contract is therefore aspirational rather than tested.
- **Suggested defense:** Replace the body-verified `save` with a `#[verifier::external_body]` returning a nondeterministic `Result`, so the Err arm is reachable and the wrapper's `Err ⇒ storage unchanged` contract is exercised.

## 10. [session_set_pub_key.rs] SEQUENCE_NUM.save is **completely missing** from the spec

- **Target:** `session_set_pub_key.rs:80-114` (Verus); `crates/contracts/core/src/handler/execute/session_set_pub_key.rs:23-27` (production)
- **Category:** missing production behaviour / replay-protection drift
- **Severity:** **critical**
- **Scenario:** Production `SessionSetPubKey::handle` (production lines 21-27) performs **two** storage writes in a row: (1) `SESSION.save(deps.storage, &session)` then (2) `SEQUENCE_NUM.save(deps.storage, &Uint64::new(0))`. The second write **resets the replay counter to zero**. This is the replay-protection foundation for all subsequent `Sequenced<T>` handlers (which call `SEQUENCE_NUM.update(...)` to increment — `crates/contracts/core/src/handler/execute/sequenced.rs:9-12`). The Verus prototype's `Storage` struct (line 47) has *no* `sequence_num` field, and the handler's Ok postcondition (lines 89-94) makes **zero mention** of sequence_num being reset.
- **Why it succeeds:** A re-handshake (legitimate or attacker-induced) silently wipes the sequence counter — every previously-issued `Sequenced<T>` message becomes a valid replay target because the counter is back to zero. The Verus prototype proves a property strictly weaker than what the production handler is responsible for. An adversarial implementer could refactor the production handler to *skip* the SEQUENCE_NUM reset and the Verus proof would still hold; the failure mode is invisible to the spec. The replay-protection invariant is unprovable from this prototype.
- **Suggested defense:** Add `pub sequence_num: Option<u64>` to `Storage`, and extend the Ok postcondition with `final(storage).sequence_num == Some(0)`. Also add a separate proof obligation that the Err branch leaves sequence_num *unchanged* (since a partial first-save / failed-second-save would leave SESSION updated but the counter stale — a real subtle bug Verus can catch).

## 11. [session_set_pub_key.rs] Atomicity gap: SESSION saved, SEQUENCE_NUM save fails

- **Target:** `session_set_pub_key.rs:110-114` (Verus); `crates/contracts/core/src/handler/execute/session_set_pub_key.rs:21-27` (production)
- **Category:** transaction atomicity / missing property
- **Severity:** **serious**
- **Scenario:** If `SEQUENCE_NUM.save` fails *after* `SESSION.save` succeeded (production), the cosmwasm transaction aborts and the chain rolls back both writes — but only because cosmwasm's per-tx atomic-rollback is in force. The Verus spec doesn't model that rollback. As written, the prototype's `Storage` is just a mutable struct; if it modeled both fields and the second save failed, the spec would witness `SESSION updated, SEQUENCE_NUM unchanged` as a possible final state — which is exactly what production *should not* allow.
- **Why it succeeds:** The Verus prototype has no model of transaction rollback. Adding `sequence_num` to Storage without adding rollback semantics would *introduce* a spurious attack surface that the cosmwasm runtime forecloses. Either model both fields with rollback, or model neither.
- **Suggested defense:** Add a single `commit` operation at the end of the handler that flushes a staged Storage to the live Storage; spec the handler over staged storage only.

## 12. [session_set_pub_key.rs] `with_pub_key` spec admits `pub_key = 0` collision with "unset"

- **Target:** `session_set_pub_key.rs:20-43` (Verus); `crates/contracts/core/src/state.rs:229-236` (production)
- **Category:** type narrowing / Option vs Result
- **Severity:** **advisory**
- **Scenario:** Verus models `pub_key: Option<u64>` where `0` is a valid u64 inhabitant. Production `Option<HexBinary>` has `HexBinary` as a `Vec<u8>` newtype; an empty HexBinary `[]` is distinguishable from a 33-byte SEC1 pubkey. The Verus spec's `s.pub_key.is_none()` correctly tracks the Option discrimination, but the `pk: u64` parameter at line 34 lets `with_pub_key(n, 0)` succeed — producing `Some(Session { pub_key: Some(0) })`. Production's `with_pub_key` accepts any `Vec<u8>` including empty, which the spec does not rule out either, but the public-key cryptographic invariant (SEC1 33-byte compressed form) is enforced nowhere.
- **Why it succeeds:** The Verus spec proves the state-transition guard, not the well-formedness of the pubkey. An adversary submitting `pub_key = vec![]` or `pub_key = vec![0u8]` passes both spec and production with a syntactically valid Option but a cryptographically useless content; subsequent ECIES encrypt-to-pub_key calls will fail at the k256 layer, but no on-chain rejection happens at session_set_pub_key time.
- **Suggested defense:** Add a `requires` on `with_pub_key`: `pk.len() == 33 ∧ pk[0] ∈ {0x02, 0x03}` (or the corresponding spec-fn). Spec the SEC1 admissibility constraint.

## 13. [encryption.rs] `Message` monomorphisation drops untagged-enum / flatten / non-string-key footguns

- **Target:** `encryption.rs:44-46, 116-123` (Verus); `crates/enclave/core/src/encryption.rs:25-41` (production)
- **Category:** stubbing drift / serde_json behaviour
- **Severity:** **serious**
- **Scenario:** Verus `Message { a: u64, b: u64 }` is a record of two primitives. Production `encrypt_json::<T: serde::Serialize>` accepts any `T`. serde_json's roundtrip *fails* (is not the identity) for: (a) `#[serde(untagged)]` enums where multiple variants serialise identically, (b) `#[serde(flatten)]` on structs containing the same key in inner and outer position (silently loses one), (c) `f64::NAN` and `f64::INFINITY` (serialise as null, never deserialise back), (d) `HashMap<K, V>` with non-string K (serialised as string, deserialised back to `&str`, which fails K decoding), (e) `Vec<u8>` (which serialises as a JSON array, *not* base64).
- **Why it succeeds:** The Verus axiom `serde_roundtrip_axiom(v: Message)` at lines 116-123 says "for the model type Message, encode/decode roundtrips." Generalising this to "for all T, encode/decode roundtrips" is the implicit claim the production wrappers make. That generalisation is false. Specifically, the production payload `RawAttested<RawSessionSetPubKey, RawDstackZkAttestation>` contains nested `HexBinary` (Vec<u8> newtype) which serialises *correctly* as JSON arrays — but if any downstream consumer assumes base64 or hex (a frequent enclave/host miswiring), the roundtrip silently corrupts.
- **Suggested defense:** Refuse to claim T-generic roundtrip from a Message-specific axiom. Either prove the axiom over `RawAttested<...>` specifically (the actual payload), or add a static-assertion-style constraint that the type used implements no `#[serde(untagged)]`/`flatten`/`skip` attributes.

## 14. [encryption.rs] `ecies_roundtrip_axiom` says nothing about confidentiality

- **Target:** `encryption.rs:99-113, 186-199` (Verus); `crates/enclave/core/src/encryption.rs:13-22` (production)
- **Category:** property drift / missing security claim
- **Severity:** **serious**
- **Scenario:** The proved "ECIES roundtrip" property is `encrypt(pk, m) then decrypt(sk, ·) returns m`. This is **correctness**, not **confidentiality**. The actual security property of ECIES is "no PPT adversary with `pk` and `c = encrypt(pk, m)` can distinguish `m` from `m'` with non-negligible advantage." The Verus prototype's `ecies_encrypt_spec` is uninterpreted and could be the identity function (encrypt(pk, m) = m) — and all roundtrip proofs would still pass. Lean's `Specs/Quartz/Crypto/Ecies.lean` (referenced at line 11) carries this trust-boundary axiom alongside hardness assumptions; the Verus prototype carries only the roundtrip half.
- **Why it succeeds:** The prototype's text at lines 12-14 says "We do NOT prove secp256k1 hardness, AES-GCM/HKDF correctness, or any byte-level serde_json behaviour — those remain trust-boundary axioms." Acknowledged. But this means the proved property is operationally vacuous — the spec admits an `ecies_encrypt_spec` that leaks the plaintext in cleartext. A reviewer who sees "ECIES roundtrip verified in Verus" and assumes confidentiality is misled.
- **Suggested defense:** Add a spec-level IND-CPA predicate `ecies_indcpa_secure(pk, m1, m2)` even if uninterpreted; require it as a `requires` of any caller that relies on confidentiality. Mirror the Lean axiomatisation.

## 15. [encryption.rs] `encrypt_json` Err branch is `Err(_) => true` — no contract at all

- **Target:** `encryption.rs:152-166, 169-183` (Verus)
- **Category:** Option/Result discipline / spec hole
- **Severity:** **advisory**
- **Scenario:** The Ok branches at lines 155-157 and 172-174 give a precise existential. The Err branches at lines 158 and 175 are `Err(_) => true` — the spec is silent. This means a buggy implementation that returns `Err(CryptoError::Ecies)` *whenever serde succeeds and ECIES fails*, OR `Err(CryptoError::Serde)` *whenever serde fails*, OR a swap of those two — all pass verification. A caller cannot infer from the spec that `Err(CryptoError::Serde)` implies serde failure.
- **Why it succeeds:** Verus's `Err(_) => true` is propositionally trivially true. The spec is correct in the sense that it does not lie, but it is uninformative — a caller doing `if let Err(CryptoError::Ecies) = encrypt_json(...) { /* retry serialisation */ }` has no spec-backed guarantee that the retry is well-founded.
- **Suggested defense:** Tighten the Err branch to discriminate: `Err(CryptoError::Serde) => serde_to_vec_spec(*value) is Err` and `Err(CryptoError::Ecies) => serde_to_vec_spec(*value) is Ok ∧ ecies_encrypt_spec(*pubkey, ?bytes) is Err`.

## 16. [key_manager.rs] Binding invariant `pub_key matches sk` does not survive `import`

- **Target:** `key_manager.rs:122-126, 156-166` (Verus); `crates/enclave/core/src/key_manager/default.rs:50-57` (production)
- **Category:** missing production property / state-mutation invariant
- **Severity:** **critical**
- **Scenario:** Theorem 1 at lines 156-166 (`pub_key_matches_sk`) proves the invariant for a *frozen* `DefaultKeyManager` value. Production `impl Import for DefaultKeyManager` (production lines 49-57) does `self.sk = SigningKey::from_slice(&data)?` — mutating the `sk` field in place. After import, any previously-cached or previously-published `PubKey` is **stale**: it no longer corresponds to `km.sk`. The Verus prototype does not model `import` as a mutation at all (lines 143-146 give a pure `import_sk(bytes) -> Result<SigningKey, KmError>` that returns a fresh key but does not write it back to a DefaultKeyManager).
- **Why it succeeds:** The published `pub_key` is a `VerifyingKey` value held by callers — the contract trustfully retains it as "the enclave's identity." After an import, the enclave begins signing/decrypting with a *different* `sk`, but the contract still has the *old* `pub_key`. Subsequent ECIES-to-pub_key messages decrypt with the wrong key (or fail) and signature verification by the contract uses the wrong public key. The Verus invariant `verifying_key_spec(km.sk) == pub_key(&km).0` is a snapshot property; the temporal property "at every point in time, pub_key_currently_held_by_contract == derive(km.sk_currently_held_by_enclave)" is what matters for security, and it is not proved.
- **Suggested defense:** Add a `pub_key_published` ghost field to `DefaultKeyManager`. Prove `import` either invalidates `pub_key_published` (sets it to `None`) or atomically updates it. Alternatively, model the "publish" step explicitly and prove `publish(km) ⇒ pub_key_published(km') == verifying_key_spec(km'.sk)`.

## 17. [key_manager.rs] `pub_key_matches_sk` ensures is a propositional tautology

- **Target:** `key_manager.rs:156-166` (Verus)
- **Category:** verified-count inflation
- **Severity:** **advisory**
- **Scenario:** The ensures clause is `forall |k: DefaultKeyManager| #[trigger] verifying_key_spec(k.sk) == verifying_key_spec(k.sk)`. This is `∀ k. X = X` — the reflexivity of equality. It is provable from the empty proof body by `intro k; refl`. It does not capture the actual binding invariant (which is the ensures clause of `pub_key` itself at line 123). The "theorem" reduces to "equality is reflexive."
- **Why it succeeds:** The author appears to have intended `verifying_key_spec(k.sk) == pub_key(&k).0` but wrote both sides as `verifying_key_spec(k.sk)`. Verus happily verifies the tautology.
- **Suggested defense:** Replace the RHS with `pub_key(&k).0` (and add the appropriate exec→spec scaffolding) — or remove the theorem entirely as it duplicates the `pub_key` exec ensures.

## 18. [key_manager.rs] `signing_key_to_bytes` / `signing_key_from_slice` have no ensures linking them

- **Target:** `key_manager.rs:72-81, 94-105` (Verus); `crates/enclave/core/src/key_manager/default.rs:49-57, 59-66` (production)
- **Category:** trust-boundary hole
- **Severity:** **serious**
- **Scenario:** Lines 74-76: `signing_key_to_bytes(sk: &SigningKey) -> (r: Vec<u8>)` — no ensures. Lines 79-81: `signing_key_from_slice(b: &Vec<u8>) -> (r: Result<SigningKey, KmError>)` — no ensures. The axiom `signing_key_bytes_roundtrip_axiom` at lines 94-105 has `requires true` and gives `verifying_key_spec(decoded) == verifying_key_spec(sk)`. The axiom is invoked at line 181 with arbitrary `bytes` and `decoded` — there is **no proof obligation** that `bytes` actually came from `signing_key_to_bytes(km.sk)` or that `decoded` is the result of `signing_key_from_slice(bytes)`. The author can pass arbitrary unrelated values to the axiom and conclude that any decoded key has the same pub_key as any sk.
- **Why it succeeds:** The "ghost premise: bytes came from to_bytes(sk) and decoded came from from_slice(bytes)" at lines 100-101 is admitted as `requires true` — no actual link. The axiom is vacuously usable. The proof `import_export_roundtrip` at lines 177-182 takes `bytes: Seq<u8>` and `decoded: SigningKey` as bare parameters and applies the axiom — concluding `verifying_key_spec(decoded) == verifying_key_spec(km.sk)` for **any** `decoded`. The theorem says "for any SigningKey decoded, its pub_key equals km.sk's pub_key" — which is **false** in general and constitutes a logical inconsistency in the spec.
- **Suggested defense:** Add ensures to `signing_key_to_bytes` and `signing_key_from_slice` that link them via a spec-level encode/decode predicate. Tighten the axiom's `requires` to a non-trivial precondition that the ghost values are well-formed. As stated, the axiom and theorem are unsound.

## 19. [key_manager.rs] DstackKeyManager (production default) is unmodelled

- **Target:** `key_manager.rs` (Verus, all); `crates/enclave/core/src/key_manager/dstack.rs:36-141` (production)
- **Category:** scope drift / missing variant
- **Severity:** **serious**
- **Scenario:** The Verus prototype models `DefaultKeyManager` only (the random-key fallback). Production CLAUDE.md states "DstackKeyManager (dstack KMS) is default." `DstackKeyManager::new` (production lines 41-64) silently falls back to `SigningKey::random(...)` when dstack is unavailable — a development-vs-production divergence that should be a spec target. `DstackKeyManager::import` (production lines 167-181) re-derives the key from KMS using a stored path — a categorically different operation from `SigningKey::from_slice`. The Verus prototype's `import_export_roundtrip` proves a property that is true for DefaultKeyManager (bytes ↔ key roundtrip) but not for DstackKeyManager (path ↔ key derivation via remote KMS call).
- **Why it succeeds:** A reader of the Verus proof concludes "the key manager's binding invariant is proved" — but the proof is over the non-default key manager. The production default has a fundamentally different threat model (trust the KMS service, accept fallback to random) that is not addressed.
- **Suggested defense:** Add a `DstackKeyManager` model with an external_body `dstack_derive_key(path: &str) -> Result<SigningKey, KmError>` and an uninterpreted spec `dstack_kms_oracle(path: Seq<u8>) -> SigningKey`. Prove import-export roundtrip via path equality, not bytes equality.

## 20. [attested.rs] cfg(feature = "mock") swap is invisible to the prototype

- **Target:** `attested.rs:280-359` (Verus); `crates/contracts/core/src/handler/execute/attested.rs:46-72, 126-136` (production)
- **Category:** mock-mode vs production divergence
- **Severity:** **serious**
- **Scenario:** Production has TWO impls for `DstackAttestation::handle` (lines 46-60 non-mock, lines 62-72 mock) and TWO for `DstackZkAttestation::handle` (lines 80-124 non-mock, lines 126-136 mock). The mock variants return `Ok(Response::default())` trivially. The Verus prototype's `dstack_zk_handle` (lines 322-359) models the *non-mock* path with vkey load + zk_query_verify. Its `trivial_handler` (lines 369-376) models the *mock* path. The prototype does not declare *which* path it has proved, nor that the proved properties are conditional on `#[cfg(not(feature = "mock"))]`.
- **Why it succeeds:** A build with `--features mock` produces a binary whose `DstackZkAttestation::handle` accepts *any* proof — the `zkdcap_vkey` check, the gRPC query, the decode, the `verified == true` test, all gone. The Verus proof "zk attestation Ok ⇒ verifier said yes" does not apply to the mock build. The prototype's `trivial_handler` proof (`Ok` for any input) is the spec for the mock build — and it says nothing useful. A deployment that accidentally ships with `--features mock` has *neither* a spec-proved verification *nor* a runtime verification — the spec is silent on this configuration switch.
- **Suggested defense:** Explicitly tag each handler proof with `// Verifies: --features ≠ "mock"` and provide a separate, weaker spec for the mock build (Ok ⇒ ⊤). Document that the verified property is configuration-dependent.

## META

- **Per-file counts:** instantiate.rs 3 (attacks #5, #6, #7); attested.rs 5 (attacks #1, #2, #3, #4, #20); session_create.rs 2 (attacks #8, #9); session_set_pub_key.rs 3 (attacks #10, #11, #12); encryption.rs 3 (attacks #13, #14, #15); key_manager.rs 4 (attacks #16, #17, #18, #19). Total: **20**.
- **Severity histogram:** critical 3 (#1 ZK input binding, #10 SEQUENCE_NUM, #16 import invariant); serious 11; advisory 6.
- **Recurring patterns:**
  1. **Body-verified storage stubs that are not Variant B.** `Item::save` and `Item::may_load` in `instantiate.rs`, `session_create.rs`, `session_set_pub_key.rs` are all body-verified over typed `Option<T>` fields rather than the dyn-Storage external_body variant the prototype admits is production-faithful. The author wrote Variant B as a comment in `session_create.rs:164-182` and `instantiate.rs:120-122` but never used it. (attacks #6, #9)
  2. **Type stubs that collapse production state.** `Storage` in the wrapper files is one field per file — `session: Option<Session>` in session files, `config: Option<RawConfig>` in instantiate/attested. Production storage is a single key-value map shared by SESSION, CONFIG, **and SEQUENCE_NUM**. The prototype's Storage cannot witness an interaction between these. SEQUENCE_NUM is silently dropped from `session_set_pub_key.rs` and `sequenced.rs` is not modelled at all. (attacks #10, #11)
  3. **Tautological lemmas to inflate the verified count.** `instantiate.rs:lemma_wrapper_ok_implies_inner_ran` and `key_manager.rs:pub_key_matches_sk` both prove propositional tautologies. The advertised "binding invariant" lemma in key_manager.rs is literally `∀ k. X = X`. (attacks #7, #17)
  4. **External_body axioms with no requires linking inputs.** `signing_key_bytes_roundtrip_axiom` is the most extreme: any (sk, bytes, decoded) tuple satisfies the requires (which is `true`), and the conclusion that decoded.pub_key == sk.pub_key is then applied at arbitrary call sites. This is a soundness break — the axiom can be used to derive false statements. (attack #18)
  5. **Monomorphisations that erase the only interesting failure mode.** `Attested<M,A>` monomorphises to total-Ok handlers; the comment admits this loses inner-handler error propagation and promises a `concrete_att_handle_maybe_err` external_body variant that **does not exist in the file**. The compensating mechanism is documented but absent. (attack #2)
  6. **Type narrowing without recapture.** Nonce, MrEnclave, UserData, pubkey bytes, vkey name — all `[u8; 32]` / `[u8; 64]` / `String` in production, all `u64` in Verus. The discipline being proved is control-flow over equality, but equalities on bytes hide partial-match attacks (substring, lowercase, leading-zero stripping) that equality-on-u64 cannot witness. (attacks #8, #12)
  7. **Confidentiality vs correctness conflation.** encryption.rs proves roundtrip (correctness) and labels it "discharges Lean's ECIES axiom." Lean's axiomatisation includes IND-CPA; the Verus prototype does not. A reviewer treating "Verus-proved ECIES" as a confidentiality witness is misled. (attack #14)

- **Recommendation:** Two findings (attacks #1, #10) and the soundness break (attack #18) are blockers. Specifically:
  - #1: The DstackZkAttestation spec must witness the binding between `zkdcap_public_inputs` and the wrapper's `compose_hash` / `user_data`. As written, the spec admits a production handler that accepts proofs about a different enclave. This is the load-bearing security property of the entire zkdcap pipeline.
  - #10: `SessionSetPubKey` must spec the SEQUENCE_NUM reset. Replay protection cannot be reasoned about without it.
  - #18: `signing_key_bytes_roundtrip_axiom` must have a non-trivial requires linking (sk, bytes, decoded). The current axiom is unsound and could be used to derive `false`.
  - Lesser-but-significant: re-instate the promised `concrete_att_handle_maybe_err` (#2), model `DstackKeyManager` rather than only `DefaultKeyManager` (#19), and add a `#[cfg(feature = "mock")]`-conditional spec (#20).
  - The prototypes are useful as a sanity check that Verus *can* talk about Quartz's handler logic, but the "verified" headline overstates how much real-world drift they catch. Recommend they be re-labelled as feasibility specs (which the file headers already do) and not promoted toward integration without addressing #1, #10, #18 at minimum.
