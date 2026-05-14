# Multi-model adversarial synthesis: Quartz Verus prototype (Round D)

- Targets (6 files, 1431 lines total):
  - `crates/contracts/core/verus-prototype/instantiate.rs` (264)
  - `crates/contracts/core/verus-prototype/attested.rs` (388)
  - `crates/contracts/core/verus-prototype/session_create.rs` (247)
  - `crates/contracts/core/verus-prototype/session_set_pub_key.rs` (118)
  - `crates/enclave/core/verus-prototype/encryption.rs` (228)
  - `crates/enclave/core/verus-prototype/key_manager.rs` (186)
- Production intent: `crates/contracts/core/src/{state.rs, handler/execute/*, handler/instantiate.rs}`, `crates/enclave/core/src/{encryption.rs, key_manager/{default,dstack}.rs}`
- Reviewed at: 2026-05-14/15
- Adversarial lineup (7 voices total, 6 yielded structured output):

  | Voice | Channel | Model | Elapsed | Output | Format | Status |
  |---|---|---|---|---|---|---|
  | Claude (subagent) | Agent | Opus 4.7 (1M) | ~5m | 40K | structured, 20 attacks | OK |
  | Qwen | local | qwen3.6-27b-mlx | 22m | 9.8K | structured, 7 attacks | OK |
  | Gemma | local | google/gemma-4-26b-a4b | 110m | 103K | reasoning-only (finish=length) | partial |
  | Kimi | gateway | kimi-k2-6 | 2m | 33K | reasoning-only (finish=length, 8K cap) | partial |
  | GLM | gateway | glm-4-7-flash | 1m | 7.9K | structured, 8 attacks | OK |
  | GPT-OSS | gateway | gpt-oss-120b | 1.5m | 21K | structured, 20 attacks | OK |
  | Mistral | local | mistral-small-4-119b-2603 | 118s | — | crashed (HTTP 400, OOM-like) | FAIL |

- Result: **27 distinct attacks after dedup**; 5 critical, 14 serious, 8 advisory.

The per-model reports are persisted verbatim alongside this synthesis. Orchestrator summarizes overlap and divergence; it does not add, weaken, or re-author findings.

---

## Verdict aggregate

| Voice | instantiate | attested | session_create | session_set_pub_key | encryption | key_manager |
|---|---|---|---|---|---|---|
| Claude | WEAKENS | BREAKS | WEAKENS | BREAKS | HOLDS-WITH-CAVEATS | BREAKS |
| Qwen | BREAKS | WEAKENS | HOLDS-WITH-CAVEATS | BREAKS | WEAKENS | BREAKS |
| Gemma | WEAKENS | BREAKS | HOLDS-WITH-CAVEATS | WEAKENS | HOLDS | HOLDS |
| GLM | HOLDS-WITH-CAVEATS | HOLDS-WITH-CAVEATS | HOLDS-WITH-CAVEATS | HOLDS-WITH-CAVEATS | HOLDS-WITH-CAVEATS | HOLDS-WITH-CAVEATS |
| GPT-OSS | BREAKS | BREAKS | BREAKS | BREAKS | BREAKS | BREAKS |
| **Cross-family majority** | **WEAKENS-or-worse** | **BREAKS** | mixed | **BREAKS** | mixed | **BREAKS-or-narrow** |

**Cross-family agreement on BREAKS**: `attested.rs`, `session_set_pub_key.rs`, `key_manager.rs`. **Cross-family agreement on WEAKENS-or-worse**: `instantiate.rs`. `session_create.rs` and `encryption.rs` are mixed — Claude/Qwen/Gemma judge them mild while gpt-oss judges everything BREAKS (gpt-oss has a tighter calibration than the rest).

---

## Critical findings (cross-voice load-bearing)

### Critical 1 — `signing_key_bytes_roundtrip_axiom` is **unsound** (Claude #18, Qwen #3, GPT-OSS #14)

`key_manager.rs:84-106`. The axiom is declared with `requires true,` and applied at `import_export_roundtrip` (line 181) with arbitrary `(sk, bytes, decoded)` parameters — no proof obligation links them. Conclusion: any `decoded: SigningKey` has the same `pub_key` as any `sk: SigningKey`. Three voices independently flagged this as a soundness break — the axiom can be used to derive `false`.

Three voices agree on the same fix: tighten `requires` to a non-trivial precondition that the ghost values are well-formed (`bytes == signing_key_to_bytes(sk)`, `decoded == signing_key_from_slice(bytes).unwrap()`).

### Critical 2 — `session_set_pub_key.rs` does not model `SEQUENCE_NUM` reset at all (Claude #10, Qwen #2, GLM #1, GPT-OSS #15-area, Gemma, Kimi prose)

**Universal across all six structured-or-prose voices**. Production `session_set_pub_key.rs:23-27` performs two storage writes: `SESSION.save` then `SEQUENCE_NUM.save(.., Uint64::new(0))`. The second write **resets the replay counter to zero**, which is the foundation for every downstream `Sequenced<T>` handler's replay protection. The Verus prototype's `Storage` struct (line 47) has *no* `sequence_num` field, and the handler's Ok postcondition (lines 89-94) makes **zero mention** of the reset.

A re-handshake silently wipes the sequence counter — every previously-issued `Sequenced<T>` message becomes a valid replay target. The Verus proof is silent on this. An adversarial implementer could refactor production to *skip* the SEQUENCE_NUM reset and the proof would still hold.

### Critical 3 — `Attested<M,A>` wrapper inner-handler error propagation is lost (Claude #2, Qwen #5, GLM #2, GPT-OSS #4 + #17, Gemma, Kimi prose)

**Universal**. `attested.rs:34-46, 165-191, 266-279`. The Verus prototype monomorphises `M = ConcreteMsg`, `A = ConcreteAtt`, each with `handle` whose postcondition is literally `ensures r is Ok` (lines 173-176, 188-191). Production `Attested<M,A>::handle` calls `Handler::handle(msg, deps.branch(), env, info)?` then `Handler::handle(attestation, deps, env, info)?` — both `?` operators are real failure exits.

The prototype's comment at line 43 admits the loss and promises a compensating `external_body` fallible variant `concrete_att_handle_maybe_err` — and **that variant does not exist in the file**. The advertised compensation is missing; the docstring is misleading.

### Critical 4 — DstackZk handler does not bind `zkdcap_public_inputs` to the wrapper's `compose_hash` / `user_data` (Claude #1)

Sole-voice critical (Claude only) but load-bearing for the whole zkdcap pipeline. `attested.rs:281-359`. The Verus spec at line 314 is `Ok(true) => zk_query_verify_succeeded(proof, public_inputs, vkey_name)` — terminating at "the verifier said yes on these inputs." There is **no spec clause** linking `public_inputs` back to `wrapper.spec_att_user_data()` or `RawConfig.mr_enclave`.

Production `attested.rs:94-99` constructs the protobuf request using `self.zkdcap_proof` and `self.zkdcap_public_inputs` verbatim — there is **no on-chain equality check** that `public_inputs` encodes the claimed `compose_hash`. The wrapper's `compose_hash` check (line 184 of production) compares `config.mr_enclave()` to `attestation.mr_enclave() = self.compose_hash` — a *self-declared* field on the attestation, not extracted from the proof. The prototype's omission models the production omission. **This is the central security property of the entire zkdcap pipeline ("the proof attests to *this* enclave"), and the Verus spec does not encode it.** A reviewer treating "DstackZk handle Ok ⇒ verifier accepted" as an enclave-binding witness is misled.

GPT-OSS #6 hits a related disjunction-vs-decomposition issue (encode/grpc/decode failures all collapse to `Error::ZkdcapVerificationFailed`) but does not surface the public-inputs-binding gap directly. Claude's file-access access to the production handler was needed to substantiate this finding cleanly.

### Critical 5 — `pub_key_matches_sk` invariant does not survive `Import::import` (Claude #16)

Sole-voice critical (Claude only). `key_manager.rs:122-126, 156-166`. Theorem 1 proves the binding for a *frozen* `DefaultKeyManager` value. Production `impl Import for DefaultKeyManager` (`default.rs:50-57`) does `self.sk = SigningKey::from_slice(&data)?` — mutating `sk` in place. After import, any previously-cached or previously-published `PubKey` is **stale**: it no longer corresponds to `km.sk`. The Verus prototype does not model `import` as a mutation of `DefaultKeyManager` at all; `import_sk` is a pure function that returns a fresh key without writing it back.

The published `pub_key` is what the contract trusts as the enclave's identity. After an import, the enclave begins signing/decrypting with a different `sk`; the contract still holds the old `pub_key`. ECIES-to-pub_key messages decrypt with the wrong key (or fail); contract signature verification uses the wrong public key. The temporal property "at every point in time, `pub_key_currently_held_by_contract == derive(km.sk_currently_held_by_enclave)`" is the actual security claim, and it is not proved.

---

## Cross-model agreement on serious findings

| # | Finding | Voices | Files |
|---|---|---|---|
| S1 | Storage `Item::save` / `may_load` body-verified, hides serialization/storage failure | Claude #6 #9, GLM #3 #4 #5, GPT-OSS #2 #8 #9 #10, Kimi prose | instantiate, session_create, session_set_pub_key, attested |
| S2 | `addr_validate` stub drops bech32 canonicalisation (identity vs canonical) | Claude #8, Qwen #7, GPT-OSS #7 #19 | session_create |
| S3 | `pub_key_matches_sk` ensures is propositional tautology `∀k. X = X` | Claude #17, GLM #6 #7 | key_manager |
| S4 | `deps.branch()` semantics + transactional rollback unmodeled | Claude #3, Qwen #5, GPT-OSS #18 | attested, session_set_pub_key |
| S5 | `RawConfig::from(Config)` drops `light_client_opts`/`zkdcap_vkey` (TryFrom validation) | Claude #5, GPT-OSS #1, Kimi prose | instantiate |
| S6 | `encrypt_json` / `decrypt_json` Err branch is `Err(_) => true` (no contract) | Claude #15, GPT-OSS #13, Kimi prose | encryption |
| S7 | ECIES roundtrip axiom is correctness, not confidentiality (no IND-CPA) | Claude #14, GPT-OSS #11, Gemma | encryption |
| S8 | `Message` monomorphisation drops untagged-enum / flatten / non-string-key footguns | Claude #13, Kimi prose (partial) | encryption |

---

## Net-new findings per voice

### Net-new from Qwen

- **Qwen #6 — SEC1 byte-encoding step omitted from spec (serious)**: Production `encrypt(pubkey, plaintext)` calls `ecies::encrypt(&pubkey.to_sec1_bytes(), plaintext)` — the `.to_sec1_bytes()` serialises the `VerifyingKey` into compressed/uncompressed SEC1 format. The Verus prototype passes the abstract `VerifyingKey` struct directly to `ecies_encrypt`, omitting the serialization boundary. A format mismatch (e.g., production expects compressed but receives uncompressed) would fail decryption silently. Spec should model `to_sec1_bytes` as a spec function with a roundtrip axiom.

### Net-new from GPT-OSS

- **GPT-OSS #5 — `zkdcap_vkey` u64 vs `Option<String>` (serious)**: Production type is `Option<String>`. Verus collapses to `u64` where `0 ⇒ None`. An empty-string vkey hashes to a non-zero u64, so the spec believes a key is present even when it is effectively empty. The spec can claim "vkey is set ⇒ verification succeeds" while production treats empty as malformed and rejects. Distinct from the `UserData u64 vs [u8;64]` finding (Claude #20 / GLM #8) which Claude already covered.
- **GPT-OSS #6 — Disjunction collapse on `zk_query_verify` failure modes (serious)**: The external body can return `Err(_)` for three distinct reasons (encode failure, gRPC transport failure, decode failure). The spec's `Err(Error::ZkdcapVerificationFailed)` ensures clause only requires `vkey != 0` and does not distinguish the three sources. Downstream retry policy reasoning (transient-network vs permanent-bad-proof) is foreclosed.
- **GPT-OSS #16 — `import_sk` Err for malformed bytes is unmodeled (serious)**: `signing_key_from_slice` external body has no `ensures` clause; the spec cannot reason about when `import_sk` fails. Distinct from Critical 1 (the *axiom* is unsound) — this is the *exec-fn contract* for the same call site.
- **GPT-OSS #18 — Concurrent re-entry race (advisory)**: The Verus prototype models `SESSION.may_load` and `SESSION.save` as atomic on a single mutable `Storage` reference. Two concurrent `session_set_pub_key` invocations with the same nonce but different pub_keys could interleave; the spec assumes atomicity and does not model. (CosmWasm transactions are atomic per-tx, so this is more of a theoretical refactor hazard than a present-day bug.)
- **GPT-OSS #20 — `encrypt_json`/`decrypt_json` key-pair coupling existential decoupling (serious)**: The spec uses `exists |bytes| …` independently in the encrypt and decrypt postconditions, allowing the verifier to pick *different* `bytes` values for each call. The same `Message` could in principle "decrypt" via a different ciphertext under a different key. Production ECIES requires the ciphertext from `encrypt(pk, m)` and the private key matching `pk`; the spec does not bind these.

### Net-new from GLM

- **GLM #6 + #7 — `verifying_key_spec` / `verifying_key_exec` not validated against `k256` implementation (critical per GLM)**: The proof relies on `verifying_key_spec` being the correct mathematical map from `SigningKey` to `VerifyingKey`. Production calls `VerifyingKey::from(&SigningKey)` from the `k256` crate. The Verus spec function is uninterpreted; if the production `k256` implementation changed (different curve, buggy build), the theorem remains true vacuously. This is one notch deeper than Claude's #14 (ECIES axiom is correctness-only): GLM points at the lack of an `external_body` linking the spec to the named library function.

### Truncated voices (Kimi, Gemma)

Neither produced structured attack lists — both hit `finish=length` mid-content. Kimi (max=8192) burned its entire output budget on detailed prose reasoning about files 1-4 without producing the per-attack format. Gemma (max=32768) burned 32K on `reasoning_tokens` and produced verdict lines + draft attack scaffolding but no final structured report. Their prose covered the same ground other voices already structured (SEQUENCE_NUM, Attested propagation, ECIES axiom, addr_validate). **No net-new findings**, but their truncation is a methodology datapoint (see below).

### Mistral

Crashed at 118s with HTTP 400 ("model crashed without additional information"). Lost voice; no findings produced.

---

## Per-spec final attack count after dedup

| File | Distinct | Critical | Serious | Advisory |
|---|---|---|---|---|
| instantiate.rs | 4 | 0 | 4 | 0 |
| attested.rs | 8 | 2 (C3, C4) | 5 | 1 |
| session_create.rs | 3 | 0 | 2 | 1 |
| session_set_pub_key.rs | 4 | 1 (C2) | 2 | 1 |
| encryption.rs | 6 | 0 | 5 | 1 |
| key_manager.rs | 5 | 2 (C1, C5) | 1 | 2 |
| **Total distinct** | **30** | **5** | **19** | **6** |

Recount on the 27 vs 30 — the 27 was an early estimate from the orchestrator's first pass; the rolled-up table here is 30 after final tabulation against all 7 reports.

---

## Recurring patterns (cross-voice)

1. **Body-verified storage stubs that pretend to model Item::save / Item::may_load** (Claude #6, GLM #3 #4 #5, GPT-OSS #2 #8 #9 #10, Kimi prose, Gemma): every prototype's storage operations are total-Ok body-verified stubs that admit `Err(Error::Std)` in the contract but never produce it in the body. The "Err ⇒ storage unchanged" postcondition is vacuously true. The `external_body` "Variant B" alternative is documented in `instantiate.rs:120-122` and `session_create.rs:164-182` comments but never used. **Most pervasive single pattern** — found by every voice that reached the file.
2. **Tautological lemmas that inflate the verified count** (Claude #7 #17, GLM #6 #7, Gemma reasoning): `lemma_wrapper_ok_implies_inner_ran` proves `True ∨ X`; `pub_key_matches_sk` proves `∀ k. X = X`. Both are propositional tautologies the comments admit are "kept for an extra verified count."
3. **`external_body` axioms with no `requires` linking inputs** (Critical 1, GLM #6 #7, GPT-OSS #14 #15 #16): `signing_key_bytes_roundtrip_axiom` is the most extreme; `verifying_key_exec` lacks a purity-determinism `ensures`; `signing_key_from_slice` has no contract. All three voices flag this as a soundness/utility hole.
4. **Type narrowing without recapture** (Claude #20, GLM #8, GPT-OSS #5, Gemma): `UserData [u8;64] → u64`, `MrEnclave [u8;32] → u64`, `zkdcap_vkey Option<String> → u64`, `pub_key Vec<u8> → u64`. Equality-on-u64 hides partial-match attacks (substring, lowercase, leading-zero stripping) that equality-on-bytes cannot witness.
5. **Confidentiality vs correctness conflation** (Claude #14, GPT-OSS #11, Gemma): `encryption.rs` proves roundtrip (correctness) but labels it "discharges Lean's ECIES axiom." Lean's axiomatisation includes IND-CPA; the Verus prototype does not. A reviewer treating "Verus-proved ECIES" as a confidentiality witness is misled.
6. **Monomorphisations that erase the only interesting failure mode** (Critical 3, GPT-OSS #4 #17, Qwen #1, Gemma): `Attested<M,A>` monomorphises to total-Ok handlers; the comment admits this and promises a compensating fallible variant that does not exist. `Instantiate<A>` strips the entire `Attested` wrapper and proves a property over `CoreInstantiate` directly. **Multiple voices independently flagged the missing `concrete_att_handle_maybe_err`** — the comment's promise is widely recognised as broken.
7. **Mock-mode invisibility** (Claude #20): production `#[cfg(feature = "mock")]` swaps both `DstackAttestation::handle` and `DstackZkAttestation::handle` for trivial-Ok variants. The Verus prototype does not declare which configuration its proofs apply to. A `--features mock` build's proof is the trivial-handler proof, which says nothing useful. Sole-voice but worth recording.

---

## Recommendation

**Three blockers must land before these prototypes can be referenced as anything beyond "feasibility specs":**

1. **Fix Critical 1 (unsound axiom)**: `signing_key_bytes_roundtrip_axiom` must have a non-trivial `requires` linking `bytes`, `decoded`, and `sk`. As stated, the axiom can derive `false` and the entire `key_manager.rs` proof tree is suspect.
2. **Add Critical 2 (`SEQUENCE_NUM` reset to spec)**: The replay-protection foundation cannot be reasoned about while the `Storage` model omits `sequence_num`. Six voices independently flagged this — the highest agreement-density finding in Round D.
3. **Restate Critical 3 (Attested error propagation)**: Either re-instate the promised `concrete_att_handle_maybe_err` external_body variant OR explicitly relabel the prototype's spec as silent on inner-handler failures. The current docstring promises a compensation that does not exist.

**Two should-also-fix items**:

4. **Critical 4 (`zkdcap_public_inputs` binding)**: Add a spec-level uninterpreted predicate `proof_journal_binds(proof, public_inputs, expected_compose_hash, expected_user_data)` and require it on the Ok branch. The production handler must extract or verify-equal these fields. The prototype's omission models the production omission — the missing check is real on both sides.
5. **Critical 5 (`pub_key_matches_sk` doesn't survive import)**: Add a `pub_key_published` ghost field to `DefaultKeyManager` and prove `import` either invalidates it (sets to `None`) or atomically updates it.

**Methodology / documentation actions**:

6. Switch the prototypes to "Variant B" (external_body storage operations) for the `Item::save` / `Item::may_load` stubs that currently are body-verified — closes pattern #1's vacuity at the spec contract level.
7. Tag each handler proof with `// Verifies: --features ≠ "mock"` and note the mock-build proof is separate and trivial.
8. Either delete the tautological lemmas (`lemma_wrapper_ok_implies_inner_ran`, `pub_key_matches_sk`) or rewrite their conclusions to be non-trivial given their `requires` clauses. The "verified count" is currently inflated by ~2 lemmas per file.

The prototypes are useful as a sanity check that Verus *can* talk about Quartz's handler logic, and several proofs (the equality-discipline portion of `Attested`, the Storage-state-transition shape of session handlers) are honest within their stated scope. But the "verified" headline overstates how much real-world drift the prototypes catch. **Recommend they remain labelled as feasibility specs and not be promoted toward integration without addressing Criticals 1, 2, and 3 at minimum.**

---

## Methodology notes (filed as colosseum v0.2 ask candidates)

**Mistral crash on 22K-token prompt**: `mistral-small-4-119b-2603` returned `HTTP 400: model has crashed` at 118s. The 119B-parameter non-reasoning model appears to hit a memory/throughput limit at this prompt size. Substitute candidates: a smaller Mistral (e.g., 22B-class) for the same family-diverse slot, or skip Mistral entirely if `qwen3.6-27b-mlx` is providing the non-Western-non-Anthropic voice.

**Reasoning-model max_tokens budgeting under-budget for structured-output tasks**: Two voices (Kimi at 8K, Gemma at 32K) hit `finish=length` and never produced structured attack lists despite reasoning extensively about the material. The colosseum-agent gateway-bug doc's per-route caps held — Kimi at 8K is the safe ceiling per Bug 3 — but the *visible-content* budget after reasoning_tokens is consumed is much smaller than the raw `max_tokens` budget would suggest. Gemma's 32K total budget produced 32K reasoning + 0 visible content. **Recommendation**: for adversarial-review fan-outs, allocate `max_tokens` as `reasoning_budget + visible_budget` and document both per-model. For Gemma at 26B, structured-output runs need either a separate non-reasoning pass or a much higher cap; for Kimi, accept the 8K cap and request a follow-up "continue your prior response" round to extract verdict lines + final attack list when the first response truncates mid-prose.

**Gemma 110-minute elapsed**: massive outlier vs. Round-C's ~10-15 min for the same model. Likely cause: cross-session LM Studio auto-evict contention with another concurrent local model load (qwen and gemma were both shown as `GENERATING` in `lms ps` simultaneously for an extended window). The fan-out script's sequential per-voice load is correct; the contention may be coming from another user-session process. Confirms the colosseum-agent's note about coordinating local fan-outs across sessions.

**Cross-family productivity** (consistent with Round C's finding): Claude is consistently strongest on cross-file Rust/Verus drift requiring file access (Claude #1 ZK binding, #16 import invariant, #19 DstackKeyManager, #20 mock cfg — all need reading both production and prototype). GPT-OSS is consistently strongest on systematic completeness (20 attacks, every file verdict BREAKS, finds the existential-decoupling angle no other voice spotted). GLM is fastest and gives a milder verdict baseline (everything HOLDS-WITH-CAVEATS) — useful as a calibration anchor. Qwen contributes one focused per-spec pass with a SEC1-encoding finding no other voice surfaced. The two truncated voices added zero net-new findings but their effort wasn't wasted — they corroborated the SEQUENCE_NUM and Attested-propagation findings via independent reasoning paths.

**Pinned model IDs for reproducibility** (per gateway-bug doc's "consumer-side discipline"):
- `claude-opus-4-7` (via Agent subagent)
- `qwen3.6-27b-mlx` (LM Studio local)
- `google/gemma-4-26b-a4b` (LM Studio local — truncated)
- `mistral-small-4-119b-2603` (LM Studio local — crashed)
- `kimi-k2-6` @ max=8192 (gateway, truncated)
- `glm-4-7-flash` @ max=16384 (gateway)
- `gpt-oss-120b` @ max=16384 (gateway)
