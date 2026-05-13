# Change record: UserDataCommit VCV-io migration (Step 2)

- Date: 2026-05-13T14:33:47Z
- Classification: intent-touching (refactor of the cryptographic trust boundary) + critical methodology finding (impossible-axiom surfacing)
- Intent revision: none (no `intent.md` edit needed — public API names preserved)
- Plan reference: `.colosseum/refactor-plan-vcvio.md` § "`UserDataCommit.lean` — 5 axioms → ~1"

## Description

Second module of the VCV-io refactor sequence. Migrated `Specs/Quartz/Crypto/UserDataCommit.lean` by bundling the previously-paired `commitHash : UserDataCommit → UserData` axiom and `commitHash_inj : Function.Injective commitHash` axiom into a single `Function.Embedding`-shaped axiom

```lean
axiom commitHashE : UserDataCommit ↪ UserData
```

`commitHash` is now a derived `def` (the embedding's underlying function), and `commitHash_inj` is now a derived `theorem` (the embedding's `injective` field). The three abstract carrier axioms (`DomainSep`, `Addr`, `Nonce`) remain — they are used across multiple downstream modules (`RawMessages.lean`, `Conservation.lean`, `TransferMessages.lean`, `AuctionMessages.lean`) and bundling them is out of scope for this step. The migration preserves the public API: `commitHash`, `commitHash_inj`, and `pkOfUserData_commitHash` all retain their original signatures, so no downstream theorem needed modification.

A companion module `Specs/Quartz/Crypto/UserDataCommitVCVio.lean` was added. It sketches the truthful random-oracle model of `commitHash` using VCV-io's `OracleSpec` + `OracleComp` machinery, and documents the negligible-collision honesty target. The companion is kept separate from the core module to keep VCV-io's transitive instance load out of downstream files (same pattern as Step 1's `EciesVCVio.lean`).

## Critical methodology finding (honesty-lens) — load-bearing

The bundled `commitHashE : UserDataCommit ↪ UserData` axiom **is mathematically impossible** in the same sense the old `commitHash_inj` was. It asserts an injective embedding of the open-cardinality structure `UserDataCommit` (whose `domainSep`, `contractAddr`, `nonce` fields range over abstract carriers without size bounds, and whose `eciesPubkey` ranges over `PubKey`) into the fixed-width 64-byte `UserData` slot. By pigeonhole, no such embedding exists once `|UserDataCommit| > |UserData|`.

Bundling the two axioms into one **does not fix this**. It surfaces it: the single axiom now visibly carries both "there is a hash" and "the hash is collision-free", which exposes the second claim as the load-bearing impossible trust assumption.

**Downstream theorems silently relying on the impossible axiom**:

- `Specs.Quartz.Crypto.pkOfUserData_commitHash` (this module)
- `Specs.Quartz.Protocol.Handshake.handshake_binds_ecies_key` (3rd conjunct, via `pkOfUserData_commitHash`)
- `Specs.Quartz.Protocol.Confidentiality.session_confidentiality_via_extractor` (existential pubkey witness, via `pkOfUserData_commitHash`)
- `Specs.Quartz.Crypto.userData_session_set_pub_key_binds_ecies` (RawMessages bridge — also rides on the impossible axiom via `pkOfUserData_commitHash` after the bridge axiom)
- `Specs.Quartz.Crypto.userData_session_create_extracts_placeholder` (same)

Verified via `lean_verify`: the `commitHashE` axiom name appears in the axiom closure of each of these theorems.

**The truthful VCV-io statement** is sketched in `UserDataCommitVCVio.lean`:

```
∀ (uc₁ uc₂ : UserDataCommit), uc₁ ≠ uc₂ →
Pr[h₁ = h₂ | h₁ ← commitHashOC uc₁; h₂ ← commitHashOC uc₂]
≤ negligible(security_parameter)
```

where `commitHashOC` is the random-oracle-query version of `commitHash`.

**Why the demotion is not done in Step 2**: downstream consumers consume `commitHash_inj` as a deterministic equality, not as a probability bound. Migrating them requires lifting the protocol-layer theorems into `OracleComp` and carrying a collision-probability budget. That is a deep rewrite affecting theorem statements, not just substrate. It belongs to Steps 6+ of the refactor plan, after the rest of the crypto/attestation surface has been migrated and the rewrite cost can be amortised.

**Methodology takeaway**: the refactor methodology's honesty-lens correctly surfaced an impossible axiom that was previously buried in the trust-boundary. The surface change is small (1 axiom merged with another); the diagnostic change is significant — the methodology now visibly distinguishes "trust we accept" from "trust that is mathematically false but we accept anyway because the downstream proof shape forces it". Future Colosseum cycles should treat any axiom whose statement is mathematically impossible as a queue-for-demotion item, even when the deterministic shape is locally convenient.

This finding parallels the `session_confidentiality` name-vs-body gap surfaced in Step 1's review. Both are cases where the refactor did not *introduce* the gap; it made the gap visible. That is methodology-positive output.

## Axiom count delta (UserDataCommit module)

| Before | After | Reduction |
|---|---|---|
| 5 | 4 | -1 |

Original axioms (5): `DomainSep : Type`, `Addr : Type`, `Nonce : Type`, `commitHash : UserDataCommit → UserData`, `commitHash_inj : Function.Injective commitHash`.

Remaining axioms (4): `DomainSep : Type`, `Addr : Type`, `Nonce : Type`, `commitHashE : UserDataCommit ↪ UserData`.

`commitHash` and `commitHash_inj` are now derived (a `def` and a `theorem` respectively, both projecting from `commitHashE`).

### Note on plan target

The refactor plan (`.colosseum/refactor-plan-vcvio.md`) aimed at "5 axioms → ~1" via demotion of `commitHash_inj` to a negligibility theorem in VCV-io's `OracleComp`. That target is **deferred** at this step for the reasons documented in the honesty-lens finding above: downstream consumers ride on deterministic injectivity, not a probability bound. Migrating them belongs in Steps 6+. The 4-axiom realisation here:

- preserves the public API (no downstream theorem needed modification),
- bundles the two related axioms into one (small but real axiom-count reduction),
- promotes `commitHash` (def) and `commitHash_inj` (theorem) out of the axiom list,
- *and* explicitly surfaces the impossibility of the bundled axiom in the module docstring + change record.

Honest reduction beats forced reduction.

## Files changed

### Modified
- `proofs/lean/Specs/Quartz/Crypto/UserDataCommit.lean` — migration (5 axioms → 4 axioms + 1 def + 1 theorem on the new substrate; comprehensive honesty-lens docstring at file header)
- `proofs/lean/Specs.lean` — added import of `UserDataCommitVCVio` companion module

### Added
- `proofs/lean/Specs/Quartz/Crypto/UserDataCommitVCVio.lean` — companion module sketching the truthful random-oracle model and the negligibility honesty target. Documentary at this step (the negligibility theorem is unprovable on current carriers; sketched as `def commitHashOC` + module-docstring informal statement). Isolated from `UserDataCommit.lean` to keep VCV-io's transitive instance load out of the `Decidable` synthesis path.

### Not modified
- `proofs/lean/Specs/Quartz/Crypto/Ecies.lean` — frozen (Step 1 approved)
- `proofs/lean/Specs/Quartz/Crypto/EciesVCVio.lean` — frozen
- `proofs/lean/Specs/Quartz/Crypto/RawMessages.lean` — re-builds unchanged on the new substrate
- All `proofs/lean/Specs/Quartz/Protocol/*.lean` — re-build unchanged
- `proofs/lean/lean-toolchain`, `proofs/lean/lakefile.lean`, `proofs/lean/lake-manifest.json` — frozen from Step 0/1

## Affected verification surface

Quint: NA (no Quint changes — UserDataCommit refactor is Lean-only)

Lean (changes verified by `lake build` re-proving each theorem):
- [x] `Specs/Quartz/Crypto/UserDataCommit.lean` — `commitHash` (now `def`), `commitHash_inj` (now `theorem`), `pkOfUserData_commitHash` all built. `pkOfUserData_commitHash`'s proof body unchanged from pre-refactor — same `Classical.choose_spec` + `congrArg` chain works because `commitHash_inj` now has the same call shape as the old axiom.
- [x] `Specs/Quartz/Crypto/UserDataCommitVCVio.lean` — new companion module, builds and exposes `CommitHashSpec : OracleSpec UserDataCommit` and `commitHashOC : UserDataCommit → OracleComp CommitHashSpec UserData`.
- [x] `Specs/Quartz/Crypto/RawMessages.lean` — `userData_session_set_pub_key_binds_ecies`, `userData_session_create_extracts_placeholder` re-proved unchanged.
- [x] `Specs/Quartz/Crypto/TransferMessages.lean` — re-built unchanged
- [x] `Specs/Quartz/Crypto/AuctionMessages.lean` — re-built unchanged
- [x] `Specs/Quartz/Attestation/Dstack.lean` — re-built unchanged
- [x] `Specs/Quartz/Attestation/Zkdcap.lean` — re-built unchanged
- [x] `Specs/Quartz/Protocol/Handshake.lean` — `handshake_binds_ecies_key` re-proved unchanged
- [x] `Specs/Quartz/Protocol/Confidentiality.lean` — `session_confidentiality`, `session_confidentiality_via_extractor` re-proved unchanged
- [x] `Specs/Quartz/Protocol/CrossComponent.lean` — `cross_component_session_bind` re-proved unchanged
- [x] `Specs/Quartz/Protocol/Conservation.lean` — re-built unchanged
- [x] `Specs/Quartz/Protocol/AuctionDeterminism.lean` — re-built unchanged

Verus: NA
Kani: NA
Tests: NA
Compose: deferred — full ledger regeneration after Steps 3-6 complete.

## Verification result

`lake build` is green at HEAD:

```
Build completed successfully (2645 jobs).
```

The +7 job delta (2638 from Step 1 → 2645 here) reflects the new `UserDataCommitVCVio.lean` companion module and its build dependencies on `VCVio.OracleComp.QueryTracking.RandomOracle`.

Axiom inventory verified via `lean_verify`:

- `Specs.Quartz.Crypto.pkOfUserData_commitHash` axioms: `propext`, `Classical.choice`, `Quot.sound` (core Lean) + `Addr`, `DomainSep`, `Nonce`, `commitHashE` (this module) + `UserData` (Dstack) + `PubKey` (Ecies). **The old `commitHash` axiom is gone; `commitHash_inj` is gone**.
- `Specs.Quartz.Crypto.commitHash_inj` (now a theorem) axioms: same as above minus `propext`/`Classical.choice`/`Quot.sound` — pure derivation from `commitHashE`.
- `Specs.Quartz.Protocol.Confidentiality.session_confidentiality_via_extractor` shows `commitHashE` (not the old `commitHash`/`commitHash_inj` pair) in its axiom closure — confirms the propagation is clean.

## Classifier-routed failures encountered

Two minor issues during the spec-design loop, both resolved without revising the refactor approach:

1. **Initial `commitHash` defined as `def commitHash := commitHashE` without `noncomputable`** → Lean code generator complained about lowering an axiom-derived function. Classification: `prover_stuck` (cosmetic — code generator pass, not the logic kernel). Resolved by marking `commitHash` as `noncomputable`. Same workaround pattern as the existing `pkOfUserData` def in this file (which has been `noncomputable` from before this refactor).

2. **Companion module's first `commitHashOC` definition used `(OracleQuery.query (spec := CommitHashSpec) uc).liftM`** → unrecognised projection on `Sigma` because `OracleQuery` is defined as a `Sigma`-shape in this VCVio version, and `liftM` is not a `Sigma` field. Classification: `tool_mismatch` (my mental model of VCVio's `OracleQuery → OracleComp` lift was wrong; this VCVio version uses `MonadLift` instance + `OracleComp.lift` helper instead of a `.liftM` method). Resolved by switching to `OracleComp.lift (OracleQuery.query (spec := CommitHashSpec) uc)`.

Neither failure required spec relaxation or code revision — both were resolved by syntactic adjustments after consulting the VCVio source in `.lake/packages/VCVio/VCVio/OracleComp/OracleComp.lean`.

## Adversarial review

Not run in this loop. The honesty-lens finding above is itself an adversarial-style observation surfaced during the refactor: the bundled `commitHashE` axiom is mathematically false. A formal `colosseum-adversarial` pass against the migrated module would likely surface the same finding under a different lens (e.g. "what concrete attack does the deterministic-injectivity model under-specify?"). Deferred to post-refactor pass; the impossibility finding is already documented in the module docstring and this change record, so the adversarial review's primary output is already in the artifact set.

The companion-module sketch (`commitHashOC` + the informal `commitHash_collision_negl` statement) is **itself an adversarial target** at a different layer: does the random-oracle model faithfully capture what SHA-256-of-serde_json does in the Rust code? That gap is the second-layer trust claim that *would* survive demotion. Out of scope here; flagged for `colosseum-adversarial` once the negligibility theorem is actually proven.

## Outstanding follow-ups

### Immediate (Step 2 completion items not in scope)

None. Step 2 stops at "UserDataCommit re-proves cleanly".

### Remaining VCV-io refactor steps (Steps 3-6, per `.colosseum/refactor-plan-vcvio.md`)

- [ ] Step 3: migrate `Specs/Quartz/Crypto/RawMessages.lean` (12 axioms → ~3, largest reduction; will encounter the same "deterministic vs negligible" honesty-lens issue with `commitHashBytes_inj` — same parallel finding likely)
- [ ] Step 4: migrate `Specs/Quartz/Attestation/Dstack.lean` (8 → ~3)
- [ ] Step 5: migrate `Specs/Quartz/Attestation/Zkdcap.lean` (7 → ~3)
- [ ] Step 6: re-prove protocol layer on the new substrate — and **this is where the impossible-axiom demotion belongs**. Lifting `handshake_binds_ecies_key` and `session_confidentiality_via_extractor` into `OracleComp` with a collision-probability budget would let `commitHashE` be demoted to the truthful `commitHash_collision_negl` theorem sketched in `UserDataCommitVCVio.lean`. The companion module is built so that future Step 6 has a concrete handle.
- [ ] After all modules: run `colosseum-compose` to regenerate the integration ledger. Axiom inventory should drop from 40 → ~14 (the plan estimated ~11; the delta is the cumulative deferral of "forced reductions" — Step 1's Ecies came in at 4 vs plan's 1, Step 2 came in at 4 vs plan's 1, total +6 vs plan).

### Methodology questions raised

- **Impossible-axiom queue**: this refactor methodology should track "axioms whose mathematical content is known to be impossible" as a distinct sub-category in the ledger. Currently the ledger treats all axioms uniformly. Step 2 produced one entry for this queue (`commitHashE`); Step 3 will likely produce another (`commitHashBytes_inj` mirrors the same shape). The ledger should explicitly carry an "impossibility flag" per axiom and a forward pointer to the proposed demotion path.
- **Companion-module pattern is now load-bearing**: both Step 1 and Step 2 produced `*VCVio.lean` companion modules to keep VCVio's transitive instance load out of the `Decidable`-synthesis path. This is becoming a stable pattern. The methodology should document it explicitly (e.g. as a `colosseum-refactor` template note) before Step 3 starts so the next migrator knows to expect it.
- **Trust density (Step 2)**: UserDataCommit's trust density drops from 5/1 = 5.0 axioms-per-theorem to 4/3 ≈ 1.33 (now counting `commitHash_inj` and `commitHash` as derived theorems/defs respectively, alongside `pkOfUserData_commitHash`). The integration ledger should record this.

## Composition re-check

Not run. Full integration-ledger regeneration is deferred to post-refactor. Manual review at this checkpoint: composition theorems re-build cleanly. Specifically, `cross_component_session_bind` (the load-bearing composition theorem from the prior ledger) is built green via `Specs/Quartz/Protocol/CrossComponent.lean`. The substrate change in `UserDataCommit.lean` was deliberately public-API-preserving so this would hold without intervention; verified by `lake build`.

## Cross-step continuity (Step 1 → Step 2)

- Pattern established in Step 1 (companion `*VCVio.lean` module) applied verbatim in Step 2. Took ~2 tool calls to identify the right `OracleQuery → OracleComp` lift syntax in this VCVio version (vs. Step 1's `AsymmEncAlg`-based integration). No surprises.
- Step 1's "honest reduction beats forced reduction" principle (Ecies came in at 4 vs plan's 1) is applied identically here: UserDataCommit came in at 4 vs plan's 1, with the gap documented in the docstring + this change record as the load-bearing honesty-lens finding. Both modules are consistent in their explanation of why the plan's literal target was not pursued.
- Working tree is dirty (Step 1 + Step 2 changes layered). No git commits made. Step 1's frozen files (`Ecies.lean`, `EciesVCVio.lean`, `lakefile.lean`, `lean-toolchain`) are untouched.
