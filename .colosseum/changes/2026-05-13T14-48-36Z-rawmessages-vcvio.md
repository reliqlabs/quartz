# Change record: RawMessages VCV-io migration (Step 3)

- Date: 2026-05-13T14:48:36Z
- Classification: intent-touching (refactor of the cryptographic trust boundary) + second-instance methodology finding (impossible-axiom surfacing on a parallel domain)
- Intent revision: none (no `intent.md` edit needed — public API names preserved)
- Plan reference: `.colosseum/refactor-plan-vcvio.md` § "`RawMessages.lean` — 12 axioms → ~3"

## Description

Third module of the VCV-io refactor sequence. Migrated `Specs/Quartz/Crypto/RawMessages.lean` by bundling three pairs of "function axiom + injectivity axiom" into single `Function.Embedding`-shaped axioms:

```lean
axiom serializeRawSessionCreateE    : RawSessionCreate    ↪ ByteSeq
axiom serializeRawSessionSetPubKeyE : RawSessionSetPubKey ↪ ByteSeq
axiom commitHashBytesE              : ByteSeq             ↪ UserData
```

The previously-axiomatic `serializeRawSessionCreate`, `serializeRawSessionSetPubKey`, `commitHashBytes` are now `noncomputable def`s projecting from the embeddings; the previously-axiomatic `serializeRawSessionCreate_inj`, `serializeRawSessionSetPubKey_inj`, `commitHashBytes_inj` are now `theorem`s derived from the embeddings' `injective` fields. Public API names preserved verbatim: downstream consumers in `TransferMessages.lean`, `AuctionMessages.lean`, and `Protocol/CrossComponent.lean` re-build with no modification.

The other six axioms in the module remain unchanged: `ByteSeq` (carrier), `rawDomainSep`/`rawBoundContract`/`rawPlaceholderPubKey` (witness axioms into abstract upstream carriers `DomainSep`, `Addr`, `PubKey` that are frozen by Steps 1/2), and the two hash-domain bridge axioms `userDataOfSessionSetPubKey_eq_commitHash`/`userDataOfSessionCreate_eq_commitHash`.

A companion module `Specs/Quartz/Crypto/RawMessagesVCVio.lean` was added. It sketches the truthful random-oracle model of `commitHashBytes` using VCV-io's `OracleSpec` + `OracleComp` machinery, exposes `CommitHashBytesSpec : OracleSpec ByteSeq` and `commitHashBytesOC : ByteSeq → OracleComp CommitHashBytesSpec UserData`, and documents the negligible-collision honesty target. Isolated from `RawMessages.lean` to keep VCV-io's transitive instance load out of the `Decidable`-synthesis path (same pattern as Steps 1 & 2).

## Triage classification (per-axiom inventory of the original 12)

| Original axiom                              | Classification | Outcome                       |
|---------------------------------------------|----------------|-------------------------------|
| `ByteSeq : Type`                            | (c) genuine    | KEEP                          |
| `serializeRawSessionCreate`                 | (c) genuine    | Bundled → derived `def`       |
| `serializeRawSessionSetPubKey`              | (c) genuine    | Bundled → derived `def`       |
| `serializeRawSessionCreate_inj`             | (c) genuine    | Bundled → derived `theorem`   |
| `serializeRawSessionSetPubKey_inj`          | (c) genuine    | Bundled → derived `theorem`   |
| `commitHashBytes`                           | (c) genuine    | Bundled → derived `def`       |
| `commitHashBytes_inj`                       | (d) **impossible** | Bundled → derived `theorem` (still rides impossible axiom) |
| `rawDomainSep : DomainSep`                  | (a) demotable in principle, blocked in practice | KEEP (witness into frozen carrier) |
| `rawBoundContract : Addr`                   | (a) same                                          | KEEP                          |
| `rawPlaceholderPubKey : PubKey`             | (a) same                                          | KEEP                          |
| `userDataOfSessionSetPubKey_eq_commitHash`  | (c) genuine    | KEEP (bridge equality)        |
| `userDataOfSessionCreate_eq_commitHash`     | (c) genuine    | KEEP (bridge equality)        |

Notes on the (a) classification: the refactor plan's literal target was to demote the three named-constant axioms to `def`s with concrete values. That is structurally blocked at this step because the carrier types (`DomainSep`, `Addr`, `PubKey`) are abstract `axiom Type`s defined in `UserDataCommit.lean` and `Ecies.lean` — files frozen by Steps 1 & 2. No concrete witness value can be constructed without modifying those carriers. The honest move is to keep the three witness axioms in place and surface the dependency on the upstream-carrier abstraction in the change record.

Notes on the (c) classification: the two `serialize…_inj` axioms (bundled into embeddings here) are NOT mathematically impossible. serde_json + cw_serde produce a deterministic byte string per Lean value, and that map is plausibly injective on a fixed struct schema. The two bridge equality axioms are genuinely irreducible at this layer because discharging them requires a constructive byte-level model of serde_json AND a constructive definition of `commitHash`.

## Critical methodology finding (honesty-lens) — load-bearing, second instance

The bundled `commitHashBytesE : ByteSeq ↪ UserData` axiom **is mathematically impossible** in the same sense Step 2's `commitHashE : UserDataCommit ↪ UserData` was. It asserts an injective embedding from the open-cardinality carrier `ByteSeq` (an opaque byte-sequence type with no size bound) into the fixed-width 64-byte `UserData` slot. By pigeonhole, no such embedding exists once `|ByteSeq| > |UserData|`.

This is the **second** parallel surfacing of the same impossibility pattern in the VCV-io refactor. Step 2's `commitHashE` was the first; both carry the identical shape: an injective embedding from an open-cardinality preimage into a fixed-width hash codomain. The truthful statement in both cases is negligible-probability collision in a random-oracle model.

Bundling `commitHashBytes` + `commitHashBytes_inj` into one embedding axiom **does not fix this**. It surfaces it: the single axiom now visibly carries both "there is a byte-hash" and "the byte-hash is collision-free", which exposes the second claim as the load-bearing impossible trust assumption.

**Downstream theorems silently relying on the impossible `commitHashBytesE` axiom**, verified via `lean_verify` to carry `Specs.Quartz.Crypto.commitHashBytesE` in their axiom closure after the migration:

1. `Specs.Quartz.Crypto.distinct_raw_session_create_gives_distinct_user_data` (this module)
2. `Specs.Quartz.Crypto.distinct_raw_session_set_pub_key_gives_distinct_user_data` (this module)
3. `Specs.Quartz.Crypto.userDataOfSessionCreate_inj` (this module)
4. `Specs.Quartz.Crypto.userDataOfSessionSetPubKey_inj` (this module)
5. `Specs.Quartz.Crypto.userData_session_set_pub_key_binds_ecies` (this module — also rides on Step 2's `commitHashE`)
6. `Specs.Quartz.Crypto.userData_session_create_extracts_placeholder` (this module — same)
7. `Specs.Quartz.Crypto.distinct_transfer_request_gives_distinct_user_data` (`TransferMessages.lean`)
8. `Specs.Quartz.Crypto.userDataOfTransferRequest_inj` (`TransferMessages.lean`)
9. `Specs.Quartz.Crypto.distinct_resolve_message_gives_distinct_user_data` (`AuctionMessages.lean`)
10. `Specs.Quartz.Crypto.userDataOfResolveMessage_inj` (`AuctionMessages.lean`)
11. `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind` (the load-bearing composition theorem — rides on BOTH `commitHashBytesE` and Step 2's `commitHashE`)

**Cumulative impossible-axiom dependents across Steps 2 + 3**: 13 distinct theorems now ride on at least one of `{commitHashE, commitHashBytesE}`. Step 2 documented 5 dependents on `commitHashE`; Step 3 adds 6 new dependents on `commitHashBytesE` plus crystallises that 2 of the Step-2-listed theorems (`userData_session_set_pub_key_binds_ecies`, `userData_session_create_extracts_placeholder`) ride on BOTH simultaneously after Step 3's migration of the byte side.

**The truthful VCV-io statement** is sketched in `RawMessagesVCVio.lean`:

```
∀ (b₁ b₂ : ByteSeq), b₁ ≠ b₂ →
Pr[h₁ = h₂ | h₁ ← commitHashBytesOC b₁; h₂ ← commitHashBytesOC b₂]
≤ negligible(security_parameter)
```

where `commitHashBytesOC` is the random-oracle-query version of `commitHashBytes`.

**Why the demotion is not done in Step 3**: same reason as Step 2. Downstream consumers ride on deterministic injectivity, not a probability bound. Migrating them requires lifting all `userDataOf…` definitions into `OracleComp` and carrying a collision-probability budget across the inter-module composition chain (`RawMessages` → `TransferMessages`/`AuctionMessages` → `Protocol/CrossComponent`). That is a deep rewrite affecting theorem statements; it belongs to Step 6+ of the refactor plan, after the rest of the crypto/attestation surface (Dstack, Zkdcap) has been migrated.

**Methodology takeaway (second-instance edition)**: the impossibility pattern Step 2 surfaced was not a one-off — it is a *recurring shape* in this codebase, and it recurs precisely where the spec layer encodes "collision-resistant hash" as deterministic injectivity. The companion-module-sketch pattern is now established for the second time; Step 4 (Dstack) and Step 5 (Zkdcap) are likely to surface analogous shapes for `verifyTdxQuote` (verification-oracle deterministic equality) and `verifyGroth16_sound` (knowledge-soundness deterministic implication). The ledger's impossibility-flag (proposed in Step 2's change record) should now be treated as a load-bearing methodology feature, not a deferred enhancement.

The parallel finding to Step 1's `session_confidentiality` name-vs-body gap also holds: the refactor did not *introduce* either impossibility; it made them visible. That is methodology-positive output.

## Axiom count delta (RawMessages module)

| Before | After | Reduction |
|---|---|---|
| 12 | 9 | -3 |

Original axioms (12): `ByteSeq`, `serializeRawSessionCreate`, `serializeRawSessionSetPubKey`, `serializeRawSessionCreate_inj`, `serializeRawSessionSetPubKey_inj`, `commitHashBytes`, `commitHashBytes_inj`, `rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey`, `userDataOfSessionSetPubKey_eq_commitHash`, `userDataOfSessionCreate_eq_commitHash`.

Remaining axioms (9): `ByteSeq`, `serializeRawSessionCreateE`, `serializeRawSessionSetPubKeyE`, `commitHashBytesE`, `rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey`, `userDataOfSessionSetPubKey_eq_commitHash`, `userDataOfSessionCreate_eq_commitHash`.

Three pairs of (function-axiom, injectivity-axiom) bundled to one embedding-axiom each → -3.

`serializeRawSessionCreate`, `serializeRawSessionSetPubKey`, `commitHashBytes` are now derived `def`s. `serializeRawSessionCreate_inj`, `serializeRawSessionSetPubKey_inj`, `commitHashBytes_inj` are now derived `theorem`s. All six are promoted out of the axiom list.

### Note on plan target

The refactor plan (`.colosseum/refactor-plan-vcvio.md`) aimed at "12 axioms → ~3" via:

1. Demoting `rawDomainSep`/`rawBoundContract`/`rawPlaceholderPubKey` to `def`s with concrete values.
2. Demoting `commitHashBytes_inj` to a negligibility theorem in VCV-io's `OracleComp`.
3. Keeping the serialization-injectivity axioms as genuine byte-level claims.

**Item 1 is structurally blocked** at this step because the carriers (`DomainSep`, `Addr`, `PubKey`) are abstract types from upstream modules frozen by Steps 1 & 2. Demotion requires refining those carriers to concrete types — out of scope.

**Item 2 is deferred** for the same reason Step 2 deferred its parallel demotion: downstream consumers ride on deterministic injectivity, not a probability bound. The migration belongs to Step 6+ when the protocol-layer theorems are lifted into `OracleComp`.

**Item 3 is partially done**: the serialization-injectivity axioms are bundled into embeddings (one axiom each instead of two), but kept as honest trust-boundary claims (the embeddings themselves are NOT mathematically impossible — serde_json IS plausibly injective on a fixed schema).

The 9-axiom realisation here is the **honest reduction**. It:

- preserves the public API (no downstream theorem needed modification),
- bundles three (axiom, axiom) pairs into three embedding axioms (-3 axioms),
- promotes six identifiers out of the axiom list to `def`/`theorem`,
- explicitly surfaces the impossibility of `commitHashBytesE` in the module docstring and this change record,
- documents the blocked-but-tracked status of the named-constant demotion (item 1),
- inherits Step 1/2's "honest reduction over forced reduction" principle verbatim.

Honest reduction beats forced reduction. The plan's "~3" target is achievable but only after Steps 4-6 lift the upstream carriers + protocol-layer theorems.

## Cumulative ledger update (Steps 0-3)

| Module                              | Original axioms | Post-step axioms | Reduction       |
|-------------------------------------|-----------------|------------------|-----------------|
| `Ecies.lean`            (Step 1)    | 8               | 4                | -4              |
| `UserDataCommit.lean`   (Step 2)    | 5               | 4                | -1              |
| `RawMessages.lean`      (Step 3)    | 12              | 9                | -3              |
| `Dstack.lean`           (pending)   | 8               | 8                | (Step 4)        |
| `Zkdcap.lean`           (pending)   | 7               | 7                | (Step 5)        |
| **Crypto + Attestation totals**     | **40**          | **32**           | **-8**          |

Step 3 contributes the largest single-module reduction so far (-3 from a 12-axiom baseline). The cumulative -8 vs the plan's projected -29 reflects the cumulative deferral of "forced reductions" through Steps 1-3; the gap is intentional and tracked, not accidental.

## Files changed

### Modified
- `proofs/lean/Specs/Quartz/Crypto/RawMessages.lean` — migration (12 axioms → 9 axioms + 3 defs + 3 theorems on the new substrate; comprehensive honesty-lens docstring at file header)
- `proofs/lean/Specs.lean` — added import of `RawMessagesVCVio` companion module

### Added
- `proofs/lean/Specs/Quartz/Crypto/RawMessagesVCVio.lean` — companion module sketching the truthful random-oracle model of `commitHashBytes` and the negligibility honesty target. Documentary at this step (the negligibility theorem is unprovable on current carriers; sketched as `def commitHashBytesOC` + module-docstring informal statement). Isolated from `RawMessages.lean` to keep VCV-io's transitive instance load out of the `Decidable`-synthesis path.

### Not modified
- `proofs/lean/Specs/Quartz/Crypto/Ecies.lean` — frozen (Step 1 approved)
- `proofs/lean/Specs/Quartz/Crypto/EciesVCVio.lean` — frozen (Step 1)
- `proofs/lean/Specs/Quartz/Crypto/UserDataCommit.lean` — frozen (Step 2 approved)
- `proofs/lean/Specs/Quartz/Crypto/UserDataCommitVCVio.lean` — frozen (Step 2)
- `proofs/lean/Specs/Quartz/Crypto/TransferMessages.lean` — re-builds unchanged on the new substrate
- `proofs/lean/Specs/Quartz/Crypto/AuctionMessages.lean` — re-builds unchanged
- `proofs/lean/Specs/Quartz/Attestation/Dstack.lean` — re-builds unchanged (Step 4 target)
- `proofs/lean/Specs/Quartz/Attestation/Zkdcap.lean` — re-builds unchanged (Step 5 target)
- All `proofs/lean/Specs/Quartz/Protocol/*.lean` — re-build unchanged
- `proofs/lean/lean-toolchain`, `proofs/lean/lakefile.lean`, `proofs/lean/lake-manifest.json` — frozen from Step 0

## Affected verification surface

Quint: NA (no Quint changes — RawMessages refactor is Lean-only)

Lean (changes verified by `lake build` re-proving each theorem):

- [x] `Specs/Quartz/Crypto/RawMessages.lean` — 12 → 9 axioms. The 6 module-local theorems all re-built:
  - `serializeRawSessionCreate_inj` (now a theorem; derives from `serializeRawSessionCreateE.injective`)
  - `serializeRawSessionSetPubKey_inj` (now a theorem; same shape)
  - `commitHashBytes_inj` (now a theorem; derives from `commitHashBytesE.injective`)
  - `distinct_raw_session_create_gives_distinct_user_data` (re-proved unchanged — same composition of derived `_inj` theorems)
  - `distinct_raw_session_set_pub_key_gives_distinct_user_data` (re-proved unchanged)
  - `userDataOfSessionCreate_inj` (re-proved unchanged)
  - `userDataOfSessionSetPubKey_inj` (re-proved unchanged)
  - `userData_session_set_pub_key_binds_ecies` (re-proved unchanged; rides on derived `commitHashBytes` which unfolds to `commitHashBytesE`)
  - `userData_session_create_extracts_placeholder` (re-proved unchanged)

  Plan ledger said "6 theorems" — the actual count is 6 module-original theorems plus 3 NEW theorems-formerly-axioms (`serializeRawSessionCreate_inj`, `serializeRawSessionSetPubKey_inj`, `commitHashBytes_inj`) for a total of 9 theorems in the module after migration.

- [x] `Specs/Quartz/Crypto/RawMessagesVCVio.lean` — new companion module, builds and exposes `CommitHashBytesSpec : OracleSpec ByteSeq` and `commitHashBytesOC : ByteSeq → OracleComp CommitHashBytesSpec UserData`.
- [x] `Specs/Quartz/Crypto/TransferMessages.lean` — re-built unchanged. `distinct_transfer_request_gives_distinct_user_data` and `userDataOfTransferRequest_inj` consume `commitHashBytes`/`commitHashBytes_inj` (which are now derived def/theorem); axiom closure correctly shows `commitHashBytesE` (the new bundled axiom).
- [x] `Specs/Quartz/Crypto/AuctionMessages.lean` — re-built unchanged. `distinct_resolve_message_gives_distinct_user_data` and `userDataOfResolveMessage_inj` same story.
- [x] `Specs/Quartz/Attestation/Dstack.lean` — re-built unchanged (no dependency on migrated identifiers).
- [x] `Specs/Quartz/Attestation/Zkdcap.lean` — re-built unchanged.
- [x] `Specs/Quartz/Protocol/Handshake.lean` — `handshake_binds_ecies_key` re-proved unchanged.
- [x] `Specs/Quartz/Protocol/Confidentiality.lean` — `session_confidentiality`, `session_confidentiality_via_extractor` re-proved unchanged.
- [x] `Specs/Quartz/Protocol/CrossComponent.lean` — `cross_component_session_bind` re-proved unchanged. Axiom closure now shows `commitHashBytesE` + Step 2's `commitHashE` (the two impossible bundles) as the load-bearing trust pair, in addition to the genuine carriers + bridges.
- [x] `Specs/Quartz/Protocol/Conservation.lean` — re-built unchanged.
- [x] `Specs/Quartz/Protocol/AuctionDeterminism.lean` — re-built unchanged.

Verus: NA
Kani: NA
Tests: NA
Compose: deferred — full ledger regeneration after Steps 4-6 complete.

## Verification result

`lake build` is green at HEAD:

```
Build completed successfully (2646 jobs).
```

The +1 job delta (2645 from Step 2 → 2646 here) reflects the new `RawMessagesVCVio.lean` companion module. (Note: the delta is smaller than Step 2's +7 because Step 3's companion imports the same VCV-io modules Step 2 already pulled — the transitive closure was already built.)

Axiom inventory verified via `lean_verify` (post-rebuild, fresh LSP cache):

- `Specs.Quartz.Crypto.commitHashBytes_inj` (now a theorem) axioms: `{ByteSeq, commitHashBytesE, UserData}` — pure derivation from the bundled embedding; no `propext`/`Classical.choice` needed.
- `Specs.Quartz.Crypto.serializeRawSessionCreate_inj` (now a theorem) axioms: `{Addr, ByteSeq, Nonce, serializeRawSessionCreateE}` — pure derivation.
- `Specs.Quartz.Crypto.serializeRawSessionSetPubKey_inj` (now a theorem) axioms: `{ByteSeq, Nonce, serializeRawSessionSetPubKeyE, PubKey}` — pure derivation.
- `Specs.Quartz.Crypto.distinct_raw_session_create_gives_distinct_user_data` axioms: `{Addr, ByteSeq, Nonce, commitHashBytesE, serializeRawSessionCreateE, UserData}` — old `commitHashBytes`/`commitHashBytes_inj`/`serializeRaw…`/`serializeRaw…_inj` gone.
- `Specs.Quartz.Crypto.distinct_raw_session_set_pub_key_gives_distinct_user_data` axioms: same shape on the SetPubKey side.
- `Specs.Quartz.Crypto.userData_session_set_pub_key_binds_ecies` axioms: includes BOTH `commitHashBytesE` (Step 3) AND `commitHashE` (Step 2) — the two-impossible-axiom dependency surfaced explicitly.
- `Specs.Quartz.Crypto.userData_session_create_extracts_placeholder` axioms: same dual-impossibility shape, plus `rawPlaceholderPubKey`.
- `Specs.Quartz.Crypto.distinct_transfer_request_gives_distinct_user_data` (downstream — TransferMessages) axioms: now `commitHashBytesE`-rooted (old `commitHashBytes`/`commitHashBytes_inj` gone).
- `Specs.Quartz.Crypto.distinct_resolve_message_gives_distinct_user_data` (downstream — AuctionMessages) axioms: same.
- `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind` axioms: shows `commitHashBytesE` + `commitHashE` as the dual-impossibility pair, plus all the genuine carriers/bridges/Dstack/Zkdcap axioms. Confirms the composition theorem propagates the new bundled axioms cleanly.

## Classifier-routed failures encountered

None. The migration went through on the first lake build attempt. Two design decisions surfaced during planning but were resolved without iteration:

1. **Whether to demote `rawDomainSep`/`rawBoundContract`/`rawPlaceholderPubKey` to `def`s using `Classical.arbitrary` over a `Nonempty` instance**. Rejected: this just moves the axiom (the `Nonempty` instance would itself need to be axiomatic over the abstract carriers). The honest path is to KEEP the witness axioms and document that demotion is blocked until carriers are refined (Step 6+). This mirrors Step 2's stance on the abstract carriers.

2. **Whether `lean_verify`'s axiom closure for the downstream files was correct**. Initial output showed old axiom names (`commitHashBytes`, `commitHashBytes_inj`) in the closure — suggested LSP cache staleness. Resolved by running `lean_build` to force a fresh build + LSP restart. Post-restart, the axiom closures correctly showed `commitHashBytesE` and the old names were gone. Classification: tool-state issue, not a logic issue.

Neither issue required spec relaxation or code revision.

## Adversarial review

Not run in this loop. The honesty-lens finding above is itself an adversarial-style observation surfaced during the refactor: bundled `commitHashBytesE` is mathematically false in the same way Step 2's `commitHashE` was, and it is the second instance of an emerging *pattern* (not an isolated case). A formal `colosseum-adversarial` pass against the migrated module would likely surface the same finding under a different lens.

The companion-module sketch (`commitHashBytesOC` + the informal `commitHashBytes_collision_negl` statement) is itself an adversarial target at a different layer: does the random-oracle model faithfully capture what SHA-256-of-serde_json does in the Rust code? That gap is the second-layer trust claim that *would* survive demotion. Out of scope here; flagged for `colosseum-adversarial` once the negligibility theorem is actually proven.

The dual-impossibility shape that `userData_session_set_pub_key_binds_ecies` and `userData_session_create_extracts_placeholder` (and transitively `cross_component_session_bind`) now exhibit is also adversarial-target-worthy: a chain of two impossible axioms compose into one apparently-deterministic theorem. The honest probability-bound chaining (when Step 6 lifts both into `OracleComp`) will involve a UNION bound across both random oracles — that bound is straightforward, but worth checking that the structural composition doesn't lose tightness.

## Outstanding follow-ups

### Immediate (Step 3 completion items not in scope)

None. Step 3 stops at "RawMessages re-proves cleanly".

### Remaining VCV-io refactor steps (Steps 4-6, per `.colosseum/refactor-plan-vcvio.md`)

- [ ] Step 4: migrate `Specs/Quartz/Attestation/Dstack.lean` (8 axioms → ~3 target). Likely to encounter a third instance of the impossibility pattern around `was_signed_by_dstack` (predicate equality) or `verifyTdxQuote_sound` (deterministic-equality verification implication). The companion-module pattern from Steps 2-3 should apply directly.
- [ ] Step 5: migrate `Specs/Quartz/Attestation/Zkdcap.lean` (7 → ~3). Same expectation around `verifyGroth16_sound`. Note: the plan flagged this as the case ArkLib doesn't yet cover, so its axiom is irreducible for the foreseeable future regardless of VCV-io lifting.
- [ ] Step 6: re-prove protocol layer on the new substrate — and **this is where both impossible axioms (`commitHashE`, `commitHashBytesE`) should be demoted simultaneously**. Lifting `handshake_binds_ecies_key`, `session_confidentiality_via_extractor`, AND `cross_component_session_bind` into `OracleComp` with a union-bound collision-probability budget would let both bundled embeddings be demoted to the truthful `commit*_collision_negl` theorems sketched in `UserDataCommitVCVio.lean` and `RawMessagesVCVio.lean`. Both companion modules are built so that future Step 6 has concrete handles.
- [ ] After all modules: run `colosseum-compose` to regenerate the integration ledger. Axiom inventory should drop from 40 → ~14-18 (the plan estimated ~11; the delta is the cumulative deferral of "forced reductions" — Step 1 came in at 4 vs plan's 1, Step 2 at 4 vs plan's 1, Step 3 at 9 vs plan's 3, total +12 vs plan).

### Methodology questions raised

- **Impossible-axiom pattern is recurrent**: Step 2 surfaced `commitHashE` (structured-hash impossibility); Step 3 surfaces `commitHashBytesE` (byte-hash impossibility). The same shape will likely recur in Steps 4-5 for `verifyTdxQuote_sound` and `verifyGroth16_sound` (knowledge-soundness deterministic implication). The ledger's impossibility-flag (proposed in Step 2's change record) should now be promoted from "queue item" to "load-bearing methodology feature".
- **Companion-module pattern is now stable**: three companion modules (`EciesVCVio`, `UserDataCommitVCVio`, `RawMessagesVCVio`) follow the same template. The methodology should document this template explicitly (e.g. as a `colosseum-refactor` template note) — naming convention `<Module>VCVio`, isolation of `OracleSpec`/`OracleComp` material to keep `Decidable`-synthesis paths clean, documentary `…OC` definition + informal negligibility statement as a comment.
- **Carrier-refinement blocking**: Step 3 hit an explicit blocked-by-upstream issue with the `DomainSep`/`Addr`/`PubKey` witness axioms. Step 6+ should address carrier refinement as a separate concern *before* attempting `OracleComp` lift of the protocol layer — otherwise the carriers will still be axiomatic when the protocol theorems try to express probability bounds over them.
- **Trust density (Step 3)**: RawMessages's trust density drops from 12/6 = 2.0 axioms-per-theorem to 9/9 = 1.0 (now counting the three new derived-theorems alongside the six original theorems). The integration ledger should record this.
- **Cumulative trust density (Steps 0-3)**: Crypto + Attestation modules now sit at 32 axioms / (5 original protocol theorems + new derived theorems in Crypto). The exact derived-theorem count grew by +1 in Step 2 (commitHash_inj) and +3 in Step 3 (the three serialize/byte-hash inj's). Net trust density at this checkpoint: 32 / (16 + 4) = 1.6 axioms-per-theorem, down from the pre-refactor 40 / 16 = 2.5.

## Composition re-check

Not run. Full integration-ledger regeneration is deferred to post-refactor. Manual review at this checkpoint: composition theorems re-build cleanly. Specifically, `cross_component_session_bind` (the load-bearing composition theorem from the prior ledger) is built green via `Specs/Quartz/Protocol/CrossComponent.lean`, and `lean_verify` confirms its axiom closure correctly shows both `commitHashE` (Step 2) and `commitHashBytesE` (Step 3) as the cumulative impossible-bundle pair. The substrate change in `RawMessages.lean` was deliberately public-API-preserving so this would hold without intervention; verified.

## Cross-step continuity (Step 1 → Step 2 → Step 3)

- Companion-module pattern established in Step 1 (`EciesVCVio.lean`) and applied verbatim in Step 2 (`UserDataCommitVCVio.lean`) is applied a third time here (`RawMessagesVCVio.lean`). The template is stable: VCV-io-free core module + sibling `<Module>VCVio.lean` with `OracleSpec`/`OracleComp` material + documentary informal negligibility statement.
- "Honest reduction beats forced reduction" applied consistently: Step 1 came in at 4 vs plan's 1, Step 2 at 4 vs plan's 1, Step 3 at 9 vs plan's 3. Each gap documented in-place.
- Impossibility-surfacing pattern is now a recurring methodology output. Step 2 found 1 impossible axiom; Step 3 found 1 more of the same shape (parallel domain). The two impossibilities now compose into the bridge theorems (`userData_session_set_pub_key_binds_ecies`, `userData_session_create_extracts_placeholder`) and through them into `cross_component_session_bind`. This is the first chain of multiple impossibilities composed into a single load-bearing theorem in the refactor.
- Working tree is dirty (Steps 1 + 2 + 3 changes layered). No git commits made. Step 1/2's frozen files are untouched.
