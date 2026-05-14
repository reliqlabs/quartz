# Colosseum integration ledger — Quartz (post-VCVio refactor)

> **CORRECTION 2026-05-14 (initial)**: Round A adversarial review (`.colosseum/attacks/lean-negl-lifts-2026-05-14/`) returned BREAKS on the content-phase lift. The 8 `_negl` theorems were content-free tautologies — each binding its protocol-fail advantage as a free `ℝ≥0∞` function symbol with no defining equation; proofs went through via `negligible_of_le` + `negligible_add` (closure properties of `negligible`), proving only that the negligible class is closed under pointwise domination and finite sums.
>
> **UPDATE 2026-05-14 (post-cycle-6.4–6.11)**: Round A's structural critique has been substantially addressed. Cycles 6.4–6.11 (8 commits) replaced every `_negl` lift's free-symbol advantage with a `Pr[…]`-based `def`, replaced caller-supplied bounds with proven bounds via `probEvent_mono` + `probEvent_bind_pure_comp`, and made the bundle structure honest about which axioms are probabilistic-failure modes vs. unconditional carrier-substrate. Round A attacks #1 (free-symbol tautology), #2 (Trojan h_bound), #3 (no reduction relation), #4 (disjunction-decomposition cosmetic at terminal), and #11 (over-quantified signature) are structurally closed.
>
> Round A attacks #5 (`IsPPT := True` vacuity), #6 (`ProtocolSpec` unused), #8 (Option-(b) for `commitHashE`) remain open — they require deeper refactors than def-tying (substituting classical axioms with probabilistic hypotheses), and are queued as cycles 6.12–6.14.
>
> **New methodology finding (cycle-6.4–6.11 sequence)**: 7 of 8 lifts were over-bundled in the original Step 6.0–6.3 work. The original plan classified lifts by the union-bound shape implied by an axiom count; the actual probabilistic-failure modes in each classical proof are fewer than the axiom count suggests. The terminal lift (5-summand union bound in the original) has only one probabilistic-failure mode (Groth16-soundness) under the current carrier model — the other 4 axioms are consumed unconditionally in the classical proof and do not lift to probabilistic hypotheses. Worth back-porting to colosseum methodology v0.2 as a new ask: **bundle-count derivation must come from per-conjunct failure-mode analysis of the classical proof, not from a static axiom-count classifier**.
>
> Specific retractions remain inline below, each marked with `[RETRACTED 2026-05-14]`. The corrective trail across initial retraction → cycle 6.4–6.11 sequence is visible in `.colosseum/changes/2026-05-14T*-cycle-6.{4..11}-*.md`. See also the synthesis at `.colosseum/attacks/lean-negl-lifts-2026-05-14/synthesis.md`.

- Project: /Users/mvid/Development/reliq/quartz
- Generated: 2026-05-13T16-30-00Z (Step 7, post-Step-6.3 regeneration)
- Compared against: prior emission 2026-05-12T12:57:07Z (40 axioms, 5 composition theorems, pre-VCVio)
- Generator: `colosseum-compose` skill (manual walk; methodology v0.1; v0.2 asks below)
- Build status: `lake build` green at 2667 jobs (Step 6.3 baseline)
- Phase: ~~end of VCVio refactor Steps 0-6.3 (form-phase axiom reduction 40 → 26 = -14 / -35%; content-phase lift of all 8 protocol theorems complete)~~ — **[UPDATED 2026-05-14]** form-phase reduction holds (40 → 26 axioms); content-phase lift sequence (cycles 6.4–6.11) complete, all 8 `_negl` theorems def-tied with content-bearing `Pr[…]`-based advantages and proven (not assumed) pointwise bounds. Refactor is at "form-phase + def-tying content-phase complete; carrier-refinement / IsPPT-PolyQueries / Option-(b)-commitHash content-phase pending (cycles 6.12–6.14)".

## Audit-ready trust-boundary summary (60-second read) — [RETRACTED 2026-05-14, see banner]

After the VCVio refactor, Quartz's Lean trust boundary decomposes into three honest classes. **Honest carriers** (14 opaque types + 3 named-constant witnesses + 5 function/predicate signatures = 22 of 26 axioms) are non-cryptographic abstractions over types and named values from the deployed Rust stack (k256/ECIES key shapes, serde_json byte sequences, DCAP quote bytes, gnark vkey/proof/input bytes). They compile to nothing — they are the parametric model the Lean tree refines. **Honest cryptographic assumptions** (4 bundled record axioms — `commitHashE`, `commitHashBytesE`, `tdxVerifier`, `groth16Verifier`) name real cryptographic / attestation primitives; two are spec-impossible-as-stated injections (pigeonhole bound on hash codomain), two are classical-Prop verification implications dropping computational-soundness qualifiers. Each is consumed by the protocol-layer classical theorems but is **shadowed at the content layer** by 8 `_negl` lifts in `ProtocolVCVio*.lean` that re-state the trust claim as parametric negligibility hypotheses (zero `sorry`). **Externally deferred** discharges (5 negligibility budgets feeding the `cross_component_session_bind` 5-summand union bound) point to: ArkLib Groth16 KS coverage (upstream), a Lean reference DCAP verifier (separate effort), a PCK-signature unforgeability reduction (Intel-spec + crypto-lib), and VCVio random-oracle + birthday bound after `[Fintype UserData]` carrier refinement. The protocol layer's verified surface is now: 5 honest cryptographic assumptions on real-world primitives, plus standard carrier axioms, plus a parametric union-bound composition — *none* of the 8 lifted theorems carry a bundle axiom in its `_negl` closure (only carriers + standard logic + the parametric negligibility hypotheses).

## Per-axiom inventory (26 axioms, 4-bucket classification)

Categories: **(a)** demotable-to-def-or-dead · **(b)** demotable-to-derived-theorem · **(c)** honest-computational-assumption · **(d)** impossibility-or-over-strength

| # | Axiom | Module | Cat | Sub-tag | Discharge path | Carried by |
|---|-------|--------|-----|---------|----------------|------------|
| 1 | `PrivKey : Type` | Ecies | (c) | carrier | k256/ECIES Rust crate type model | all 8 lifted (carrier) |
| 2 | `PubKey : Type` | Ecies | (c) | carrier | k256 Rust crate type model | all 8 lifted (carrier) |
| 3 | `Plaintext : Type` | Ecies | (c) | carrier | application-level type model | all 8 lifted (carrier) |
| 4 | `keyOf : PrivKey → PubKey` | Ecies | (c) | carrier | deterministic key derivation, k256 spec | classical chain only (not in `_negl` closures) |
| 5 | `DomainSep : Type` | UserDataCommit | (c) | carrier | named-constant byte-string type | 7 of 8 lifted (carrier; not in cross_transfers/auction `_negl`) |
| 6 | `Addr : Type` | UserDataCommit | (c) | carrier | Cosmos chain-address type model | all 8 lifted (carrier) |
| 7 | `Nonce : Type` | UserDataCommit | (c) | carrier | session-nonce type model | 6 of 8 lifted (carrier; not in cross_transfers/auction `_negl` nor `verifyGroth16_yields_decoded_negl`) |
| 8 | `commitHashE : UserDataCommit ↪ UserData` | UserDataCommit | (d) | pigeonhole-impossible | concrete `H : UC → UD` carrier + `randomOracle` birthday bound, requires `[Fintype UserData]` | classical chain (4 theorems); shadowed in `_negl` by `CommitHashCollisionAdv` hypothesis |
| 9 | `ByteSeq : Type` | RawMessages | (c) | carrier | serde_json byte-sequence type model | 3 of 8 lifted (carrier; cross_transfers, auction, cross_component_session_bind) |
| 10 | `serializeRawSessionCreateE : RawSessionCreate ↪ ByteSeq` | RawMessages | (c) | carrier (genuine injectivity claim) | serde_json byte layout determinism on fixed struct schema | classical chain only |
| 11 | `serializeRawSessionSetPubKeyE : RawSessionSetPubKey ↪ ByteSeq` | RawMessages | (c) | carrier (genuine injectivity claim) | serde_json byte layout determinism on fixed struct schema | classical chain + cross_component_session_bind `_classical` |
| 12 | `commitHashBytesE : ByteSeq ↪ UserData` | RawMessages | (d) | pigeonhole-impossible | concrete `H_b : ByteSeq → UD` carrier + `randomOracle` birthday bound | classical chain (3 theorems); shadowed in `_negl` by `CommitHashBytesCollisionAdv` hypothesis |
| 13 | `rawDomainSep : DomainSep` | RawMessages | (a) | blocked-by-abstract-carrier | demote to `def` once `DomainSep` carrier refined to concrete byte string | classical chain + cross_component_session_bind `_classical` |
| 14 | `rawBoundContract : Addr` | RawMessages | (a) | blocked-by-abstract-carrier | demote to `def` once `Addr` carrier refined to concrete bech32 string | classical chain + cross_component_session_bind `_classical` |
| 15 | `rawPlaceholderPubKey : PubKey` | RawMessages | (a) | blocked-by-abstract-carrier | demote to `def` once `PubKey` carrier refined to concrete bytes | classical chain only |
| 16 | `userDataOfSessionSetPubKey_eq_commitHash` | RawMessages | (c) | carrier (genuine bridge equality) | constructive byte-level model of serde_json AND `commitHash` | classical chain + cross_component_session_bind `_classical` |
| 17 | `userDataOfSessionCreate_eq_commitHash` | RawMessages | (c) | carrier (genuine bridge equality) | same — constructive byte-level + commit model | classical chain only |
| 18 | `TdxQuote : Type` | Dstack | (c) | carrier | DCAP-quote-v4 wire-format byte-blob model | all 8 lifted (carrier) |
| 19 | `MrEnclave : Type` | Dstack | (c) | carrier | MRTD / RTMR digest byte-string model | 7 of 8 lifted (carrier; not in `verifyGroth16_yields_decoded_negl`) |
| 20 | `UserData : Type` | Dstack | (c) | carrier | 64-byte report_data slot model | all 8 lifted (carrier) |
| 21 | `was_signed_by_dstack : TdxQuote → Prop` | Dstack | (c) | carrier (off-chain reality witness) | irreducible — propositional witness for "a real dstack TEE produced this quote" | classical chain only (sidestepped by `IsPPT`/`Classical.propDecidable` in `_negl`) |
| 22 | `tdxVerifier : TdxVerifier` | Dstack | (d) | classically-over-strong-single-negligibility (sound) + preconditional (complete) | (sound) PCK-signature unforgeability reduction; (complete) explicit collateral-freshness / non-revocation preconditions; both require Lean reference DCAP verifier | classical chain (7 theorems); shadowed in `_negl` by `TdxVerifierSoundAdv` hypothesis |
| 23 | `Groth16Proof : Type` | Zkdcap | (c) | carrier | BN254 proof byte-string model | all 8 lifted (carrier) |
| 24 | `PublicInputs : Type` | Zkdcap | (c) | carrier | concatenated 32-byte fr.Element values | all 8 lifted (carrier) |
| 25 | `VKey : Type` | Zkdcap | (c) | carrier | gnark verification-key byte-string model | 1 of 8 lifted (only in cross_component_session_bind `_negl` carrier; not in others) |
| 26 | `groth16Verifier : Groth16Verifier` | Zkdcap | (d) | classically-over-strong-doubled-negligibility | (KS half) ArkLib Groth16 reduction; (circuit-eq half) Lean reference DCAP verifier + circuit-equivalence theorem; **decomposes into 2 summands at the terminal lift** | classical chain (8 theorems); shadowed in `_negl` by `Groth16SoundAdv` (intermediate) or `Groth16KSAdv` + `CircuitEqAdv` (terminal) hypotheses |

### Bucket totals (26 axioms)

- **(a) demotable-to-def-or-dead** — 3 (rawDomainSep, rawBoundContract, rawPlaceholderPubKey); all blocked-by-abstract-carrier
- **(b) demotable-to-derived-theorem** — 0 (all demotables of this kind were already discharged in Steps 1-5: `roundtrip`, `commitHash_inj`, `commitHashBytes_inj`, `serializeRaw*_inj`, `verifyTdxQuote_sound`/`_complete`, `verifyGroth16_sound`)
- **(c) honest-computational-assumption** — 19 (14 carriers + 3 function/predicate signatures + 2 bridge equalities)
- **(d) impossibility-or-over-strength** — 4 (`commitHashE`, `commitHashBytesE`, `tdxVerifier`, `groth16Verifier`); each shadowed at content layer by parametric `_negl` hypothesis

### Sub-bucket (d) sub-taxonomy

- (d-pigeonhole-impossible): 2 — `commitHashE`, `commitHashBytesE`
- (d-classically-over-strong-single-negligibility): 1 — `tdxVerifier.sound`
- (d-classically-over-strong-preconditional): 1 — `tdxVerifier.complete`
- (d-classically-over-strong-doubled-negligibility): 1 — `groth16Verifier.sound`

(`tdxVerifier` carries two distinct (d) sub-tags inside one record axiom.)

## Lifted theorem index (8 of 8, all `_negl`-shadowed) — [PARTIALLY RETRACTED 2026-05-14]

> The 8 lifted theorems exist and type-check, but their `_negl` forms bind the protocol-fail advantage as a free `ℝ≥0∞` function symbol rather than a defined probability event. Round A established that each can be vacuously satisfied by instantiating the fail-advantage to `0`. Reading this section: the theorem *names* and *bundle composition* below are correct; the trust claim attached to each (that the `_negl` form constitutes a content-bearing parametric security reduction) is retracted pending the def-tying refactor.

| # | Theorem | Module | Bundle card. | Summands in union bound | `_negl` closure | `_classical` closure |
|---|---------|--------|--------------|-------------------------|-----------------|----------------------|
| 1 | `verifyGroth16_yields_decoded_negl` | ProtocolVCVio | single | 1 | carriers (Groth16Proof, PublicInputs) + std logic | `tdxVerifier` + `groth16Verifier` + carriers |
| 2 | `handshake_sound_negl` | ProtocolVCVioDual | dual | 2 (groth16 + tdx) | carriers (MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs) + std logic | `tdxVerifier` + `groth16Verifier` + carriers |
| 3 | `handshake_binds_ecies_key_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashE-CR) | carriers (Addr, DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs, Plaintext, PrivKey, PubKey) + std logic | `tdxVerifier` + `groth16Verifier` + `commitHashE` + carriers |
| 4 | `session_confidentiality_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashE-CR) | same as #3 | `tdxVerifier` + `groth16Verifier` + `commitHashE` + carriers |
| 5 | `session_confidentiality_via_extractor_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashE-CR) | same as #3 | `tdxVerifier` + `groth16Verifier` + `commitHashE` + carriers |
| 6 | `cross_component_transfers_conservation_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashBytesE-CR) | carriers (Addr, ByteSeq, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs) + std logic | `tdxVerifier` + `groth16Verifier` + `commitHashBytesE` + carriers + `serializeTransferRequest`, `Conservation.addrOf` |
| 7 | `cross_component_auction_winner_determinism_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashBytesE-CR) | same as #6 | `tdxVerifier` + `groth16Verifier` + `commitHashBytesE` + carriers + `serializeResolveMessage`, `Conservation.addrOf`, `AuctionDeterminism.decryptBid` |
| 8 | `cross_component_session_bind_negl` | ProtocolVCVioQuad | quadruple | **5** (groth16-KS + circuit-eq + tdx + commitHashE-CR + commitHashBytesE-CR) | carriers (Addr, ByteSeq, DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs, VKey, Plaintext, PrivKey, PubKey) + std logic | `commitHashE` + `commitHashBytesE` + `tdxVerifier` + `groth16Verifier` + carriers + `rawBoundContract`, `rawDomainSep`, `serializeRawSessionSetPubKeyE`, `userDataOfSessionSetPubKey_eq_commitHash`, `was_signed_by_dstack`, `keyOf` |

**Invariant across all 8 lifts**: the `_negl` form's axiom closure contains **only carriers + standard logic** (`propext`, `Classical.choice`, `Quot.sound`) — *no bundle axioms*. Bundles enter through parametric hypotheses, not closure. The `_classical` corollary preserves the original bundle dependency unchanged for downstream consumers that still want the classical form.

Each lifted theorem comes in four packagings: `_classical` (corollary), `_negl` (raw `negligible` form), `_secure_of_*_bundle_secure` (`SecurityExp`), `*Game_secure_of_*_bundle_secure` (`SecurityGame` with `IsPPT` filter, body `True`).

## Cross-bundle composition map → `cross_component_session_bind_negl`

The terminal load-bearing lift composes all 4 classical bundles via a 5-summand union bound (Groth16 decomposes into 2 summands per the Step 5 doubled-negligibility finding):

```
                     Step 2 bundle              Step 3 bundle
                     ┌────────────┐             ┌────────────────┐
                     │ commitHashE│             │commitHashBytesE│
                     │ (UC ↪ UD)  │             │ (ByteSeq ↪ UD) │
                     └─────┬──────┘             └────────┬───────┘
                           │                             │
                           │ (d-pigeonhole)              │ (d-pigeonhole)
                           ▼                             ▼
              Pr[commitHashE collision]    Pr[commitHashBytesE collision]
                  ← CommitHashCollisionAdv   ← CommitHashBytesCollisionAdv
                           │                             │
                     Step 4 bundle              Step 5 bundle (DECOMPOSED)
                     ┌────────────┐             ┌──────────────────────┐
                     │ tdxVerifier│             │  groth16Verifier     │
                     │ (verify    │             │  (vkey+verify+       │
                     │  +sound    │             │   inputsToQuote+sound)│
                     │  +complete)│             └──┬────────────────┬──┘
                     └─────┬──────┘                │                │
                           │ (d-single-negl)       │ (d-doubled-negl)
                           ▼                       ▼                ▼
                  Pr[tdxVerifier forgery] negligible_groth16  negligible_circuit
                  ← TdxVerifierSoundAdv   ← Groth16KSAdv       ← CircuitEqAdv
                           │                       │                │
                           └─────────┬─────────────┴────────────────┘
                                     ▼
       Pr[cross_component_session_bind fails]
         ≤ Pr[commitHashE coll]          (summand 1, Step 2)
         + Pr[commitHashBytesE coll]     (summand 2, Step 3)
         + Pr[tdxVerifier forgery]       (summand 3, Step 4)
         + negligible_groth16            (summand 4, Step 5 KS half)
         + negligible_circuit            (summand 5, Step 5 circuit-eq half)
```

### Which lifted theorems carry which bundles (classical closures)

| Bundle | Carrying classical theorems |
|--------|-----------------------------|
| `commitHashE` (Step 2) | `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`, `cross_component_session_bind` (4) |
| `commitHashBytesE` (Step 3) | `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`, `cross_component_session_bind` (3) |
| `tdxVerifier` (Step 4) | `verifyGroth16_yields_decoded`, `handshake_sound`, `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`, `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`, `cross_component_session_bind` (8) |
| `groth16Verifier` (Step 5) | all 8 |

### Composition shape per theorem

- **Single** (1): `verifyGroth16_yields_decoded`
- **Dual** (1): `handshake_sound`
- **Triple-commitHashE** (3): `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`
- **Triple-commitHashBytesE** (2): `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`
- **Quadruple → 5 summands** (1): `cross_component_session_bind`

## Companion-module inventory (9 new modules)

Carrier-side (5):
- `Specs/Quartz/Crypto/EciesVCVio.lean` — `eciesAlg : AsymmEncAlg Id ...`
- `Specs/Quartz/Crypto/UserDataCommitVCVio.lean` — `CommitHashSpec`, `commitHashOC`
- `Specs/Quartz/Crypto/RawMessagesVCVio.lean` — `CommitHashBytesSpec`, `commitHashBytesOC`
- `Specs/Quartz/Attestation/DstackVCVio.lean` — `VerifyTdxQuoteSpec`, `verifyTdxQuoteOC`
- `Specs/Quartz/Attestation/ZkdcapVCVio.lean` — `VerifyGroth16Spec`, `verifyGroth16OC`

Protocol-side (4):
- `Specs/Quartz/Protocol/ProtocolVCVio.lean` — scaffolding (combined `ProtocolSpec` via `(+)`-sum, `IsPPT`, `Decidable was_signed_by_dstack`, Step 6.0 single-bundle lift)
- `Specs/Quartz/Protocol/ProtocolVCVioDual.lean` — Step 6.1 dual-bundle lift
- `Specs/Quartz/Protocol/ProtocolVCVioTriple.lean` — Step 6.2 five triple-bundle lifts
- `Specs/Quartz/Protocol/ProtocolVCVioQuad.lean` — Step 6.3 quadruple-bundle terminal lift

Companion-module invariant: VCV-io's transitive instance load is kept out of the `Decidable`-synthesis hot path. Classical theorems do not import these modules; `Specs.lean` is the only top-level importer.

## Coverage delta vs prior ledger (2026-05-12T12:57:07Z)

| Metric | Prior | Post-Step-6.3 | Delta |
|--------|-------|---------------|-------|
| Total Lean axioms | 40 | 26 | **-14 (-35%)** |
| Bundled record axioms (Step 1-5 condensation) | 0 | 4 | +4 |
| Demoted to def/theorem | 0 | 14+ (roundtrip, commitHash, commitHash_inj, commitHashBytes, commitHashBytes_inj, serializeRaw*_inj×2, verifyTdxQuote, verifyTdxQuote_sound, verifyTdxQuote_complete, verifyGroth16, inputs_to_quote, verifyGroth16_sound, zkdcapVKey) | +14+ |
| Dead axioms removed | 0 | 1 (`RtmrLog`, Step 4) | -1 |
| Protocol theorems (classical) | 5 | 8 (extended scope: Conservation + AuctionDeterminism added) | +3 |
| Protocol theorems lifted to `_negl` | 0 | **8 of 8** | +8 |
| Companion modules | 0 | 9 (5 carrier + 4 protocol) | +9 |
| `lake build` jobs | 104 | 2667 (VCVio adds ~2534 transitive targets) | +2563 |
| `sorry` count | 0 | 0 | 0 |
| Trust density (axioms / total theorems) | 40/16 = 2.5 | 26/(16+14+8 derived/lifted) ≈ 0.68 | -1.82 |

## Per-tool coverage snapshot

| Tool | Artifacts | Proven / Verified | Outstanding | Notes |
|------|-----------|-------------------|-------------|-------|
| Lean | 26 axioms + classical theorems + 8×4 = 32 new lifted/packaged theorems | `lake build` green, 2667 jobs, 0 `sorry` | parametric negligibility hypotheses (5 budgets) deferred to ArkLib + ref-DCAP-verifier + carrier refinement | Step 6 complete — 8/8 lifted |
| Quint | 22 invariants | 2 Apalache-verified (handshake `inv_pubkey_set_once`, attestation temporal violation reproducible) | 20 not exhaustively verified | unchanged from prior ledger; attestation `temporal_zk_accept_requires_vkey` rewrite landed (`temporal_zk_accept_action_tag` change record) |
| Verus | 6 prototypes | 5 of 43 verified prior run | 38 unsampled | unchanged from prior ledger |
| Kani | 41 harnesses | 1 verified, 1 prover-stuck | 39 unsampled | unchanged from prior ledger |
| proptest | 0 | n/a | — | unchanged |

## Outstanding work

### External discharges (the 5 negligibility hypotheses)

1. `negligible_groth16_ks` — ArkLib Groth16 knowledge-soundness coverage (upstream)
2. `negligible_circuit` — Lean reference DCAP verifier + circuit-equivalence theorem (separate effort)
3. `negligible_tdx` — PCK-signature unforgeability reduction (Intel-spec + crypto-lib)
4. `negligible_commitHash` — VCVio `randomOracle` + birthday bound; requires `[Fintype UserData]`
5. `negligible_commitHashBytes` — same shape as (4) on byte domain

### Carrier refinement queue (14 abstract carriers blocking concrete `Pr[...]`)

Crypto: `DomainSep`, `Addr`, `Nonce`, `Plaintext`, `Ciphertext` (now def), `PrivKey`, `PubKey`, `ByteSeq`
Attestation: `TdxQuote`, `MrEnclave`, `UserData`
Zkdcap: `Groth16Proof`, `PublicInputs`, `VKey`

Concrete `Pr[...]` statements (instead of parametric `[Fintype X] → ...`) require these refined to concrete byte-list / `BitVec n` representations. Currently sidestepped by parametric formulation in all 8 `_negl` lifts.

### In-codebase work

- Adopt VCV-io's `PolyQueries` as the `IsPPT` body (currently placeholder `True`). Blocked on adversaries gaining `OracleComp ProtocolSpec` access.
- Replace `Classical.propDecidable` instance for `was_signed_by_dstack` with extractor reformulation if a less-classical move is desired.
- Demote `rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey` to `def`s once their carriers (`DomainSep`, `Addr`, `PubKey`) are refined.

### Adversarial review

- Run `colosseum-adversarial` against the composed single+dual+triple+quadruple `_negl` surface (Step 6.3 explicitly queued this — all 4 lift levels in place provide the right granularity to surface union-bound-tightness, doubled-negligibility-correlation, and Option-(b) symmetric-framing findings).
- Specifically challenge the Option-(b) collision-resistance framing for `commitHashE` / `commitHashBytesE` — is the lift's hypothesis the *correct* statement of collision resistance for the concrete real-world hash, or has the embedding-to-concrete-hash mapping smuggled past a subtlety?

### Unchanged from prior ledger

- 1 clippy result_large_err
- 1 prover-stuck Kani harness
- 3 ignored unit tests in contracts/core
- attestation `temporal_zk_accept_requires_vkey` design decision (Option A/B per change record `2026-05-12T17-13-32Z-temporal_zk_accept_action_tag.md`)
- 38 unsampled Verus annotations, 39 unsampled Kani harnesses, 20 unsampled Quint invariants

## Reviewer checklist — [REVISED 2026-05-14 after Round A]

- [ ] All 26 axioms reviewed — bucket assignments stand?
- [ ] ~~All 4 (d)-bundle sub-tags match their discharge paths?~~ → Round A finds the sub-tag *labels* are correct but their *discharge mechanism* is cosmetic at the current code state. Re-frame as: do the (d) sub-tags name the right discharge paths *and* is each path's advantage abbrev tied to a concrete win predicate? (Currently no — see attacks #4, #8.)
- [ ] ~~All 8 `_negl` closures verified to carry **no bundle axioms**?~~ → **VACUOUSLY SATISFIED**. The closures are clean because the lifts say nothing about the bundle axioms (or about Quartz). Reframe as: does each `_negl` closure contain *exactly* the axioms its `_classical` form contains, *minus* the bundle axiom shadowed by the parametric negligibility hypothesis?
- [ ] `cross_component_session_bind_negl` 5-summand union bound matches the load-bearing claim the protocol layer is meant to make? — **Round A: no**, because the 5 underlying adversaries are unconstrained from the main one. See attack #3.
- [ ] No new `sorry` introduced in the lift modules? — Yes, still none.
- [ ] No regression in classical-chain axiom closures (each `_classical` corollary preserves its pre-refactor closure)? — **Yes, Round A confirms this is honest.**
- [ ] ~~Option-(b) collision-resistance framing is the framing the team intended?~~ → Round A: the framing is correctly intended, but the *implementation* of the framing names a new symbol without tying it back to `commitHash`. See attack #8.
- [ ] `IsPPT := True` placeholder is acceptable as a documented gap (or is `PolyQueries` adoption a blocker)? — **Round A escalates: blocker**. The placeholder interacts with the free-symbol root cause to admit "for all adversaries, this opaque function is negligible" certificates that mean nothing. See attack #5.

**New items added by Round A:**

- [ ] For each `_negl` theorem, is the protocol-fail advantage a `def` over a concrete win event, or a free function symbol?
- [ ] For each `*Advantage` `abbrev`, is it tied to a concrete win condition involving the actual verifier/hash, or is it a `Type`-only alias?
- [ ] At the terminal lift, are the bundle adversaries *derived* from the main adversary (via a `reduce : 𝒜 → 𝒜_low` function with a `reduce_correct` lemma), or are they free arguments?
- [ ] Has the `ProtocolSpec` oracle-access framework been wired into adversary types, or is it imported but unused?

---

## Methodology v0.2 asks

Four findings accumulated across Steps 4-6.3 (one-line each, with change-record provenance):

1. **`dead_axiom_scan` checkpoint in `colosseum-compose`** — per-step global reference scan to surface axioms with zero downstream uses; "found" and "none" both valid outputs. Provenance: Step 4 first instance (`RtmrLog`, removed: `2026-05-13T14-56-59Z-dstack-vcvio.md`); Step 5 first explicit "none" outcome (`2026-05-13T15-05-36Z-zkdcap-vcvio.md`).

2. **Bundle-cardinality drift tracking** — bundle-count changes (dual → triple → quadruple) silently accumulate downstream of bundling steps; mid-refactor an originally-dual theorem can be promoted to triple by an upstream bundle without warning. Methodology should track bundle count per dependent theorem and flag promotions. Provenance: Step 6.1 (`2026-05-13T15-27-38Z-protocol-vcvio-dual-bundle.md` — three of four originally-dual targets turned out triple-bundle after Step 2's `commitHashE` cascade).

3. **Meta-(d): vacuous-impossible-axiom-as-hypothesis** — a classical theorem consuming a spec-impossible axiom is vacuously satisfied; the OracleComp lift cannot inherit the vacuous satisfaction and must restate the truthful cryptographic hypothesis (collision resistance of the concrete real-world hash). The lift *upgrades* the hypothesis from vacuous to non-vacuous, but only if the upgraded hypothesis is correctly identified. Provenance: Step 6.2 (`2026-05-13T15-48-32Z-protocol-vcvio-triple-bundle.md`, "(d-vacuous-hypothesis)" sub-variant; the Option-(b) framing for `commitHashE`).

4. **(d-disjunction-vs-decomposition) — load-bearing-terminal-lift discipline** — disjunctions in (d) axioms (e.g. `groth16Verifier`'s doubled-negligibility = Groth16-KS ∨ circuit-equivalence) can be honestly *collapsed* at intermediate composition levels but must *expand* at the load-bearing terminal lift. Compose-time should track which disjunctions are still collapsed at the current level and flag any that survive past the terminal lift. Requires a machine-checkable `terminal: true` flag in the refactor plan. Provenance: Step 6.3 (`2026-05-13T16-02-47Z-protocol-vcvio-quad-bundle.md`, methodology-side ask M-1).

### Prior methodology asks referenced from earlier change records

Already on the docket (pre-Step-6, not specific to this refactor):

- **PPT predicate hardening** — replace placeholder `IsPPT := True` with VCV-io's `PolyQueries`. Blocked on adversaries gaining `OracleComp ProtocolSpec` access (Step 6.1, sustained through 6.3).
- **`_negl` reduction-skeleton in companion modules** — currently the 5 carrier-side companion modules (`*VCVio.lean`) carry documentary informal-statement comments only; the load-bearing `_negl` content lives in the 4 protocol-side modules. Methodology could push the documentary skeletons one layer earlier so each carrier-side module ships its own `_collision_negl` / `_forgery_negl` theorem stub (Steps 2-5, recurring suggestion).
- **Impossible-axiom flag in ledger** — separate sub-category for axioms whose mathematical content is known impossible (Steps 2-3, surfaced when `commitHashE` and `commitHashBytesE` first bundled). This ledger now encodes it via the (d-pigeonhole-impossible) sub-tag.
- **Companion-module template** — naming convention `<Module>VCVio.lean`, isolation of `OracleSpec`/`OracleComp` material to keep `Decidable`-synthesis paths clean, documentary `…OC` definition + informal negligibility statement (Steps 1-5; pattern now stable across 5+4 = 9 modules).
- **Trust-density metric** — ratio of axioms-per-theorem; was 40/16 = 2.5 at first ledger emission; is now 26/(16+14 derived + 8 lifted at 4 packagings each = 30+) ≈ 0.68 if counting derived theorems. `colosseum-compose` should emit this delta automatically (Steps 1-6, recurring).
- **`temporal_state_mismatch` ≠ `temporal_intent_mismatch`** sub-classification for adversarial findings where a state-only invariant correctly state-checks but a temporal property would reveal a violation (prior ledger meta-finding 1; revalidated by the attestation-spec change record).
- **`design_intent_mismatch` ↔ `code_wrong-by-design`** classifier sub-category (attestation change record's methodology meta-finding 4).

## Discrepancies, unknowns, and emergent findings

### Discrepancies between change records

- **Ledger axiom counts vs change-record running totals**: Step 3's change record predicts post-refactor will land at ~14-18 axioms; Step 4's predicts ~14-19; Step 5 lands at 26 (Steps 6.0-6.3 are content-phase, no further axiom reduction). The 26 figure is correct (verified by summing per-module post-step columns: 4+4+9+5+4). The earlier predictions were optimistic about which (a)-bucket items could be discharged in Steps 4-5; the carrier-refinement blockers were heavier than the per-step predictions assumed.
- **Step 2 says `commitHashE` has 5 dependent theorems; Step 3 says 5 dependents on `commitHashE` plus 6 new on `commitHashBytesE`; Step 4 says 9 total dependents; Step 5 says 16 total dependents.** Each is correct for its time-slice (the dependent set grows as later steps bundle their own axioms and as the protocol-layer trust statement is extended). Step 5's "16" includes all derived theorems and `_negl` candidates. Latest authoritative: see this ledger's "Cross-bundle composition map".
- **Step 6.0's predicted Step 6.1 was "lift the dual-bundle theorem `handshake_sound`" — Step 6.1 ran this**, but Step 6.1 also surfaced that *three of four originally-dual targets had become triple-bundle*, deferring them to Step 6.2. Step 6.0's bundle-count expectation was correct for the original ledger state but incorrect for the post-Step-5 state. This is the Methodology v0.2 ask #2 above.

### Classification uncertainties (Part C)

- **`tdxVerifier` is bucketed (d) with two sub-tags** (single-negl on sound, preconditional on complete). Defensible because it's a single record axiom carrying two distinct over-strength shapes. An auditor could argue this should be 2 separate axiom rows.
- **`groth16Verifier` is bucketed (d-doubled-negligibility)**. The (d-disjunction-vs-decomposition) finding (Step 6.3) implies this is a meta-level concern about *how* the lift expands the disjunction — not a fifth sub-variant of (d) on the axiom itself. The bucket label here treats it as Step 5 did (doubled-negligibility); Step 6.3's framing is captured in the Methodology v0.2 asks rather than the bucket.
- **`serializeRawSessionCreateE` / `serializeRawSessionSetPubKeyE`** are (c) genuine because serde_json on a fixed schema *is* plausibly injective (no pigeonhole obstruction — the codomain `ByteSeq` is open-cardinality). This is structurally different from the `commit*E` embeddings, which face pigeonhole because their codomain is fixed-width `UserData`. Auditor could ask: does serde_json *actually* serialize injectively in the deployed encoder, including edge cases (NaN floats, key ordering)? Not in scope here.
- **`userDataOf*_eq_commitHash` bridge equalities** are (c) genuine: they connect `commitHashBytes ∘ serialize` with `commitHash` over `UserDataCommit`. Discharging them requires both a constructive byte-level serde_json model AND a constructive `commitHash` over abstract carriers. Could plausibly be reclassified (a) once carriers are concrete.

### Emergent findings from regeneration

- ~~**All 8 `_negl` lifts hide bundle axioms from their closures uniformly** — a stronger invariant than any single change record states. This is the *single most important observable* in the ledger: external auditors can take any lifted theorem, run `lean_verify`, and confirm that the bundle axiom is absent from the closure. The trust claim moves from "the bundle axiom is honest" (which it isn't, for the 4 (d) cases) to "the lift's parametric negligibility hypothesis is honest" (which it can be, given the discharge paths).~~ **[RETRACTED 2026-05-14]** The uniform invariant is satisfied vacuously: the `_negl` forms have no bundle axiom in closure *because they say nothing about Quartz*. A theorem of the form `negligible f → negligible f` (which is what each lift currently reduces to under the right adversarial instantiation) trivially has no axiom closure beyond standard logic. The invariant's intended reading — "the lift's parametric negligibility hypothesis stands in for the bundle axiom" — requires the advantage symbols to be tied to defined probability events; they are not. See Round A attacks #1, #2, #7 in `.colosseum/attacks/lean-negl-lifts-2026-05-14/claude.md`.
- **Companion-module count is asymmetric**: 5 carrier-side modules paired with 4 protocol-side modules. The asymmetry is structural — the carrier-side modules are 1-per-trust-primitive (Ecies, UserDataCommit, RawMessages, Dstack, Zkdcap) while protocol-side modules are sliced by bundle cardinality (foundations, dual, triple, quad). The 9 total is correct per the Step 7 brief.
- **The `_classical` corollaries form a load-bearing "exit door"**: downstream consumers (engineering code that wants the classical Prop form) get unchanged behaviour via `*_classical` re-exports. Removing the classical chain would break this exit door. The lift sequence preserves backward compatibility intentionally.
- **None of the 8 lifts use `Function.Injective` directly** — the spec-level injectivity claims (`commitHash_inj`, `commitHashBytes_inj`, etc.) are now derived theorems consumed by `_classical` corollaries only. The `_negl` chain bypasses injectivity entirely, substituting collision-resistance hypotheses on the underlying concrete hash.
- **`Ecies.lean` produced no (d)-bucket axioms** — alone among the 5 modules. The original ECIES roundtrip was demoted to a real theorem; the carrier axioms are (c). This is a methodology-positive observation: when the substrate supports a concrete spec-level model (here a deterministic `Ciphertext := PubKey × Plaintext`), no (d) emerges.

## What's next — recommendation — [REVISED 2026-05-14 after cycles 6.4–6.11]

Cycle-6.4-through-6.11 sequence complete. All 8 `_negl` lifts def-tied with content-bearing `Pr[…]`-based advantages, proven pointwise bounds, and bundle structures matching their classical proofs' actual probabilistic-failure mode counts. Round A attacks #1, #2, #3, #4 (partial at terminal), #11 are structurally closed across all lifts.

**Cycle outcome summary**:

| Cycle | Lift | Bundle (was → is) | Failure mode |
|---|---|---|---|
| 6.4 | `verifyGroth16_yields_decoded_negl` | single → single | Groth16 |
| 6.5 | `handshake_sound_negl` | dual → single | Groth16 |
| 6.6 | `handshake_binds_ecies_key_negl` | triple → single | Groth16 |
| 6.7 | `session_confidentiality_negl` | triple → zero | None |
| 6.8 | `session_confidentiality_via_extractor_negl` | triple → zero | None |
| 6.9 | `cross_component_transfers_conservation_negl` | triple → single | Groth16 |
| 6.10 | `cross_component_auction_winner_determinism_negl` | triple → single | Groth16 |
| 6.11 | `cross_component_session_bind_negl` (terminal) | quad (5-summand) → single | Groth16 |

7 of 8 lifts were over-bundled in the original. Six have a single surviving Groth16-soundness probabilistic-failure mode; two are degenerate-zero (deterministic-only — the spec models unconditional correctness, not CPA security).

**Open work**:

1. **Cycles 6.12–6.14** (deeper refactors than def-tying):
   - 6.12: replace `IsPPT := True` placeholder with VCV-io's `PolyQueries` — closes Round A attack #5.
   - 6.13: wire `OracleComp ProtocolSpec` into adversary types instead of `ProbComp` — closes Round A attack #6.
   - 6.14: replace `pkOfUserData_commitHash`'s reliance on `commitHash_inj` with a probabilistic collision-resistance hypothesis — closes Round A attack #8 and surfaces a real second bundle at the terminal lift.

2. **Methodology v0.2 back-port**: send the **over-bundling meta-finding** to the colosseum agent — bundle-count derivation must come from per-conjunct failure-mode analysis of the classical proof, not from a static axiom-count classifier. Also send the **degenerate-zero-advantage sub-kind** observation from cycles 6.7/6.8 — when a lift's advantage proves identically zero, the cycle should explicitly state whether the spec is intentionally not modelling the relevant probabilistic phenomenon (yes/no).

3. **Round C adversarial review**: 4 unattacked Quint specs (handshake, attestation, pingpong, transfers), 39 Kani harnesses, 43 Verus invariants. Background-runnable; not blocking.

4. **External discharges** (mostly upstream-paced):
   - `negligible_groth16_ks` — ArkLib Groth16 KS coverage (upstream roadmap)
   - `negligible_circuit` — Lean reference DCAP verifier (multi-month, no owner)
   - `negligible_tdx` — PCK-signature unforgeability reduction
   - `negligible_commitHash` / `_commitHashBytes` — VCV-io random-oracle + birthday bound + `[Fintype UserData]`

The highest-leverage remaining work item is **methodology-side**: back-port the four v0.2 asks into colosseum (especially `dead_axiom_scan` and bundle-cardinality drift tracking, which are mechanically straightforward and would have caught the Step 6.0 → 6.1 bundle-count surprise). The Quartz-side discharges (concrete hash spec, ArkLib integration, reference DCAP verifier, carrier refinement) are mostly **upstream-blocked**: ArkLib's Groth16 coverage is on a roadmap not yet shipped; the reference DCAP verifier is a multi-month software-verification effort with no current owner; the `[Fintype]` carrier refinement requires deciding on concrete byte representations across the whole crypto layer. The single near-term-tractable Quartz-side item is **demoting the 3 (a)-bucket named-constant axioms** (`rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey`) once their carriers are refined to concrete byte strings — this is a 1-2-day refactor with no external dependencies and would close out the (a) bucket entirely, leaving only (c) and (d) on the ledger. After that, focused adversarial review of the 8 `_negl` lifts (especially the Option-(b) collision-resistance framing) is the right cadence; bug-finding in the lift surface is higher-yield than chasing the upstream discharge paths.
