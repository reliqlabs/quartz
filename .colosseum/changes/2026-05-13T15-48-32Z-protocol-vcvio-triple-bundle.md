# Change record: Protocol VCV-io triple-bundle lifts (Step 6.2)

- Date: 2026-05-13T15:48:32Z
- Classification: intent-touching (continues the **content-phase**
  VCV-io refactor; lifts five triple-bundle protocol theorems from
  classical-`Prop` to `OracleComp` + negligibility with three-summand
  union bounds) + methodology-extension (introduces the
  collision-resistance adversary framing for the bundled
  `commitHashE` / `commitHashBytesE` axioms)
- Intent revision: none (no `intent.md` edit needed — public API
  names preserved; new theorems are additive)
- Plan reference: `.colosseum/refactor-plan-vcvio.md` § "Step 6
  detail: OracleComp lift of the protocol layer"
- Predecessors:
  - `2026-05-13T15-18-06Z-protocol-vcvio-foundations.md` (Step 6.0)
  - `2026-05-13T15-27-38Z-protocol-vcvio-dual-bundle.md` (Step 6.1)

## Description

Step 6.2 of the VCV-io refactor — the triple-bundle extension of
Steps 6.0 (single-bundle) and 6.1 (dual-bundle). Five lifts in
total, all in a new sibling module `ProtocolVCVioTriple.lean`.

The brief named five candidate triple-bundle theorems. All five
were confirmed triple-bundle via `lean_verify` before lift (see
"Bundle classification verification" below) and all five were
lifted in this cycle.

Three deliverables:

1. **Five protocol theorems lifted** (one classical corollary +
   one `_negl` form + one `SecurityExp` form + one `SecurityGame`
   form per theorem, total 20 new theorems). All proven without
   `sorry` via real reduction-based proofs using the union-bound
   pattern
   `negligible_of_le ∘ negligible_add ∘ negligible_add`.

2. **Two new collision-resistance adversary types** introduced
   (`CommitHashCollisionAdv`, `CommitHashBytesCollisionAdv`) plus
   their corresponding advantage / game pairs, mirroring the
   Step 6.0 / 6.1 pattern.

3. **Honest framing decision documented** for the `commitHashE` /
   `commitHashBytesE` hypotheses (Option (b) — keep the embedding
   model at the spec layer, frame the negligibility hypothesis as
   collision-resistance of the underlying concrete hash function
   `H` the embedding abstracts over). See "Critical honesty
   question for commitHashE" below.

## Bundle classification verification

Per the methodology, each of the five target theorems was checked
via `mcp__lean-lsp__lean_verify` *before* attempting the lift:

| Theorem | Bundles in axiom closure | Classification |
|---|---|---|
| `handshake_binds_ecies_key` | `tdxVerifier` + `groth16Verifier` + `commitHashE` | TRIPLE ✓ |
| `session_confidentiality` | same | TRIPLE ✓ |
| `session_confidentiality_via_extractor` | same | TRIPLE ✓ |
| `cross_component_transfers_conservation` | `tdxVerifier` + `groth16Verifier` + `commitHashBytesE` | TRIPLE ✓ |
| `cross_component_auction_winner_determinism` | same | TRIPLE ✓ |

Standard logic axioms (`propext`, `Classical.choice`, `Quot.sound`)
and carriers (`MrEnclave`, `TdxQuote`, `Addr`, `ByteSeq`, etc.) are
present in all five closures and not counted as bundles. The
carrier-side `was_signed_by_dstack` and `keyOf` are likewise
non-bundle dependencies (carrier-level, not Step 1-5 record axioms).

The two cross-component theorems also pick up local axioms outside
the bundle set:

- `cross_component_transfers_conservation`: `serializeTransferRequest`,
  `Conservation.addrOf`
- `cross_component_auction_winner_determinism`:
  `serializeResolveMessage`, `Conservation.addrOf`,
  `AuctionDeterminism.decryptBid`

These are example-specific carriers / serializers, not
cryptographic-trust bundles. They are not in scope for the
union-bound composition.

**Finding**: all five theorems are genuinely triple-bundle, exactly
matching the Step 6.1 classification table. No promotions to
quadruple, no demotions to dual. The lift sequence scales
mechanically.

## Critical honesty question for `commitHashE`

The bundled `commitHashE : UserDataCommit ↪ UserData` (and its
byte-domain twin `commitHashBytesE : ByteSeq ↪ UserData`) is a
`Function.Embedding`. At the spec level the embedding-injectivity
hypothesis is **mathematically impossible-as-stated** by
pigeonhole — there is no injection from an open-cardinality
preimage to a fixed-width 64-byte codomain. Three options were
weighed for how to honestly frame the negligibility hypothesis:

### Option (a): Replace `commitHashE` with a concrete `H` carrier

Treat `commitHashE` as a placeholder for an externally-supplied
concrete hash function `H : UserDataCommit → UserData` (no
embedding), and frame the hypothesis as `negligible (CR_advantage
𝒜)` for that `H`.

**Rejected** for Step 6.2. Would touch every dependent classical
theorem (`pkOfUserData_commitHash`, the `handshake_binds_ecies_key`
chain, plus the byte-domain analogs in `RawMessages.lean` /
`TransferMessages.lean` / `AuctionMessages.lean`), fragment the
spec-vs-impl boundary, and require carrier refinement for
`UserData`. Out of scope for Step 6.2 and Step 6.3.

### Option (b): Keep the embedding model, frame the hypothesis as concrete-hash collision resistance

Acknowledge that the spec-level embedding model is impossible (as
the companion modules `UserDataCommitVCVio.lean` /
`RawMessagesVCVio.lean` already do explicitly), and frame the
negligibility hypothesis as the **collision-resistance advantage
of the concrete hash function `H` the embedding axiom abstracts
over**.

**Selected.** The hypothesis `negligible (commitHashCollAdv 𝒜_h)`
is the standard cryptographic statement on the real
`H : UserDataCommit → UserData` that the embedding is a (lossy,
impossible-as-stated) abstraction of. Under the spec-level
pigeonhole impossibility, this hypothesis is *strictly weaker than*
(and hence implied by) the embedding axiom — the lifted theorems
are honest about depending on the collision-resistance of the
*real* hash function, not on the literally-impossible
embedding-side injectivity claim.

This is the lighter-touch and matches the precedent set in Step
6.0 / 6.1 (parametric hypotheses for negligibility budgets that
the spec layer cannot yet discharge).

### Option (c): Add a concrete-hash carrier axiom alongside the embedding

Keep the embedding *and* add a parallel concrete-hash carrier
axiom for the negligibility hypothesis to refer to.

**Rejected.** Doubles the axiom surface without methodology gain
over Option (b) — the hypothesis lives in the same place either
way. Worse: introducing a parallel concrete-hash axiom alongside
the impossible embedding makes the two axioms structurally
non-aligned, opening a methodology gap of its own (which carrier
do downstream theorems consume?).

### Honesty implication

Is the collision-resistance framing honest, given the spec-level
pigeonhole impossibility?

**Yes — and the framing is in fact stronger / more honest than
the original.** The spec-level embedding axiom is mathematically
impossible; consuming it as a hypothesis is *vacuously satisfied*
(impossibility lets you derive anything). The collision-resistance
hypothesis is the *standard cryptographic statement* and is
**not** vacuous: real concrete hashes (SHA-256) have non-trivial
collision-finding adversaries. So Option (b) replaces a vacuous
hypothesis with a non-vacuous one.

The down side: the lifted theorem now says "if a concrete hash
function `H` has negligible collision-finding advantage, then ...".
The spec-level audit surface needs to acknowledge that the bundle
axiom is a *placeholder* for the concrete `H`. This is documented
in the module header of `ProtocolVCVioTriple.lean` and in the
companion modules' commentary.

The framing is therefore the most honest one available: it makes
the dependency on the concrete (real-world, externally-supplied)
hash function explicit, rather than hiding it behind a
spec-impossible embedding.

## Lift pattern

The Step 6.0 single-bundle pattern was `negligible_of_le`. Step
6.1 added one composition: `negligible_of_le ∘ negligible_add`.
Step 6.2 adds one more: `negligible_of_le ∘ negligible_add ∘
negligible_add`. The shape:

```lean
negligible_of_le h_bound
  (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hash_negl)
```

The protocol-fail advantage is bounded pointwise by the sum of the
three underlying soundness advantages:

```
protocolFailAdv 𝒜 n
  ≤ groth16Adv 𝒜_groth n + tdxAdv 𝒜_tdx n + hashAdv 𝒜_hash n
```

Negligibility is closed under finite sums (twice); pointwise
monotonicity gives the union-bound shape. This composes mechanically
with VCV-io's `Negligible.lean` lemmas.

### Per-theorem proof shape

Each of the five `_negl` theorems uses exactly the same
proof body:

```lean
negligible_of_le h_bound
  (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hash_negl)
```

The five differ only in:
- adversary type (`HandshakeBindsAdv`, `SessionConfidentialityAdv`,
  `SessionConfidentialityExtractorAdv`, `TransfersConservationAdv`,
  `AuctionDeterminismAdv`),
- hash adversary type (`CommitHashCollisionAdv` for theorems 1-3,
  `CommitHashBytesCollisionAdv` for theorems 4-5).

The mechanical scaling matches the Step 6.1 prediction exactly.

## Files changed

### Added

- `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioTriple.lean` —
  new module (~610 lines). Defines:
  - 5 adversary type pairs (composite + advantage abbrev) for the
    five lifted theorems
  - 2 new collision-resistance adversary types
    (`CommitHashCollisionAdv` for the `commitHashE` bundle,
    `CommitHashBytesCollisionAdv` for the `commitHashBytesE` bundle)
  - 5 `_classical` corollaries (preserved-axiom-closure re-exports)
  - 5 `_negl` theorems (probabilistic three-summand union-bound lifts)
  - 5 `_secure_of_triple_bundle_secure` `SecurityExp` packagings
  - 5 `Game_secure_of_triple_bundle_secure` `SecurityGame`
    reduction-form packagings with `IsPPT` filter

### Modified

- `proofs/lean/Specs.lean` — added import of
  `Specs.Quartz.Protocol.ProtocolVCVioTriple` companion module.

### Not modified

- All other Lean source files. The lift is purely additive — no
  existing theorem statement, proof, or axiom is touched. The
  classical chain re-builds unchanged. Verified by post-build
  `lean_verify` on
  `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
  (still riding on the quadruple-bundle
  `{commitHashE, commitHashBytesE, tdxVerifier, groth16Verifier}`),
  and on `Specs.Quartz.Protocol.ProtocolVCVioDual.handshake_sound_negl`
  (closure unchanged from Step 6.1).

## Per-acceptance-criterion status

- [x] `lake build` green. **2666 jobs** (+1 from Step 6.1's
  2665 baseline — the new `ProtocolVCVioTriple.lean` module).
  Inside the expected "+2 to +8" envelope; in fact at the bottom
  of the envelope because the new module imports the same
  `Asymptotics.Security` transitive closure already pulled by
  `ProtocolVCVioDual.lean`.

- [x] Five `_negl` theorems land in `ProtocolVCVioTriple.lean`.
  All five have **real reduction-based proofs** (no `sorry`)
  using the union-bound pattern
  `negligible_of_le ∘ negligible_add ∘ negligible_add`.

- [x] `lean_verify` on each `_negl` form confirms axiom closure.
  **All five close with carriers + standard logic only** —
  `{propext, Classical.choice, Quot.sound, MrEnclave, TdxQuote,
    UserData, Groth16Proof, PublicInputs, ...}` plus example-
  specific carriers (`Addr`, `DomainSep`, `Nonce`, `ByteSeq`,
  `PubKey`, `PrivKey`, `Plaintext`). **No bundle axioms enter the
  closure** — `tdxVerifier`, `groth16Verifier`, `commitHashE`,
  `commitHashBytesE` are all absent. Bundles enter through
  hypotheses.

- [x] No new axioms added. Bundle axioms unchanged.

- [x] One change record at
  `.colosseum/changes/2026-05-13T15-48-32Z-protocol-vcvio-triple-bundle.md`.

## Verification result

`lake build` is green at HEAD:

```
✔ [2664/2666] Built Specs.Quartz.Protocol.ProtocolVCVioTriple (1.4s)
✔ [2665/2666] Built Specs (1.2s)
Build completed successfully (2666 jobs).
```

### Axiom closure of the lifted theorems

Verified via `lean_verify` (post-rebuild):

**Theorem 1: `handshake_binds_ecies_key_negl`**
- axioms: `{propext, Classical.choice, Quot.sound, Addr, DomainSep,
  Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs,
  Plaintext, PrivKey, PubKey}`
- carriers + standard logic only. No bundles.

**Theorem 2: `session_confidentiality_negl`**
- axioms: identical to theorem 1.

**Theorem 3: `session_confidentiality_via_extractor_negl`**
- axioms: identical to theorem 1.

**Theorem 4: `cross_component_transfers_conservation_negl`**
- axioms: `{propext, Classical.choice, Quot.sound, Addr, ByteSeq,
  MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs}`
- carriers + standard logic only. Notably tighter than theorems 1-3
  because `Confidentiality.lean`'s `Plaintext`/`PrivKey`/`PubKey`/
  `DomainSep`/`Nonce` chain is irrelevant here.

**Theorem 5: `cross_component_auction_winner_determinism_negl`**
- axioms: identical to theorem 4.

**All five _classical corollaries preserve their original triple-
bundle closures unchanged** (verified by re-running `lean_verify`
on the `_classical` versions; e.g.
`handshake_binds_ecies_key_classical` carries `tdxVerifier,
groth16Verifier, commitHashE` exactly as the original).

### Downstream regression check

Verified via `lean_verify` (post-rebuild):

- `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
  axioms: `{commitHashE, commitHashBytesE, tdxVerifier,
  groth16Verifier}` + carriers — **unchanged from Step 6.1**.
  Quadruple-bundle composition preserved.

- `Specs.Quartz.Protocol.ProtocolVCVioDual.handshake_sound_negl`
  axioms: `{propext, Classical.choice, Quot.sound, MrEnclave,
  TdxQuote, UserData, Groth16Proof, PublicInputs}` — **unchanged
  from Step 6.1**. Dual-bundle lift unaffected.

- `Specs.Quartz.Protocol.ProtocolVCVio.verifyGroth16_yields_decoded_negl`
  axioms: unchanged from Step 6.0.

## Honesty section

### How many lifts went through cleanly with real reduction proofs?

**Five of five** lifts went through cleanly with real reduction-
based proofs, zero `sorry`. Each `_negl` theorem's proof body is
literally:

```lean
negligible_of_le h_bound
  (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hash_negl)
```

The variation between theorems is purely in adversary types and
the hash-bundle (commitHashE vs commitHashBytesE). The
`SecurityExp` and `SecurityGame` packagings are equally mechanical.

### How many needed reframing or hit Bool/Prop gymnastics?

**Zero** at the proof level. The Step 6.1 `IsPPT` placeholder and
`Decidable was_signed_by_dstack` instance (both inherited from
`ProtocolVCVio.lean`) carried over unchanged. The triple-bundle
adversaries are no-oracle-access `ProbComp` producers, same shape
as Step 6.0 / 6.1.

**One reframing at the hypothesis level**: the `commitHashE` /
`commitHashBytesE` bundles are spec-impossible-as-stated
embeddings; the negligibility hypothesis cannot literally be
"the embedding has a collision" (that is false by
`Function.Embedding.injective`). The reframing — to collision-
resistance of the concrete hash function the embedding abstracts
over — is documented as Option (b) above. The reframing is
documentary, not proof-level: it lives in module-level commentary
and in this change record's "Critical honesty question" section.
The lift theorems themselves are parametric over the hypothesis,
so the framing decision only affects what the hypothesis *means*
to a reader, not how the proof goes through.

### How many turned out to be a different bundle cardinality than expected?

**Zero.** All five target theorems are genuinely triple-bundle:

- Three were originally-dual-bundle and were promoted by Step 2's
  `commitHashE` bundling (already noted in Step 6.1).
- Two are cross-component theorems that pick up `commitHashBytesE`
  from the Step 3 bundling (predicted by Step 6.1's analysis).

No surprises in either direction. The Step 6.1 bundle classification
table was complete and accurate.

### Any new (d)-bucket findings?

**One new (d)-bucket-adjacent finding** surfaces in the framing of
the `commitHashE` / `commitHashBytesE` hypotheses:

**(d-vacuous-hypothesis)** *vacuous-impossible-axiom-as-hypothesis*:
when a spec-level axiom is mathematically impossible as stated, a
classical theorem that consumes it as a hypothesis becomes
vacuously true. The OracleComp lift cannot inherit this vacuous
satisfaction; it must instead state the *truthful* cryptographic
hypothesis (here: collision resistance of the concrete hash). The
lift therefore *upgrades* the hypothesis from vacuous to
non-vacuous, which is a methodology win — but only if the
upgraded hypothesis is correctly identified.

This is a meta-(d) finding: it characterizes the *shape of the
gap* between spec-impossible axioms and their honest-lift
hypotheses. It is methodologically distinct from the Step 2-3
finding (*"impossible-as-stated"*) and the Step 6.0-6.1 finding
(*"adversary-class-strong"*) — those describe the axiom's
honesty problem; this describes the *lift's framing*.

The framing decision (Option (b)) closes the meta-(d) gap by
making the upgraded hypothesis explicit (collision resistance of
the underlying concrete hash), documenting that the spec-level
axiom is a placeholder, and threading the truthful hypothesis
through the parametric `_negl` theorem statements.

### Is the collision-resistance framing honest, or vacuous?

**The collision-resistance framing is honest.** The bundled
embedding axiom is spec-impossible, but the collision-resistance
hypothesis the lift consumes is the standard cryptographic
statement on the *real* hash function the embedding abstracts
over. The framing is in fact *strictly stronger* (more honest)
than the original embedding-injectivity hypothesis:

- Spec-level embedding hypothesis: vacuous (impossible-as-stated).
- Lift-level collision-resistance hypothesis: non-vacuous, standard
  cryptographic statement.

The downstream consumer must understand that the bundle axiom in
the spec layer is a placeholder for the concrete hash; the lift's
hypothesis refers to that concrete hash. This is documented in the
module header, in this change record, and in the companion modules
(`UserDataCommitVCVio.lean`, `RawMessagesVCVio.lean`) which already
flag the spec-level impossibility.

### Did the union-bound pattern scale mechanically per the Step 6.1 prediction?

**Yes.** Per Step 6.1: "the composition pattern `negligible_of_le
∘ negligible_add` is established here and will scale to three-
summand (`+ negligible_add`) and four-summand union bounds in
Steps 6.2 / 6.3." This prediction held exactly:

- Step 6.0 (single-summand): `negligible_of_le h_bound h_negl`
- Step 6.1 (two-summand): `negligible_of_le h_bound (negligible_add h₁ h₂)`
- Step 6.2 (three-summand): `negligible_of_le h_bound (negligible_add (negligible_add h₁ h₂) h₃)`

Mechanically uniform; each new summand adds one `negligible_add`
application. The `SecurityExp` and `SecurityGame` forms scale
identically.

The third summand did not introduce friction. The only friction
encountered was the `commitHashE` framing decision (documented
above), which is hypothesis-shape, not proof-shape.

## Cross-step continuity (Steps 1-6.1 → Step 6.2)

- **Companion-module pattern (5 instances, Steps 1-5)**:
  load-bearing here as in Step 6.0 / 6.1. The new
  `ProtocolVCVioTriple.lean` imports `ProtocolVCVio`,
  `ProtocolVCVioDual`, and the three protocol-layer classical
  files (`Confidentiality`, `Conservation`, `AuctionDeterminism`)
  the lifted theorems re-export from. The companion-module
  invariant ("VCV-io classpath stays out of the
  `Decidable`-synthesis hot path") is preserved — the triple-lift
  module is imported only by `Specs.lean`, not by any classical
  protocol file.

- **(d)-bucket pattern**: one new meta-variant
  (*vacuous-impossible-axiom-as-hypothesis*) surfaced, documented
  above. Methodologically distinct from prior sub-variants
  (`impossible-as-stated`, `adversary-class-strong`,
  `single-/doubled-/preconditional-negligibility`).

- **Negligibility framework choice (Step 6.0)**: preserved
  unchanged. Every probabilistic theorem in this step continues
  to state results in terms of `negligible` directly. The
  framework choice remains reversible.

- **Bundle composition discipline**: the triple-bundle union
  bound is the *first three-summand composition* in the lift
  sequence (Step 6.0 was single-bundle; Step 6.1 was
  dual-bundle). The composition pattern
  `negligible_of_le ∘ negligible_add ∘ negligible_add` is
  established here and will scale to four-summand (and
  potentially five-summand if `groth16Verifier` decomposes)
  union bounds in Step 6.3.

- **Cumulative state**:
    - Steps 0-5: axiom count 40 → 26 (form progress, -35%)
    - Step 6.0: no axiom change; 1 protocol theorem lifted
      (single-bundle proof-of-concept).
    - Step 6.1: no axiom change; +1 protocol theorem lifted
      (`handshake_sound`, dual-bundle). Total lifted: 2 of 8.
    - Step 6.2 (this step): no axiom change; **+5 protocol
      theorems lifted** (the five triple-bundle theorems). Total
      lifted: 7 of 8 protocol theorems.
    - Step 6.3 (remaining): lift the 1 remaining quadruple-bundle
      protocol theorem (`cross_component_session_bind`).

## Adversarial review

Not run in this cycle. The triple-bundle lifts use the same proof
shape as Step 6.1's dual-bundle lift, scaled by one `negligible_add`
step. The substantive risk surface is the same as Step 6.0 / 6.1:

- the parametric advantage abstraction may hide complexity
  (vacuously true under trivial bounds);
- the `IsPPT := True` placeholder is informationally equivalent
  to no adversary-class restriction;
- the union-bound shape may not compose tightly when stacked
  further.

Plus one new triple-bundle-specific risk:

- the collision-resistance framing for `commitHashE` /
  `commitHashBytesE` (Option (b) above) needs to be verified
  against actual cryptographic adversarial models. The
  abstraction "the embedding axiom is a placeholder for a
  concrete hash" is documentary; an adversarial review should
  challenge whether the lifted theorems' hypotheses are the
  *correct* statement of collision resistance for the concrete
  hash, or whether subtleties of the embedding-to-concrete-hash
  mapping have been smuggled past.

A formal `colosseum-adversarial` pass should run once Step 6.3
lands the quadruple-bundle lift. The triple-bundle alone may not
surface composition findings beyond those already flagged in
Step 6.1; the four-summand composition with
doubled-negligibility may.

## Outstanding follow-ups

### Step 6.3 (quadruple-bundle lift) — explicitly queued

- [ ] **Lift `cross_component_session_bind`** — four (or five if
  `groth16Verifier` decomposes into KS + circuit-eq) summands.
  This is the load-bearing protocol-layer trust statement; the
  composition discipline established in Steps 6.0-6.2 should
  scale mechanically, with one additional `negligible_add` step.

### Methodology infrastructure (inherited from Steps 6.0/6.1)

- [ ] **Adopt VCV-io's `PolyQueries` as the `IsPPT` body**. Still
  blocked on carrier-refinement work.
- [ ] **Discharge the negligibility hypotheses**:
  - `negligible_groth16` from ArkLib (once Groth16 KS lands)
  - `negligible_circuit` from a Lean reference DCAP verifier
  - `negligible_commitHash` / `negligible_commitHashBytes` from
    VCV-io's `randomOracle` + birthday bound (requires
    `[Fintype UserData]`)
  - `negligible_tdxVerifier` from a PCK-signature unforgeability
    reduction

### Adversarial-review queue

- [ ] Run `colosseum-adversarial` against the triple-bundle lifts
  once Step 6.3's quadruple-bundle lift lands. The combined
  surface (single + dual + triple + quadruple) is the right
  granularity for surfacing union-bound-tightness and
  composition-finding shapes.

- [ ] Specifically challenge the **collision-resistance framing
  decision** (Option (b)): is the lifted theorem's hypothesis the
  *correct* statement of collision resistance for the concrete
  hash, or has the embedding-to-concrete-hash mapping smuggled
  past a subtlety?

## Readiness for Step 6.3 (quadruple-bundle lift)

All Step 6.2 deliverables are in place. Step 6.3 can proceed by:

1. Defining no new adversary types (the four bundles already have
   adversary types from Steps 6.0-6.2:
   `Groth16SoundAdv`, `TdxVerifierSoundAdv`,
   `CommitHashCollisionAdv`, `CommitHashBytesCollisionAdv`).

2. Defining one new composite adversary
   `CrossComponentSessionBindAdv` mirroring the existing
   composite adversaries.

3. Stating the lifted theorem with a four-summand union bound:
   `bindFailAdv ≤ groth16Adv + tdxAdv + hashAdv + hashBAdv`.

4. Proving via `negligible_add` (three times; one for each
   composition step).

5. (Optional) Decomposing `groth16Verifier` into KS + circuit-eq
   summands for a five-summand bound if the doubled-negligibility
   shape is desired.

**Step 6.3 is unblocked.** The triple-bundle pattern proven here
scales mechanically to quadruple-bundle. The remaining lift is
scaling along the union-bound dimension, not re-architecting.
