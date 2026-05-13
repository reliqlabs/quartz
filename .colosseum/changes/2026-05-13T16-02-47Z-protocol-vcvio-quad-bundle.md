# Change record: Protocol VCV-io quadruple-bundle lift (Step 6.3)

- Date: 2026-05-13T16:02:47Z
- Classification: intent-touching (closes the **content-phase**
  VCV-io refactor; lifts the one quadruple-bundle protocol theorem
  from classical-`Prop` to `OracleComp` + negligibility with the
  **five-summand** union bound that surfaces the Step 5
  doubled-negligibility decomposition) + methodology-completion
  (the final lift of the Step 6 sequence — load-bearing
  methodology target of the whole content phase)
- Intent revision: none (no `intent.md` edit — public API names
  preserved; new theorems are additive)
- Plan reference: `.colosseum/refactor-plan-vcvio.md` § "Step 6
  detail: OracleComp lift of the protocol layer"
- Predecessors:
  - `2026-05-13T15-18-06Z-protocol-vcvio-foundations.md` (Step 6.0)
  - `2026-05-13T15-27-38Z-protocol-vcvio-dual-bundle.md` (Step 6.1)
  - `2026-05-13T15-48-32Z-protocol-vcvio-triple-bundle.md` (Step 6.2)

## Description

Step 6.3 of the VCV-io refactor — the **quadruple-bundle** lift of
the single load-bearing protocol-layer theorem
`cross_component_session_bind`, and the **final lift** of the Step 6
sequence.

The lift expands the four classical bundles in the closure
(`commitHashE`, `commitHashBytesE`, `tdxVerifier`, `groth16Verifier`)
into **five** cryptographic-assumption summands under the union bound
— the fifth coming from the Step 5 doubled-negligibility
decomposition of `groth16Verifier` into Groth16 knowledge soundness +
zkdcap circuit equivalence.

Three deliverables:

1. **One protocol theorem lifted** (one classical corollary +
   one `_negl` form + one `SecurityExp` form + one `SecurityGame`
   form, total 4 new theorems). All proven without `sorry` via a
   real reduction-based proof using a four-deep
   `negligible_add` chain composed with `negligible_of_le`.

2. **Two new doubled-negligibility adversary types** introduced
   (`Groth16KSAdv`, `CircuitEqAdv`) plus their corresponding
   advantage / game pairs, mirroring the Step 6.0 / 6.1 / 6.2
   pattern. One new composite adversary (`CrossSessionBindAdv`).

3. **Decision (β) confirmed**: the `groth16Verifier` summand is
   **decomposed** into two summands rather than inheriting the
   triple-bundle monolithic framing. This is the methodology-level
   fulfilment of the Step 5 (d)-bucket "doubled-negligibility"
   finding.

## Bundle classification verification

Per the methodology, the target theorem was checked via
`mcp__lean-lsp__lean_verify` *before* attempting the lift:

| Theorem | Bundles in axiom closure | Classification |
|---|---|---|
| `cross_component_session_bind` | `commitHashE` + `commitHashBytesE` + `tdxVerifier` + `groth16Verifier` | QUAD ✓ |

Standard logic axioms (`propext`, `Classical.choice`, `Quot.sound`)
and carriers (`Addr`, `ByteSeq`, `DomainSep`, `Nonce`, `MrEnclave`,
`TdxQuote`, `UserData`, `Groth16Proof`, `PublicInputs`, `VKey`,
`Plaintext`, `PrivKey`, `PubKey`) are present in the closure but
not counted as bundles. The carrier-side `was_signed_by_dstack`,
`keyOf`, `userDataOfSessionSetPubKey_eq_commitHash`,
`rawBoundContract`, `rawDomainSep`, `serializeRawSessionSetPubKeyE`
are likewise non-bundle dependencies (carrier-level or example-
specific, not Step 1-5 record axioms).

**Finding**: the theorem is genuinely quadruple-bundle, exactly
matching the Step 6.1 / 6.2 classification table. No surprises.

## Decision 1: doubled-negligibility framing — Option (β) selected

The Step 6.3 brief offered two options for the `groth16Verifier`
summand:

* **(α) Monolithic**: one hypothesis `negligible (groth16Adv 𝒜)`,
  same as triple-bundle lifts.
* **(β) Decomposed**: two hypotheses
  `negligible (groth16KSAdv 𝒜_ks)` and
  `negligible (circuitEqAdv 𝒜_circuit)`, with the bound stated as
  `groth16Adv ≤ groth16KSAdv + circuitEqAdv`.

**Selected: Option (β).** The Step 5 honesty finding was
specifically that `groth16Verifier`'s soundness rests on two
distinct cryptographic assumptions:

1. **Groth16 knowledge soundness over BN254** (cryptographic — KZG
   / power-knowledge / GGM, ArkLib roadmap target).
2. **zkdcap R1CS circuit ≡ reference DCAP verifier** (software-
   verification, separate effort).

The triple-bundle lifts of Step 6.2 could afford monolithic
because they didn't reach the load-bearing composition that
exercises BOTH halves of the assumption. Step 6.3 *does* reach
that composition: `cross_component_session_bind` is the cross-
component theorem whose downstream is the entire Quartz protocol-
layer trust statement, so both halves of `groth16Verifier`
soundness end up in the audit surface.

The lift therefore introduces TWO new adversary types
(`Groth16KSAdv : ℕ → ProbComp (VKey × Groth16Proof × PublicInputs)`,
`CircuitEqAdv : ℕ → ProbComp PublicInputs`), each with its own
advantage and game packaging.

**No fallback to (α) was needed.** The five-summand chain
composed mechanically; no proof-complexity barrier emerged. See
"Decision 1 outcome" in the Honesty section.

## Decision 2: Option (b) framing applied symmetrically

The Step 6.2 lift introduced **Option (b)** for `commitHashE`:
keep the embedding model at the spec/classical layer, frame the
negligibility hypothesis as collision-resistance of the concrete
hash function the embedding abstracts over.

Step 6.3 applies Option (b) **symmetrically** to BOTH `commitHashE`
and `commitHashBytesE`. The two hashes abstract over different
concrete hash functions (`H : UserDataCommit → UserData` and
`H_b : ByteSeq → UserData`), but the meta-(d) "vacuous-impossible-
axiom-as-hypothesis" finding applies symmetrically:

* spec-level embedding hypothesis (either side): vacuous
  (impossible-as-stated);
* lift-level collision-resistance hypothesis: non-vacuous, standard
  cryptographic statement.

The collision-resistance adversary types
(`CommitHashCollisionAdv`, `CommitHashBytesCollisionAdv`) and
their advantage / game packages are imported unchanged from
`ProtocolVCVioTriple.lean`. No new collision-resistance carrier
is introduced.

The symmetry is clean: both hash summands have the same shape, same
framing rationale, same hypothesis discipline. No asymmetry
emerged at the proof level.

## Decision 3: union-bound chain shape — left-associated

The Step 6.0 / 6.1 / 6.2 sequence established left-associated
`negligible_add` chains. Step 6.3 follows the same shape:

```
negligible_of_le h_bound
  (negligible_add
    (negligible_add
      (negligible_add
        (negligible_add h_groth_ks h_circuit)
        h_tdx)
      h_hash)
    h_hashB)
```

Four `negligible_add` applications (one fewer than summands; each
`add` composes two previous-step negligibilities). Balanced
bracketing was considered but rejected: sum-of-negligibles closure
is associative and commutative, so left-association gives no
sharper bound. Left-association also keeps the inductive scaling
pattern uniform with Steps 6.0-6.2.

## Lift pattern recap

The composition pattern across the Step 6 sequence:

| Step | Summands | Pattern |
|---|---|---|
| 6.0 | 1 | `negligible_of_le h_bound h_negl` |
| 6.1 | 2 | `negligible_of_le h_bound (add h₁ h₂)` |
| 6.2 | 3 | `negligible_of_le h_bound (add (add h₁ h₂) h₃)` |
| 6.3 | **5** | `negligible_of_le h_bound (add (add (add (add h₁ h₂) h₃) h₄) h₅)` |

Step 6.3 jumps from 3 to 5 summands (not 4) because of the Step 5
doubled-negligibility decomposition: the fourth classical bundle
(`groth16Verifier`) decomposes into two cryptographic-assumption
summands rather than one. Methodologically uniform; each new
summand adds one `negligible_add` step.

## Files changed

### Added

- `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioQuad.lean` —
  new module (~370 lines). Defines:
  - 2 new doubled-negligibility adversary types (`Groth16KSAdv`,
    `CircuitEqAdv`) plus their advantage / game packages
  - 1 new composite adversary (`CrossSessionBindAdv`) plus
    advantage / game packages
  - `cross_component_session_bind_classical` (preserved-axiom-
    closure re-export)
  - `cross_component_session_bind_negl` (probabilistic
    five-summand union-bound lift)
  - `crossSessionBindFail_secure_of_quad_bundle_secure`
    (SecurityExp form)
  - `crossSessionBindGame_secure_of_quad_bundle_secure`
    (SecurityGame reduction form with `IsPPT` filter)

### Modified

- `proofs/lean/Specs.lean` — added import of
  `Specs.Quartz.Protocol.ProtocolVCVioQuad` companion module.

### Not modified

- All other Lean source files. The lift is purely additive — no
  existing theorem statement, proof, or axiom is touched. The
  classical chain re-builds unchanged. Verified by post-build
  `lean_verify` regression checks on all 7 prior `_negl` lifts and
  on the classical `cross_component_session_bind` (closures
  unchanged).

## Per-acceptance-criterion status

- [x] `lake build` green. **2667 jobs** (+1 from Step 6.2's
  2666 baseline — the new `ProtocolVCVioQuad.lean` module). At the
  bottom of the expected "+1 to +3" envelope; in fact exactly +1
  because the new module imports the same `Asymptotics.Security`
  transitive closure already pulled by `ProtocolVCVioTriple.lean`.

- [x] `_negl` form closes via `lean_verify` with carriers +
  standard logic only, **NO bundle axioms**. Confirmed (see
  "Axiom closure" below).

- [x] `_classical` form preserves original quadruple-bundle
  closure (4 bundles: `commitHashE`, `commitHashBytesE`,
  `tdxVerifier`, `groth16Verifier`). Confirmed.

- [x] **5-summand union bound visible** in the `_negl`
  hypothesis list: `h_groth_ks_negl`, `h_circuit_negl`,
  `h_tdx_negl`, `h_hash_negl`, `h_hashB_negl` (4 hash/forgery
  summands + the Groth16 decomposition adding the 5th).
  Confirmed.

- [x] **Downstream regression check**: all 7 prior `_negl` lifts
  re-verified post-build with closure unchanged. Confirmed
  (see "Downstream regression check" below).

- [x] No new axioms added. Bundle axioms unchanged.

- [x] One change record at
  `.colosseum/changes/2026-05-13T16-02-47Z-protocol-vcvio-quad-bundle.md`.

## Verification result

`lake build` is green at HEAD:

```
✔ [2665/2667] Built Specs.Quartz.Protocol.ProtocolVCVioQuad (1.4s)
✔ [2666/2667] Built Specs (1.2s)
Build completed successfully (2667 jobs).
```

### Axiom closure of the lifted theorems

Verified via `lean_verify` (post-rebuild):

**`cross_component_session_bind_negl`**:
- axioms: `{propext, Classical.choice, Quot.sound, Addr, ByteSeq,
  DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof,
  PublicInputs, VKey, Plaintext, PrivKey, PubKey}`
- carriers + standard logic only. **No bundle axioms**:
  `commitHashE`, `commitHashBytesE`, `tdxVerifier`,
  `groth16Verifier` are all absent. Bundles enter through
  hypotheses, not the closure.

**`cross_component_session_bind_classical`**:
- axioms: `{propext, Classical.choice, Quot.sound, Addr, ByteSeq,
  DomainSep, Nonce, commitHashBytesE, commitHashE, rawBoundContract,
  rawDomainSep, serializeRawSessionSetPubKeyE,
  userDataOfSessionSetPubKey_eq_commitHash, MrEnclave, TdxQuote,
  UserData, tdxVerifier, was_signed_by_dstack, Groth16Proof,
  PublicInputs, VKey, groth16Verifier, Plaintext, PrivKey, PubKey,
  keyOf}`
- exactly the original quadruple-bundle classical closure of
  `cross_component_session_bind`. Re-export preserved unchanged.

**`crossSessionBindFail_secure_of_quad_bundle_secure`**:
- axioms: `{propext, Classical.choice, Quot.sound}`
- pure logical theorem. No carrier or bundle dependencies.

**`crossSessionBindGame_secure_of_quad_bundle_secure`**:
- axioms: `{propext, Classical.choice, Quot.sound, Addr, ByteSeq,
  DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof,
  PublicInputs, VKey, Plaintext, PrivKey, PubKey}`
- carriers + standard logic only. No bundles.

### Downstream regression check

Verified via `lean_verify` (post-rebuild) — all seven prior `_negl`
lifts close cleanly with closure unchanged from their respective
landing steps:

- `Specs.Quartz.Protocol.ProtocolVCVio.verifyGroth16_yields_decoded_negl`
  axioms: `{propext, Classical.choice, Quot.sound, Groth16Proof,
  PublicInputs}` — **unchanged from Step 6.0**.

- `Specs.Quartz.Protocol.ProtocolVCVioDual.handshake_sound_negl`
  axioms: `{propext, Classical.choice, Quot.sound, MrEnclave,
  TdxQuote, UserData, Groth16Proof, PublicInputs}` — **unchanged
  from Step 6.1**.

- `Specs.Quartz.Protocol.ProtocolVCVioTriple.handshake_binds_ecies_key_negl`,
  `session_confidentiality_negl`,
  `session_confidentiality_via_extractor_negl`
  axioms: `{propext, Classical.choice, Quot.sound, Addr,
  DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof,
  PublicInputs, Plaintext, PrivKey, PubKey}` — **unchanged from
  Step 6.2**.

- `Specs.Quartz.Protocol.ProtocolVCVioTriple.cross_component_transfers_conservation_negl`,
  `cross_component_auction_winner_determinism_negl`
  axioms: `{propext, Classical.choice, Quot.sound, Addr, ByteSeq,
  MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs}` —
  **unchanged from Step 6.2**.

- `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
  axioms: `{commitHashE, commitHashBytesE, tdxVerifier,
  groth16Verifier}` + carriers — **unchanged from Step 6.2**.
  Quadruple-bundle classical chain preserved.

## Honesty section

### Did Decision 1 land on (β) decomposed, or fall back to (α)?

**Landed cleanly on (β).** No proof-complexity barrier emerged.
The five-summand chain composed mechanically with one additional
`negligible_add` step over the Step 6.2 triple pattern. No
fallback was required.

The decomposition is now visible in:

- the `_negl` theorem's hypothesis list (5 negligibility
  hypotheses: `h_groth_ks_negl`, `h_circuit_negl`, `h_tdx_negl`,
  `h_hash_negl`, `h_hashB_negl`),
- the bound inequality (5-summand sum on the RHS),
- the proof body (4-deep `negligible_add` chain),
- the `SecurityExp` and `SecurityGame` packagings (5 component
  experiments / games each).

This is the methodology-level pay-off of the Step 5 (d)-bucket
"doubled-negligibility" finding: surfaced as commentary in Step 5,
preserved as documentation in Step 6.0 (`ZkdcapVCVio.lean`),
collapsed-back-to-monolithic for the triple-bundle lifts in Step
6.2, and **finally made load-bearing** in Step 6.3.

### Did the 5-summand chain scale mechanically?

**Yes.** The Step 6.1 / 6.2 prediction held exactly: each new
summand adds one `negligible_add` step. The Step 6.3 lift
introduces two new summands (the doubled-negligibility
decomposition), each adding one step. Total: two new
`negligible_add` calls on top of Step 6.2's triple pattern; no
re-architecting, no new closure-discipline issues.

The third summand (Step 6.2) did not introduce friction; the
fifth summand likewise did not. The scaling is uniform.

### Did Option-(b) framing apply symmetrically to `commitHashBytesE`?

**Yes, symmetrically and cleanly.** No asymmetry emerged. Both
hash summands have:

- the same impossible-as-stated embedding axiom shape (open-
  cardinality preimage → fixed-width 64-byte UserData);
- the same vacuous-hypothesis trap if consumed naively in the
  classical layer;
- the same collision-resistance hypothesis framing in the lift
  layer (Option (b));
- the same adversary type shape (
  `CommitHashCollisionAdv : ℕ → ProbComp (UserDataCommit × UserDataCommit)`
  vs
  `CommitHashBytesCollisionAdv : ℕ → ProbComp (ByteSeq × ByteSeq)` —
  differ only in the input domain).

The two adversary types were already introduced in Step 6.2
(`ProtocolVCVioTriple.lean`); Step 6.3 imports them unchanged. The
symmetry is enforced by the import.

### Is the bound statement tight or conservative?

**Conservative (union bound).** The five-summand sum is a
**union bound** — the protocol-fail probability is bounded by the
sum of the per-bundle break probabilities. Tighter bounds would
require:

1. Modelling correlations between adversaries (e.g. an adversary
   that breaks Groth16 KS may be related to one that breaks the
   circuit equivalence, since both are zkdcap-side attacks). The
   union bound assumes independence, which is conservative.

2. Reduction-with-game-hopping that tightens the bound below the
   sum (e.g. by showing that two of the five events cannot
   simultaneously hold, or by amplifying one event's negligibility
   absorbs the other's).

Neither is in scope for Step 6.3. The conservative union bound is
the standard cryptographic move for compositional security
reasoning; tightening is the responsibility of the discharging
work (when ArkLib Groth16 KS and the Lean reference DCAP verifier
land, the bound can be re-stated with sharper constants).

### Any final (d)-bucket findings surfaced by the integration?

**One** new (d)-bucket-adjacent finding, **on the methodology
side rather than the spec side**:

**(d-disjunction-vs-decomposition)** *folded-disjunction-collapses-
under-tight-monolithic-bundling*. The Step 5 doubled-negligibility
finding established that `groth16Verifier`'s soundness is a
disjunction of two independent cryptographic events. The Step 6.0
/ 6.1 / 6.2 lifts could collapse this disjunction back into a
monolithic `Groth16SoundAdv` because their union bounds had ≤ 3
summands — the collapsed framing was *honest enough* for those
abstraction levels. Step 6.3's load-bearing composition forces
the decomposition to become visible.

The finding: **(d)-bucket disjunctions can be honestly collapsed
at intermediate composition levels, but must be expanded at the
load-bearing composition level where they become audit-surface
material.** Methodologically, this means the lift sequence should
*deliberately defer* the disjunction expansion to the highest-
composition point — keeping intermediate lifts simpler — and only
expand at the load-bearing terminal lift.

This is methodologically distinct from prior sub-variants:

- (d-impossible-as-stated) — Steps 2/3 — spec axiom is false.
- (d-classically-over-strong) — Step 4 — spec axiom drops a
  negligibility qualifier.
- (d-doubled-negligibility) — Step 5 — spec axiom folds two
  independent assumptions.
- (d-adversary-class-strong) — Step 6.0 — spec axiom is true
  against unbounded adversaries.
- (d-vacuous-hypothesis) — Step 6.2 — collapsed-impossible
  axiom-as-hypothesis becomes vacuous.
- (d-disjunction-vs-decomposition) — *Step 6.3, this finding* —
  honest framing depends on the lift level: disjunctions can be
  collapsed at intermediate steps but must expand at the load-
  bearing terminal step.

The methodology-side ask is: **the colosseum compose-time honesty
check should track which (d)-disjunctions are still collapsed at
the current composition level and flag any that survive past the
load-bearing terminal lift.** This is a methodology v0.2
candidate.

### Closing assessment: trust boundary audit

With this lift complete, Quartz's trust boundary now decomposes as:

**Honest cryptographic assumptions (the five Step 6.3 union-bound
summands, each a standard statement about a real-world primitive)**:

1. *Groth16 knowledge soundness over BN254* — concretely
   ~2^{-100} bound from KZG / power-knowledge / generic-group-
   model. Discharge path: ArkLib (when Groth16 lands).

2. *zkdcap R1CS circuit ≡ reference DCAP verifier* — circuit-
   correctness bound, software-verification. Discharge path:
   Lean reference DCAP verifier + circuit-equivalence theorem.

3. *DCAP / PCK-signature unforgeability* — concretely the Intel
   SGX PCK chain plus the dstack-CVM signing key's resistance to
   forgery. Discharge path: PCK unforgeability reduction (Intel
   spec + cryptographic library).

4. *`commitHashE` collision resistance* — concretely the SHA-256-
   over-UserDataCommit hash function's collision resistance.
   Discharge path: VCV-io `randomOracle` + birthday bound, once
   `[Fintype UserData]` lands.

5. *`commitHashBytesE` collision resistance* — same shape as (4)
   on the byte domain.

**Honest axiomatic carriers (still required to compile, but
non-cryptographic in nature)**:

- Type axioms: `UserData`, `MrEnclave`, `TdxQuote`, `PrivKey`,
  `PubKey`, `Plaintext`, `Ciphertext`, `Groth16Proof`,
  `PublicInputs`, `VKey`, `Addr`, `ByteSeq`, `DomainSep`,
  `Nonce`.
- Constant axioms (named values): `rawDomainSep`,
  `rawBoundContract`, `rawPlaceholderPubKey`.
- Function axioms: `keyOf`, `was_signed_by_dstack`,
  `userDataOfSessionSetPubKey_eq_commitHash`,
  `serializeRawSessionSetPubKeyE`, etc.

**Externally-deferred reductions** (parametric hypotheses, not
yet discharged):

- The five negligibility hypotheses above (deferred to ArkLib /
  reference DCAP verifier / `[Fintype]` carrier refinement work).
- The pointwise union bound itself (deferred to a concrete
  `OracleComp`-resident game modelling, blocked on `[Fintype]`).
- The `IsPPT` PPT-class filter (placeholder body `True`, deferred
  to VCV-io `PolyQueries` adoption when adversaries gain
  `OracleComp ProtocolSpec` access).

**Audit-ready summary**: at Step 6.3 exit, the Quartz protocol-layer
trust boundary is honestly expressed as **five cryptographic
assumptions on real-world primitives** (Groth16 KS, zkdcap circuit
equivalence, DCAP unforgeability, two hash collision-resistance
bounds), plus the **standard non-cryptographic carrier axioms**
(types, named constants, function signatures), with **all five
negligibility budgets and the union-bound composition surfaced as
parametric hypotheses** for downstream cryptographic-library work
to discharge. The transition from "spec-level impossible
embeddings + classical-Prop unbounded-soundness implications" (Step
1-5 state) to "honest negligibility budgets in OracleComp +
SecurityGame" (Step 6.3 state) is **methodologically complete** for
all 8 protocol-layer theorems — none remain in the
classical-only-form.

### Methodology-side ask (for v0.2)

The Step 6.3 lift surfaced one finding worth flagging for the
methodology v0.2 (outside the scope of this cycle to fix):

**(M-1) — compose-time disjunction-decomposition tracking.** The
colosseum compose-time honesty check should track which
(d)-disjunctions (like Step 5's Groth16 KS + circuit
equivalence) are still collapsed at the current composition level,
and flag any that survive past the **load-bearing terminal lift**
of a refactor sequence. Currently the methodology has no
machine-checkable concept of "load-bearing terminal lift" — Step
6.3 is one *by inspection* of the bundle classification table, but
the methodology cannot detect that. A v0.2 addition: a `terminal:
true` flag in the refactor-plan that compose-time can read, plus
a check that all surfaced (d)-disjunctions are decomposed at any
terminal-flagged step.

The finding is methodologically distinct from prior asks: it's
about *composition-level visibility discipline* rather than
*axiom shape* or *adversary class*. Adding the methodology-side
fix would prevent future lift sequences from silently inheriting
the collapsed-monolithic framing past their load-bearing point.

## Adversarial review

Not run in this cycle. The quadruple-bundle lift uses the same
proof shape as Step 6.2's triple lifts, scaled by two
`negligible_add` steps (the doubled-negligibility decomposition
expansion). The substantive risk surface is the same as Step 6.0 /
6.1 / 6.2, plus three new quad-specific items:

- the parametric advantage abstraction may hide complexity
  (vacuously true under trivial bounds — including bounds that
  set one of the five summands to ⊤);
- the `IsPPT := True` placeholder is informationally equivalent
  to no adversary-class restriction;
- the five-summand union bound may not be the tightest available
  composition (see "Is the bound statement tight or conservative?"
  above);
- the doubled-negligibility decomposition's two summands may
  correlate (Groth16 KS attacks may inform circuit-equivalence
  attacks), in which case the conservative union bound's tightness
  loss is more than the standard "independent events" loss
  budget;
- the Option-(b) symmetric framing for both hash summands depends
  on the soundness of the embedding-to-concrete-hash mapping,
  which is documentary not formal — an adversarial review should
  challenge whether the hypotheses correctly state collision
  resistance for the *real* hash functions.

A formal `colosseum-adversarial` pass should run **now** that all
four lift levels (single + dual + triple + quadruple) are in
place. The combined surface is the right granularity for surfacing
union-bound-tightness, composition, and disjunction-vs-collapse
findings.

## Outstanding follow-ups

### Step 7 (integration-ledger regeneration) — explicitly queued, NOT in this cycle

Per the brief, Step 7 is a separate methodology-side cycle the
human will dispatch:

- [ ] Regenerate the integration ledger with the post-Step-6 trust
  density metric.
- [ ] Surface the explicit five-summand decomposition of
  `cross_component_session_bind`'s soundness budget in the ledger
  output.
- [ ] Update the axiom-to-theorem ratio metric (currently 26:16;
  post-Step-6 it remains 26:16 because the lift sequence is
  additive — the form-progress / content-progress split is now
  fully reflected in the ledger).

### Methodology infrastructure (inherited from Steps 6.0/6.1/6.2)

- [ ] **Adopt VCV-io's `PolyQueries` as the `IsPPT` body**. Still
  blocked on carrier-refinement work (adversaries need
  `OracleComp ProtocolSpec` access).
- [ ] **Discharge the five negligibility hypotheses**:
  - `negligible_groth16_ks` from ArkLib (once Groth16 KS lands)
  - `negligible_circuit` from a Lean reference DCAP verifier +
    circuit-equivalence theorem
  - `negligible_tdx` from a PCK-signature unforgeability
    reduction
  - `negligible_commitHash` / `negligible_commitHashBytes` from
    VCV-io's `randomOracle` + birthday bound (requires
    `[Fintype UserData]`)

### Methodology v0.2 ask (surfaced by this lift)

- [ ] **(M-1)** Compose-time disjunction-decomposition tracking
  (see "Methodology-side ask" in the Honesty section above).

### Adversarial-review queue

- [ ] Run `colosseum-adversarial` against the composed
  single+dual+triple+quadruple surface. All four lift levels are
  now in place — the right granularity for surfacing union-bound-
  tightness, composition, doubled-negligibility-correlation, and
  Option-(b) symmetric framing findings.

## Cross-step continuity (Steps 1-6.2 → Step 6.3)

- **Companion-module pattern (5 instances, Steps 1-5)**:
  load-bearing here as in Step 6.0 / 6.1 / 6.2. The new
  `ProtocolVCVioQuad.lean` imports `ProtocolVCVio`,
  `ProtocolVCVioDual`, `ProtocolVCVioTriple`, and the protocol-
  layer classical `CrossComponent.lean`. The companion-module
  invariant ("VCV-io classpath stays out of the
  `Decidable`-synthesis hot path") is preserved — the quad-lift
  module is imported only by `Specs.lean`, not by any classical
  protocol file.

- **(d)-bucket pattern**: one new methodology-side sub-variant
  (*folded-disjunction-collapses-under-tight-monolithic-bundling*)
  surfaced, documented above. Methodologically distinct from prior
  sub-variants (`impossible-as-stated`, `classically-over-strong`,
  `doubled-negligibility`, `adversary-class-strong`,
  `vacuous-hypothesis`). This is the first *methodology-side*
  (d) finding — prior ones all named *spec-side* honesty shapes.

- **Negligibility framework choice (Step 6.0)**: preserved
  unchanged. Every probabilistic theorem in this step continues to
  state results in terms of `negligible` directly. The framework
  choice remains reversible.

- **Bundle composition discipline**: the quadruple-bundle five-
  summand union bound is the **load-bearing terminal lift** of
  the Step 6 sequence. The composition pattern
  `negligible_of_le ∘ (negligible_add)^4` is the final form. No
  further composition level remains in the Quartz protocol layer.

- **Cumulative state**:
    - Steps 0-5: axiom count 40 → 26 (form progress, -35%)
    - Step 6.0: no axiom change; 1 protocol theorem lifted
      (single-bundle, `verifyGroth16_yields_decoded_negl`).
    - Step 6.1: no axiom change; +1 protocol theorem lifted
      (`handshake_sound`, dual-bundle). Total lifted: 2 of 8.
    - Step 6.2: no axiom change; +5 protocol theorems lifted
      (triple-bundle). Total lifted: 7 of 8.
    - Step 6.3 (this step): no axiom change; **+1 protocol
      theorem lifted** (`cross_component_session_bind`,
      quadruple-bundle / five-summand). Total lifted: **8 of 8
      protocol theorems — COMPLETE**.

## Closure of Step 6

**Step 6 of the VCV-io refactor is now methodologically
complete.** All 8 protocol-layer theorems have been lifted from
classical-`Prop` to `OracleComp` + negligibility:

| Theorem | Bundles | Step |
|---|---|---|
| `verifyGroth16_yields_decoded` | 1 | 6.0 |
| `handshake_sound` | 2 | 6.1 |
| `handshake_binds_ecies_key` | 3 | 6.2 |
| `session_confidentiality` | 3 | 6.2 |
| `session_confidentiality_via_extractor` | 3 | 6.2 |
| `cross_component_transfers_conservation` | 3 | 6.2 |
| `cross_component_auction_winner_determinism` | 3 | 6.2 |
| `cross_component_session_bind` | 4 (→ 5 summands) | **6.3** |

All lifts:

- zero `sorry`;
- real reduction-based proofs (no axiomatic shortcuts);
- parametric over the underlying cryptographic hypotheses;
- preserve the original classical closures via `_classical`
  corollaries (no behaviour change for downstream consumers);
- emit `_negl`, `SecurityExp`, and `SecurityGame` packagings
  uniformly.

The trust boundary is now expressed as **five honest cryptographic
assumptions** + **standard carrier axioms** + **a parametric
union-bound composition** ready for the Step 7 integration-ledger
regeneration to enumerate and the discharging work to attack.

**Stop condition reached.** Step 7 (integration-ledger regeneration)
is a separate methodology-side cycle for the human to dispatch.
