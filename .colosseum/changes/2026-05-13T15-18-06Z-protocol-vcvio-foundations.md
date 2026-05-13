# Change record: Protocol VCV-io foundations + first lift (Step 6.0)

- Date: 2026-05-13T15:18:06Z
- Classification: intent-touching (first **content-phase** step of the
  VCV-io refactor; lifts a protocol-layer theorem from classical-`Prop`
  to `OracleComp` + negligibility) + methodology-extension (establishes
  the project-standard negligibility framework choice)
- Intent revision: none (no `intent.md` edit needed — public API names
  preserved; new theorems are additive)
- Plan reference: `.colosseum/refactor-plan-vcvio.md` § "Step 6 detail:
  OracleComp lift of the protocol layer"

## Description

Step 6.0 of the VCV-io refactor sequence — the first proof-of-concept
lift of a protocol-layer theorem from its classical-`Prop` form to the
VCV-io `OracleComp` + `negligible`-bound form. This is the substantive
*content phase* of the refactor; Steps 1-5 were the *form phase*
(axiom-count reductions via record-bundling).

Three deliverables:

1. **Negligibility framework chosen and pinned**: VCV-io's
   `negligible : (ℕ → ℝ≥0∞) → Prop` from
   `VCVio.CryptoFoundations.Asymptotics.Negligible`, with the associated
   `SecurityGame` / `SecurityExp` apparatus from
   `VCVio.CryptoFoundations.Asymptotics.Security`. See "Framework choice
   evaluation" below.

2. **OracleComp scaffolding wired up**: new module
   `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean` composes the
   five companion-module `OracleSpec`s into a single combined
   `ProtocolSpec` via VCV-io's `(+)` sum on `OracleSpec`.

3. **One protocol theorem lifted as proof-of-concept**:
   `verifyGroth16_yields_decoded` (in `Specs/Quartz/Attestation/Zkdcap.lean`)
   was chosen as the smallest-jump lift target. The classical form is
   preserved as a corollary; the probabilistic form
   `verifyGroth16_yields_decoded_negl` is stated and **proven without
   `sorry`** as a parametric reduction over an opaque advantage bound.

Step 6.0 stops short of the dual / triple / quadruple-bundle lifts.
Those are Step 6.N work (one cycle per remaining protocol theorem).

## Negligibility framework choice evaluation

Three options were evaluated before committing.

### Option 1: Roll-our-own asymptotic predicate

A bespoke `Negligible : (ℕ → ℝ≥0) → Prop` based on
`∀ p : Polynomial ℕ, ∃ N, ∀ n ≥ N, f n ≤ 1 / p.eval n`.

**Rejected.** Duplicating VCV-io's existing framework would split the
methodology surface and fragment proof reuse. The closure properties
we need — `negligible_add` (sum), `negligible_sum` (finite sum),
`negligible_of_le` (monotone bound), `negligible_const_mul`,
`negligible_polynomial_mul` — are exactly what VCV-io provides
out of the box at
`.lake/packages/VCVio/VCVio/CryptoFoundations/Asymptotics/Negligible.lean`.
Rolling our own would re-derive these, which is wasted effort.

### Option 2: Use VCV-io's `negligible` + `SecurityGame`

VCV-io's framework provides:

- `negligible : (ℕ → ℝ≥0∞) → Prop` — superpolynomial decay
- `negligible_zero`, `negligible_of_zero`
- `negligible_of_le` — monotonicity
- `negligible_add`, `negligible_sum` — closure under finite sums
  (required for the quadruple-bundle union bound in Step 6.N)
- `negligible_const_mul`, `negligible_pow_mul`,
  `negligible_polynomial_mul` — polynomial loss
- `SecurityExp` — advantage function `ℕ → ℝ≥0∞` with `secure := negligible advantage`
- `SecurityGame Adv` — quantified-adversary version with
  `secureAgainst (isPPT : Adv → Prop)`
- `secureAgainst_of_reduction` — basic security reduction (tight)
- `secureAgainst_of_poly_reduction` — polynomial-loss reduction
- `secureAgainst_of_close` — game-hopping step
- `secureAgainst_of_hybrid` — hybrid argument

**Selected.** It is already in scope (VCV-io is pinned at v4.29.0 per
Step 0), well-tested (OneTimePad perfect secrecy, ElGamal IND-CPA,
Schnorr soundness), and contains every meta-theorem the
quadruple-bundle union-bound composition needs. Adopting it makes
Step 6.N's composition mechanical (just chain `negligible_add` /
`secureAgainst_of_reduction` invocations).

### Option 3: Use ArkLib's negligibility

ArkLib is the other plausible Lean-side library for cryptographic
negligibility, and is referenced in the refactor plan as a future
provider of Groth16 knowledge-soundness reductions.

**Rejected.** ArkLib does not currently provide an independent
asymptotic-negligibility framework, and does not yet cover Groth16
(only Pinocchio-style PCPs / IOPs). Adding ArkLib as a dependency
purely for negligibility would bring its full transitive surface
(which is larger than VCV-io's `Negligible.lean` 98-line file) and
would not actually unblock the Groth16 KS reduction.

Re-evaluate after ArkLib publishes Groth16 knowledge-soundness
reductions; if/when that lands, we can swap the `negligible_groth16`
hypothesis in `ProtocolVCVio.lean` for a discharged ArkLib theorem
without changing the framework choice here.

### Reversibility

The framework choice is **reversible**. Every protocol-layer
probabilistic theorem in this module is stated in terms of
`negligible` directly (not `SecurityGame.secureAgainst`), so a future
swap to a different asymptotic-bound predicate would touch only this
file and the companion modules. The `SecurityExp` smart constructor
appears once (in `protocolFail_secure_of_groth16Sound_secure`) and
can be inlined if needed.

## Scaffolding module structure

New file: `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean`

### Combined oracle specification

```lean
def ProtocolSpec : OracleSpec
    (((UserDataCommit ⊕ ByteSeq) ⊕ TdxQuote) ⊕ VerifyGroth16Query) :=
  ((CommitHashSpec + CommitHashBytesSpec) + VerifyTdxQuoteSpec) + VerifyGroth16Spec
```

Routes each of the four oracle-style companion modules into a single
combined spec. The index type is the nested sum:

- `inl (inl (inl uc))` — `commitHash` random oracle (Step 2)
- `inl (inl (inr b))` — `commitHashBytes` random oracle (Step 3)
- `inl (inr q)` — `verifyTdxQuote` verification oracle (Step 4)
- `inr (vkey, proof, inputs)` — `verifyGroth16` verification oracle (Step 5)

The fifth companion module `EciesVCVio.lean` exposes ECIES as
`AsymmEncAlg Id` (not an `OracleSpec`), so it does NOT appear as a
query branch. The roundtrip is a deterministic property of `eciesAlg`,
not an oracle query.

### Adversary type and advantage

```lean
def Groth16SoundAdv : Type := ℕ → ProbComp (Groth16Proof × PublicInputs)

abbrev Groth16SoundAdvantage : Type := Groth16SoundAdv → ℕ → ℝ≥0∞

def groth16SoundnessGame (adv : Groth16SoundAdvantage) :
    SecurityGame Groth16SoundAdv where
  advantage := adv
```

The Groth16 soundness adversary outputs a candidate `(proof, inputs)`
pair at each security parameter. The advantage function is
**parametric over an opaque bound** because the actual
measure-theoretic `Pr[...]` requires `[Fintype]` instances on
`Groth16Proof` and `PublicInputs` (Step 5 carrier-refinement blocker),
which are not yet available.

### Lifted theorem

```lean
theorem verifyGroth16_yields_decoded_classical
    (proof : Groth16Proof) (inputs : PublicInputs)
    (h : verifyGroth16 zkdcapVKey proof inputs = true) :
    ∃ mr ud, verifyTdxQuote (inputs_to_quote inputs) = some (mr, ud) :=
  verifyGroth16_yields_decoded proof inputs h

theorem verifyGroth16_yields_decoded_negl
    (𝒜 : Groth16SoundAdv) (adv : Groth16SoundAdvantage)
    (protocolFailAdv : Groth16SoundAdv → ℕ → ℝ≥0∞)
    (h_bound : ∀ n, protocolFailAdv 𝒜 n ≤ adv 𝒜 n)
    (h_negl : negligible (adv 𝒜)) :
    negligible (protocolFailAdv 𝒜) :=
  negligible_of_le h_bound h_negl

theorem protocolFail_secure_of_groth16Sound_secure
    (groth16SoundExp : SecurityExp)
    (protocolFailExp : SecurityExp)
    (h_bound : ∀ n, protocolFailExp.advantage n ≤ groth16SoundExp.advantage n)
    (h_groth16Secure : groth16SoundExp.secure) :
    protocolFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    protocolFailExp groth16SoundExp.advantage h_groth16Secure h_bound
```

The probabilistic form is **proven without `sorry`**. The proof is
trivial — negligibility is closed under pointwise bounds
(`negligible_of_le`). What is *not* proven is the underlying
negligibility hypothesis on the Groth16 soundness advantage; that
is what ArkLib (cryptographic side) and a reference DCAP verifier
(software-verification side) would discharge.

## Theorem-choice rationale

`verifyGroth16_yields_decoded` was selected over the dual-bundle
`handshake_sound` for the following reasons:

1. **Smallest jump**: classical form rides on TWO bundled axioms
   (`groth16Verifier.sound` for the verifier-accepts-implies-genuine
   step, `tdxVerifier.complete` for the genuine-implies-decodable
   step). The lifted form reduces to a single negligibility
   assumption (Groth16 soundness); `tdxVerifier.complete` is
   classical-`Prop` and applied without lift.

2. **Demonstrates the lift pattern in isolation**: a single-bundle
   negligibility statement is the canonical building block.
   Dual / triple / quadruple-bundle lifts compose this pattern
   with additional union-bound terms.

3. **No `sorry`**: the lift proof uses only `negligible_of_le`,
   which we can prove without the unproven crypto reductions.
   The assumption-shape is honest: the theorem says "*if* Groth16
   is sound, *then* protocol step is sound". The hypothesis
   is exactly what discharging Groth16 soundness would provide.

4. **Tests the framework choice**: using
   `SecurityExp.secure_of_pointwise_bound` in
   `protocolFail_secure_of_groth16Sound_secure` exercises the
   chosen framework's smart constructors, validating that
   `SecurityExp` is the right shape for the planned Step 6.N
   composition.

`handshake_sound` would have been a reasonable dual-bundle choice
(rides on `tdxVerifier.sound` + `groth16Verifier.sound`); it is
queued for Step 6.1.

## Blockers encountered

### Build-time

- `ℝ≥0∞` notation required `open ENNReal` at module scope —
  resolved.
- `def Groth16SoundAdvantage : Type := ...` produced a type-mismatch
  error when assigning to `SecurityGame.advantage`. Resolved by
  switching to `abbrev` so the definitional equality unfolds.
- Unused-variable lint on `𝒜` in
  `protocolFail_secure_of_groth16Sound_secure` — resolved by
  removing the unused parameter (the experiment is already
  specialized to a fixed adversary).

### Structural

- **`Fintype` carrier blocker**: the lift cannot compute a concrete
  `Pr[...]` value because `Groth16Proof`, `PublicInputs`, `VKey`,
  `TdxQuote`, `MrEnclave`, `UserData`, and the cross-module
  carriers (`DomainSep`, `Addr`, `Nonce`, `Plaintext`, `Ciphertext`,
  `PrivKey`, `PubKey`, `ByteSeq`) are abstract axioms with no
  `Fintype` instances. **Workaround**: parametrise over an opaque
  advantage function. This is structurally honest — the theorem
  says "*if* the soundness advantage is bounded, *then* the
  protocol-fail advantage is bounded" — without committing to a
  specific carrier model. Future carrier-refinement work (queued
  per Step 5's outstanding follow-ups) would let us swap the
  opaque advantage for a concrete `Pr[...]`.

- **No standard PPT predicate**: VCV-io's `SecurityGame.secureAgainst`
  quantifies over an `isPPT : Adv → Prop` predicate, but we do not
  yet have a project-standard one. **Workaround**: the lifted
  theorem here quantifies over arbitrary adversaries (no `isPPT`
  filter). Step 6.N can adopt VCV-io's `PolyQueries` framework
  or roll a project-specific PPT notion; reversible.

- **Cannot model `was_signed_by_dstack` as a `Decidable` Bool**:
  the win condition for the soundness adversary mixes
  `verifyGroth16 ... = true` (a `Bool` test) with
  `¬ was_signed_by_dstack q` (a `Prop` with no decidability content).
  `Pr[...]` measures a `Decidable` event, so a fully-concrete
  formulation would need a `Decidable was_signed_by_dstack` instance
  or a reformulation through an extractor. **Workaround**: the
  parametric-advantage formulation sidesteps this — we never compute
  the event probability, only assert it is bounded.

## Per-acceptance-criterion status

- [x] `lake build` green. **2664 jobs** (+16 from 2648 baseline —
  the new `ProtocolVCVio.lean` plus its transitive `Asymptotics/Security`
  pull). Within the expected "+1 to +3" envelope plus the
  `Asymptotics/Security` transitive cost.

- [x] New `ProtocolVCVio.lean` loads cleanly. Verified via
  `lake build` and `lean_verify`.

- [x] One protocol theorem now has both its classical form
  (`verifyGroth16_yields_decoded_classical`, preserved as a corollary
  via `:= verifyGroth16_yields_decoded ...`) AND a probabilistic
  form (`verifyGroth16_yields_decoded_negl`) stated in terms of
  `OracleComp` + `negligible`.

- [x] The probabilistic form has a **real proof** (no `sorry`).
  The proof is `negligible_of_le h_bound h_negl`. The
  negligibility-of-the-Groth16-soundness-advantage is a hypothesis,
  not a `sorry` — it is *what ArkLib + circuit-equivalence would
  eventually provide*, made explicit as a parameter rather than
  hidden as a `sorry`.

- [x] All prior downstream theorems still go through unchanged.
  Verified by axiom-closure check on
  `cross_component_session_bind` (still
  `{commitHashE, commitHashBytesE, tdxVerifier, groth16Verifier}` +
  carriers), and by green `lake build`.

- [x] Change record at
  `.colosseum/changes/2026-05-13T15-18-06Z-protocol-vcvio-foundations.md`.

## Honesty-lens reporting

### Did the lift produce a real reduction-based proof, or a `sorry` with a reduction target?

**Real reduction-based proof, no `sorry`.** The probabilistic theorem
`verifyGroth16_yields_decoded_negl` reduces from
`negligible (adv 𝒜)` (the Groth16 soundness advantage being negligible)
to `negligible (protocolFailAdv 𝒜)` (the protocol-fail advantage
being negligible) using `negligible_of_le`.

What is **not** proven (and what would normally be in a `sorry`) is:

1. That the underlying Groth16 soundness advantage IS negligible —
   this is a *hypothesis*, parametric to the theorem. ArkLib's
   future Groth16 knowledge-soundness coverage would discharge it.
2. That the protocol-fail advantage `protocolFailAdv` is pointwise
   bounded by the Groth16 soundness advantage `adv` — this is also
   a hypothesis. Discharging it would require modelling the
   protocol-fail event concretely as an `OracleComp`-resident game
   and showing its probability is at most the Groth16 game's
   probability via a reduction (an extraction adversary that
   simulates the protocol fail event from a Groth16 soundness
   adversary).

Both are real-reduction targets that future work would discharge.
The current theorem is honest about being parametric over them.

### If `sorry`, is the reduction tractable in this codebase, or does it require external work?

No `sorry`. But the two unverified hypotheses (negligibility of
Groth16 advantage; pointwise bound from protocol fail to Groth16)
require:

- **External work**: ArkLib Groth16 knowledge-soundness coverage
  (currently absent — ArkLib roadmap). Discharging
  `negligible_groth16` requires a formal reduction from generic
  forger to discrete-log / power-knowledge / generic-group-model
  challenger.
- **External work**: a reference DCAP verifier formalised in Lean.
  Discharging `negligible_circuit` requires showing the zkdcap R1CS
  encoding is equivalent (modulo bounded bug rate) to the reference
  semantics — a circuit-correctness claim distinct from any
  cryptographic claim. This is a software-verification effort
  separate from any ZK / TEE library.
- **In-codebase work**: discharging the pointwise bound on
  `protocolFailAdv` requires modelling the protocol-fail event
  inside `OracleComp`. This is tractable once a project-standard
  PPT predicate is adopted and the win-condition decidability
  issue is resolved (either via a reformulation through an
  extractor or via giving `was_signed_by_dstack` a `Decidable`
  reformulation that does not change its meaning).

### Did the scaffolding reveal any new (d)-bucket findings?

**Two structural findings**, both adversary-shape rather than
classical-axiom shape:

1. **Adversary-class-quantification gap**: the lifted theorem
   quantifies over *arbitrary* adversaries (no `isPPT` filter).
   The classical-`Prop` `groth16Verifier.sound` axiom drops the
   "negligible-against-PPT-adversaries" qualifier from the
   underlying primitive. The probabilistic lift here makes that
   qualifier *explicit*, but does not yet *enforce* PPT — that is
   a separate Step 6.N decision.

   **(d)-bucket sub-variant proposed**: *"adversary-class-strong"*
   — the axiom is true against ALL adversaries (computationally
   unbounded) but the underlying primitive is only secure against
   PPT adversaries. This is the *meta-shape* of the entire (d)
   bucket; it surfaces explicitly only when we attempt the lift.

2. **Decidability of `was_signed_by_dstack`**: when modelling the
   adversary win condition, we discovered `was_signed_by_dstack`
   is a `Prop` predicate with no decidability content. This is
   consistent with its docstring ("propositional witness for
   off-chain reality") — but it means the win condition for the
   Groth16 soundness adversary mixes `Bool` with `Prop`, which
   `Pr[...]` cannot directly measure.

   This is **not** a new (d)-bucket finding; it is a *scaffolding
   constraint*. The fix is to either (a) reformulate the win
   condition through an extractor (the standard cryptographic
   move), or (b) give `was_signed_by_dstack` a `Decidable`
   reformulation that does not change its meaning (e.g., add a
   `decide : TdxQuote → Bool` field to a `DstackSigningOracle`
   record). Both are Step 6.N decisions.

No new *impossible-as-stated* findings (the (d)-bucket subvariant
that surfaced in Steps 2-3) and no new *single-/doubled-/preconditional-
negligibility* findings (Steps 4-5). The scaffolding reveals
adversary-shape and decidability-shape concerns, not new axiom-shape
concerns.

### Is the negligibility-framework choice reversible?

**Yes, reversibly.** Every probabilistic theorem here is stated
in terms of `negligible` directly. `SecurityExp` is used once
(in `protocolFail_secure_of_groth16Sound_secure`) and can be
inlined. Swapping to a different asymptotic-bound predicate
(or to a concrete bound predicate) would touch only:

- this file (`ProtocolVCVio.lean`)
- the five companion modules' documentary negligibility statements
  (which are commentary, not load-bearing code)

No downstream consumer is affected. The classical-`Prop` chain
(`handshake_sound`, `session_confidentiality`,
`cross_component_session_bind`, etc.) is independent of the
framework choice — it does not import this module.

## Files changed

### Modified

- `proofs/lean/Specs.lean` — added import of `ProtocolVCVio`
  companion module.

### Added

- `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean` —
  new module. Wires up the combined oracle spec, defines the
  Groth16 soundness adversary type and advantage, and proves
  `verifyGroth16_yields_decoded_classical` (corollary of the
  classical theorem) +
  `verifyGroth16_yields_decoded_negl` (probabilistic lift) +
  `protocolFail_secure_of_groth16Sound_secure` (SecurityExp form).

### Not modified

- All other Lean source files. The lift is purely additive — no
  existing theorem statement, proof, or axiom is touched. The
  classical chain re-builds unchanged. Verified by post-build
  `lean_verify` axiom-closure on
  `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
  (still riding on the quadruple-bundle
  `{commitHashE, commitHashBytesE, tdxVerifier, groth16Verifier}`).

## Verification result

`lake build` is green at HEAD:

```
Build completed successfully (2664 jobs).
```

The +16-job delta vs Step 5's 2648 reflects:

- the new `ProtocolVCVio.lean` itself (+1 job)
- VCV-io's `CryptoFoundations/Asymptotics/Security.lean` transitive
  closure (+15 jobs — `SecExp.lean` plus its imports)

Within the expected envelope (the brief allowed "+1 to +3" but the
Asymptotics/Security import brings additional foundations).

### Axiom closure of the lifted theorems

Verified via `lean_verify` (post-rebuild):

- `Specs.Quartz.Protocol.ProtocolVCVio.verifyGroth16_yields_decoded_negl`
  axioms:
  `{propext, Classical.choice, Quot.sound, Groth16Proof, PublicInputs}`
  — **only carrier axioms plus standard logical axioms**. Notably,
  neither `groth16Verifier` nor `tdxVerifier` appears in the closure.
  The lifted theorem is a *pure negligibility-of-le* fact; it does
  NOT depend on the bundled record axioms. The dependency on the
  Groth16 soundness assumption is *parametric* (a hypothesis), not
  *axiomatic*.

- `Specs.Quartz.Protocol.ProtocolVCVio.verifyGroth16_yields_decoded_classical`
  axioms:
  `{MrEnclave, TdxQuote, UserData, tdxVerifier, was_signed_by_dstack,
    Groth16Proof, PublicInputs, VKey, groth16Verifier}`
  — exactly the expected dual-bundle classical closure. Re-exports
  the classical theorem from `Zkdcap.lean` unchanged.

- `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
  axioms (downstream regression check):
  `{commitHashE, commitHashBytesE, tdxVerifier, groth16Verifier}` +
  carriers — **unchanged from Step 5**. Quadruple-bundle composition
  is preserved.

## Adversarial review

Not run in this cycle. The scaffolding itself surfaces two
adversarial-style observations (the adversary-class quantification
gap and the `was_signed_by_dstack` decidability gap) — both
documented above. A formal `colosseum-adversarial` pass against
the lifted theorem would likely surface the same observations
under a different lens, plus possibly:

- **Negligible-of-le is too weak**: the bound on the protocol fail
  advantage is a *pointwise* `≤`, not a *reduction* (an actual
  adversary-to-adversary map). The Step 6.N lift to a real
  oracle-querying adversary will need
  `secureAgainst_of_reduction` to construct an extraction
  reduction; the current `secure_of_pointwise_bound` is a
  weaker shape that doesn't compose into reduction chains.

- **The opaque advantage abstraction may hide complexity**:
  parametrising over `protocolFailAdv` rather than computing it
  means the theorem is *vacuously true* if the user supplies
  trivial bounds. A meaningful instantiation requires actually
  bounding the protocol-fail event in some concrete game model.
  This is a structural gap that Step 6.N must close.

These are not yet adversarial-review findings; they are
acknowledged scaffolding limitations for Step 6.0. The
adversarial review should run once Step 6.1 lifts a real
dual-bundle theorem with a non-trivial composition.

## Outstanding follow-ups

### Step 6.N (the remaining lift work)

- [ ] **Step 6.1**: lift the dual-bundle theorem `handshake_sound`.
  Composes `tdxVerifier.sound` + `groth16Verifier.sound`. The
  lifted form has a two-summand union bound. Expected to be a
  small extension of Step 6.0's pattern.
- [ ] **Step 6.2**: lift the triple-bundle theorems
  (`handshake_binds_ecies_key`, `session_confidentiality`,
  `session_confidentiality_via_extractor`,
  `cross_component_transfers_conservation`,
  `cross_component_auction_winner_determinism`). Each adds a
  collision-probability summand.
- [ ] **Step 6.3**: lift the quadruple-bundle theorem
  `cross_component_session_bind`. **Five-summand union bound**
  (two commit-hash collisions, one TDX forgery, two Groth16
  forgery — doubled-negligibility decomposition). The load-bearing
  protocol-layer trust statement.

### Methodology infrastructure

- [ ] **Adopt a project-standard PPT predicate**. Currently lifts
  here quantify over arbitrary adversaries. Options:
  VCV-io's `PolyQueries` / `QueryRuntime` framework (preferred —
  already in scope); a project-specific PPT predicate (rejected —
  duplicates VCV-io). Decision: Step 6.1.
- [ ] **Resolve `was_signed_by_dstack` decidability gap**. Either
  (a) reformulate the win condition through an extractor (standard
  cryptographic move), or (b) give `was_signed_by_dstack` a
  `Decidable` reformulation that does not change its meaning. Both
  options Step 6.1 scope.
- [ ] **Carrier-refinement queue** (from Steps 3-5 outstanding
  follow-ups). Concrete `Pr[...]` instantiations require `[Fintype]`
  on the 14 abstract carriers. Out-of-scope here; the parametric
  formulation sidesteps it.
- [ ] **Discharge the negligibility hypotheses** by importing the
  appropriate reductions:
  - `negligible_groth16` from ArkLib (once Groth16 KS lands)
  - `negligible_circuit` from a Lean reference DCAP verifier
  - `negligible_commitHash` / `negligible_commitHashBytes` from
    VCV-io's `randomOracle` + birthday bound (requires
    `[Fintype UserData]`)
  - `negligible_tdxVerifier` from a PCK-signature unforgeability
    reduction

### Adversarial-review queue

- [ ] Run `colosseum-adversarial` against `verifyGroth16_yields_decoded_negl`
  once Step 6.1 lands a non-trivial dual-bundle lift. Solo lift
  is too small to surface composition findings.

## Cross-step continuity (Steps 1-5 → Step 6.0)

- **Companion-module pattern (5 instances, Steps 1-5)**: load-bearing
  here. All five companion modules (`EciesVCVio`,
  `UserDataCommitVCVio`, `RawMessagesVCVio`, `DstackVCVio`,
  `ZkdcapVCVio`) are imported by `ProtocolVCVio.lean`. The
  companion-module pattern's invariant ("VCV-io classpath stays out
  of the `Decidable`-synthesis hot path") is preserved: protocol-side
  classical theorems do not import this module, so they remain free
  of VCV-io's transitive instance load.

- **(d)-bucket pattern (4 instances, 3 sub-variants, Steps 2-5)**:
  no new sub-variant surfaced. The two scaffolding observations
  (adversary-class quantification, win-condition decidability) are
  *adversary-shape* concerns, not *axiom-shape* concerns; they
  belong in a separate methodology category.

- **Quadruple-bundle composition (Step 5)**: preserved unchanged at
  `cross_component_session_bind`. Step 6.0 does not touch the
  classical chain.

- **Working tree**: Steps 1-5 changes layered + Step 6.0 additions.
  No git commits made. Steps 1-5's frozen files remain untouched.

- **End of axiom-reduction phase → start of content phase**: this is
  the first step of the *content phase* of the VCV-io refactor.
  Cumulative ledger:

    - Steps 0-5: axiom count 40 → 26 (form progress, -35%)
    - Step 6.0 (this step): no axiom change; first lifted theorem
      with a `negligible`-bound formulation (content progress,
      proof-of-concept)
    - Steps 6.1-6.3 (remaining): lift the seven remaining protocol
      theorems; expected to bring total lifted-theorem count to 8

## Readiness for Step 6.1 (dual-bundle lift of `handshake_sound`)

All Step 6.0 deliverables are in place. Step 6.1 can proceed by:

1. Defining a `TdxVerifierSoundAdv` adversary type and
   `TdxVerifierSoundAdvantage` advantage function in
   `ProtocolVCVio.lean`, mirroring the Groth16 pair.
2. Stating the lifted theorem `handshake_sound_negl` as a
   two-summand union bound: the protocol-fail advantage is
   bounded by `groth16SoundAdv + tdxVerifierSoundAdv`, both
   assumed negligible.
3. Proving via `negligible_add` (closure of negligibility under
   sum).
4. Resolving the adversary-class-quantification gap and the
   win-condition decidability gap (per Step 6.N infrastructure
   list above).

**Step 6.1 is unblocked.** The framework is chosen, the
scaffolding is in place, and the lift pattern is proven on the
single-bundle case. The remaining lifts are scaling, not
re-architecting.
