# Change record: Protocol VCV-io dual-bundle lift + Step 6.0 finding resolutions (Step 6.1)

- Date: 2026-05-13T15:27:38Z
- Classification: intent-touching (continues the **content-phase**
  VCV-io refactor; lifts one dual-bundle protocol theorem from
  classical-`Prop` to `OracleComp` + negligibility, and resolves
  the two Step 6.0 scaffolding-shape findings) +
  methodology-extension (introduces the project-standard PPT
  predicate stub and the Bool/Prop decidability bridge)
- Intent revision: none (no `intent.md` edit needed — public API
  names preserved; new theorems and resolutions are additive)
- Plan reference: `.colosseum/refactor-plan-vcvio.md` § "Step 6
  detail: OracleComp lift of the protocol layer"
- Predecessor: `2026-05-13T15-18-06Z-protocol-vcvio-foundations.md`
  (Step 6.0)

## Description

Step 6.1 of the VCV-io refactor — the dual-bundle extension of Step
6.0's single-bundle proof-of-concept. Three deliverables:

1. **Resolved both Step 6.0 scaffolding-shape findings**:
   - (A.1) Adversary-class quantification gap → adopted a
     project-standard `IsPPT` placeholder predicate (rationale
     below).
   - (A.2) Win-condition Bool/Prop mismatch on
     `was_signed_by_dstack` → added a `noncomputable local`
     `Decidable` instance via `Classical.propDecidable`.

2. **Lifted the one genuinely-dual-bundle theorem,
   `handshake_sound`**: classical form preserved as a corollary
   (`handshake_sound_classical`); probabilistic form
   (`handshake_sound_negl`) proven without `sorry` as a real
   reduction-based proof using the union-bound pattern
   `negligible_of_le ∘ negligible_add`. Two additional
   convenience packagings via `SecurityExp` and `SecurityGame`.

3. **Deferred three target theorems that turned out
   triple-bundle** to Step 6.2 (see "Bundle classification
   verification" below). Per the brief's
   "if-triple-defer" instruction, these are explicitly
   not-attempted in this cycle.

## Bundle classification verification

Per the brief's "verify bundle composition first" instruction,
each of the four theorems in scope was checked via
`mcp__lean-lsp__lean_verify` *before* attempting the lift:

| Theorem | Bundles in axiom closure | Classification |
|---|---|---|
| `handshake_sound` | `tdxVerifier` + `groth16Verifier` | **DUAL** (lifted) |
| `handshake_binds_ecies_key` | `tdxVerifier` + `groth16Verifier` + `commitHashE` | **TRIPLE** (deferred) |
| `session_confidentiality` | `tdxVerifier` + `groth16Verifier` + `commitHashE` | **TRIPLE** (deferred) |
| `session_confidentiality_via_extractor` | `tdxVerifier` + `groth16Verifier` + `commitHashE` | **TRIPLE** (deferred) |

Standard logic axioms (`propext`, `Classical.choice`, `Quot.sound`)
and carriers (`MrEnclave`, `TdxQuote`, etc.) are present in all four
closures and not counted as bundles.

**Finding**: three of the four originally-targeted dual-bundle
theorems have been **promoted to triple-bundle by Steps 2-5**. Each
now carries an additional `commitHashE` dependency from the Step 2
bundling of `commitHash`'s injectivity claim. This is consistent with
Step 5's analysis of the "downstream cascade" of the Step 2 bundling
(see Step 5's change record for that prediction).

Two additional Step 6.2-scope theorems (cross-component) were also
checked for completeness:

| Theorem | Bundles | Classification |
|---|---|---|
| `cross_component_transfers_conservation` | `tdxVerifier` + `groth16Verifier` + `commitHashBytesE` | **TRIPLE** |
| `cross_component_auction_winner_determinism` | same | **TRIPLE** |

The quadruple-bundle `cross_component_session_bind` was not
re-checked (Step 5's analysis stands: 4 bundles —
`commitHashE` + `commitHashBytesE` + `tdxVerifier` + `groth16Verifier`).

## Part A.1 — Adversary-class quantification (Step 6.0 finding 1)

### Decision: project-standard `IsPPT` placeholder

Step 6.0 left the adversary class implicit. Two options were
evaluated per the brief:

1. **Use VCV-io's `PolyQueries` as-is.** Requires our adversary
   types to be `OracleComp`-valued and indexed by a security
   parameter at the type level (`α β : ℕ → Type` in
   `PolyQueries`'s structure signature). Our current adversary
   types are `ℕ → ProbComp (...)` — no `α` carrier; the
   adversary takes no input; no oracle access. Adapting them to
   `PolyQueries`'s shape would rewrite every adversary type and
   every advantage definition.

2. **Add a project-standard wrapper.** A thin `IsPPT : Adv →
   Prop` predicate that the project defines once and threads
   through every `SecurityGame.secureAgainst` invocation.

**Selected: Option 2**, with the placeholder body `True`. This
is the lighter-touch option (per the brief's "prefer the
lighter-touch option" directive).

### Implementation

Located in `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean`:

```lean
def IsPPT {Adv : Type} (_ : Adv) : Prop := True

@[simp] theorem IsPPT_trivial {Adv : Type} (A : Adv) : IsPPT A := trivial
```

The placeholder is structurally a vacuous filter (every adversary
is "PPT" under it), but it threads the adversary-class parameter
through `SecurityGame.secureAgainst` exactly as VCV-io's
apparatus expects. The reduction theorem
`handshakeSoundnessGame_secure_of_dual_bundle_secure` invokes
this filter as `groth16Game.secureAgainst IsPPT` /
`tdxGame.secureAgainst IsPPT`, demonstrating that the wrapper
plugs in correctly.

### Reversibility

When adversary types gain `OracleComp ProtocolSpec` access (in
the carrier-refinement work queued from Steps 3-5), swap the
`IsPPT` body for `PolyQueries`. The signature
`{Adv : Type} → Adv → Prop` is the shape `secureAgainst` expects,
so the swap is purely internal to the `def`. No theorem
statement changes.

### Honesty caveat

The placeholder `IsPPT := True` means the current lifts are
**informationally equivalent to quantifying over arbitrary
adversaries**. The "PPT filter" is documentary, not load-bearing.
The methodology audit surface explicitly carries this gap
(file-level docstring + this change record's honesty section).

## Part A.2 — Win-condition Bool/Prop mismatch (Step 6.0 finding 2)

### Decision: Decidable reframing via `Classical.propDecidable`

Step 6.0 surfaced that `was_signed_by_dstack` is a `Prop`-only
predicate with no decidability content, blocking `Pr[...]`
measurements over win conditions involving it. Two options per
the brief:

1. **Extractor reformulation**: lift the win condition to return
   a `Bool` by introducing a decision oracle.

2. **Decidable reframing**: add a `Decidable` instance via
   `Classical.propDecidable`.

**Selected: Option 2.** Matches the existing Step 1 Ecies
precedent (`Classical.propDecidable` for `DecidableEq PubKey`
on an abstract carrier). Touches one declaration; preserves all
downstream win-condition formulations.

### Implementation

```lean
noncomputable local instance was_signed_by_dstack_decidable
    (q : TdxQuote) : Decidable (was_signed_by_dstack q) :=
  Classical.propDecidable _
```

The instance is `noncomputable local` to avoid leaking into
downstream type-class search (matching the `Ecies.DecidableEq
PubKey` discipline that prevents instance-synthesis timeouts on
`Decidable (∃ c, …)` goals in `UserDataCommit.lean`).

### Honesty caveat

`Classical.propDecidable` is non-constructive — it asserts
decidability of any proposition under classical logic. The
instance does not claim that `was_signed_by_dstack` is
*computationally* decidable; it just makes the proposition
syntactically `Decidable` so `Pr[...]` can type-check. This is
the standard cryptographic-spec move for off-chain witness
predicates.

## Part B — Dual-bundle lift of `handshake_sound`

### New module

`proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioDual.lean` (366 lines).

Kept separate from `ProtocolVCVio.lean` (609 lines after Part A
additions) per the brief's "sibling file if it grows past
~500 lines" guidance. The two files form the protocol-layer
VCV-io scaffolding together; `Specs.lean` imports both.

### New definitions

- `TdxVerifierSoundAdv : Type := ℕ → ProbComp TdxQuote`
- `TdxVerifierSoundAdvantage : Type := TdxVerifierSoundAdv → ℕ → ℝ≥0∞`
- `tdxVerifierSoundnessGame : ... → SecurityGame TdxVerifierSoundAdv`
- `HandshakeSoundAdv : Type := ℕ → ProbComp HandshakeCheck`
- `HandshakeSoundAdvantage : Type := HandshakeSoundAdv → ℕ → ℝ≥0∞`
- `handshakeSoundnessGame : ... → SecurityGame HandshakeSoundAdv`

### Lifted theorems

```lean
theorem handshake_sound_classical (h : HandshakeCheck) (acc : Accepted h) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q  = some h.msgUserData :=
  handshake_sound h acc

theorem handshake_sound_negl
    (𝒜 : HandshakeSoundAdv)
    (𝒜_groth : Groth16SoundAdv)
    (𝒜_tdx : TdxVerifierSoundAdv)
    (handshakeFailAdv : HandshakeSoundAdv → ℕ → ℝ≥0∞)
    (groth16Adv : Groth16SoundAdvantage)
    (tdxAdv : TdxVerifierSoundAdvantage)
    (h_bound : ∀ n,
      handshakeFailAdv 𝒜 n ≤ groth16Adv 𝒜_groth n + tdxAdv 𝒜_tdx n)
    (h_groth_negl : negligible (groth16Adv 𝒜_groth))
    (h_tdx_negl : negligible (tdxAdv 𝒜_tdx)) :
    negligible (handshakeFailAdv 𝒜) :=
  negligible_of_le h_bound (negligible_add h_groth_negl h_tdx_negl)

theorem handshakeFail_secure_of_dual_bundle_secure
    (handshakeFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (h_bound : ∀ n,
      handshakeFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure : tdxExp.secure) :
    handshakeFailExp.secure := ...

theorem handshakeSoundnessGame_secure_of_dual_bundle_secure
    {handshakeGame : SecurityGame HandshakeSoundAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame : SecurityGame TdxVerifierSoundAdv}
    (reduce : HandshakeSoundAdv → Groth16SoundAdv × TdxVerifierSoundAdv)
    (h_bound : ∀ A n,
      handshakeGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage  (reduce A).2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure : tdxGame.secureAgainst IsPPT) :
    handshakeGame.secureAgainst IsPPT := ...
```

### Proof structure

All four lifted theorems are **proved without `sorry`** as real
reduction-based proofs:

- `handshake_sound_classical`: direct corollary of `handshake_sound`.
- `handshake_sound_negl`:
  `negligible_of_le h_bound (negligible_add h_groth_negl h_tdx_negl)`.
- `handshakeFail_secure_of_dual_bundle_secure`:
  `SecurityExp.secure_of_pointwise_bound` + `negligible_add`.
- `handshakeSoundnessGame_secure_of_dual_bundle_secure`:
  a `SecurityGame.secureAgainst` proof that destructures over the
  adversary class predicate (here `IsPPT`).

The proofs reduce mechanically using `negligible_add` (closure of
negligibility under finite sum, from VCV-io's `Negligible.lean`)
and `negligible_of_le` (pointwise monotonicity). Both are
project-standard meta-theorems.

### Why a dual bound for a singly-bundled conclusion

`handshake_sound`'s classical proof uses only
`groth16Verifier.sound` directly (the `was_signed_by_dstack`
conclusion is delivered by `verifyGroth16_sound`; the TDX
verifier's `complete` field is *not* used in the original proof).
A *minimal* dual-bundle lift could in principle use a single-summand
bound (Groth16 only). However, we use the two-summand bound because:

1. **Cryptographic correctness**: a real adversary can attack
   either bundle independently. The truthful threat surface
   includes TDX forgery even if the *current proof* doesn't
   leverage it.

2. **Composition pattern reuse**: Steps 6.2 / 6.3 will need the
   three- and four-summand union bounds. Building the dual-summand
   pattern here keeps the composition lemmas mechanical.

3. **Zero cost**: the second summand adds one `negligible_add`
   step. The theorem statement carries an additional hypothesis
   (`h_tdx_negl`) but no additional load.

This is documented in the module docstring.

## Honesty section

### Did the lifts produce real reduction-based proofs, or `sorry`-stubs?

**Real reduction-based proofs, zero `sorry`.** Both `_negl` /
`_secure` theorems reduce mechanically via `negligible_of_le` +
`negligible_add` (single composition with a finite-sum closure).

The proofs are **parametric** over:
- the underlying soundness advantages (Groth16, TDX),
- the bound between them and the handshake-fail advantage,
- the reduction map for the `SecurityGame` form.

What is **not** discharged (and would normally be in a `sorry`):

1. The negligibility of the Groth16 soundness advantage — same as
   Step 6.0; requires ArkLib Groth16 KS coverage + a reference
   DCAP verifier in Lean.

2. The negligibility of the TDX-verifier soundness advantage —
   requires a PCK-signature unforgeability reduction (cryptographic)
   + a Lean DCAP verifier model.

3. The pointwise union bound itself — requires modelling the
   protocol-fail event concretely as an `OracleComp`-resident game
   and showing its probability is decomposable into the two
   bundle-fail events.

All three are **external** (cryptographic-library or carrier-
refinement work) or **in-codebase but out-of-scope here**
(`OracleComp`-resident game modelling, blocked on `[Fintype]`
carriers). They are exactly the same shape of future-work as
Step 6.0's single-bundle hypothesis, scaled to two summands.

### How many lifts went through cleanly, how many needed reframing?

**One lift through cleanly** (`handshake_sound`). The proof
shape is identical to Step 6.0's template scaled by one
`negligible_add` step.

**Three lifts deferred** (`handshake_binds_ecies_key`,
`session_confidentiality`, `session_confidentiality_via_extractor`)
because they turned out to be triple-bundle after the Step 2
`commitHashE` bundling. Per the brief's "if-triple-defer"
instruction, these are not attempted here.

**Two scaffolding-shape findings resolved cleanly** (Part A).
The PPT placeholder and the `Decidable` instance both took one
declaration each. Both are reversible (PPT) or non-leaking
(`Decidable` is `local`).

### New (d)-bucket findings?

**One adversary-shape finding confirmed** (already flagged in
Step 6.0, now made machine-checkable):

- **(d-strong)** *adversary-class-strong*: a classical-`Prop`
  axiom is true against *all* adversaries (computationally
  unbounded) but the underlying primitive is only secure against
  PPT adversaries. Step 6.0 surfaced this as commentary; this
  step makes it explicit via the `IsPPT` placeholder. The
  placeholder body is `True` (vacuous filter), so the gap is now
  *named* but not *closed*. Closing it requires adversaries to
  have oracle access and the `PolyQueries` swap.

No new *impossible-as-stated* findings (the (d)-bucket subvariant
from Steps 2-3); no new *single-/doubled-/preconditional-
negligibility* findings (Steps 4-5).

### Any theorems turned out triple-bundle?

**Yes, three out of four** target theorems are triple-bundle:

- `handshake_binds_ecies_key`
- `session_confidentiality`
- `session_confidentiality_via_extractor`

All three pick up a `commitHashE` axiom dependency (from Step 2's
bundling of `commitHash`'s injectivity claim). They are deferred
to Step 6.2 per the brief.

This is consistent with Step 5's prediction: the downstream
protocol-layer theorems carry a `commitHashE` dependency
because they all consume `pkOfUserData_commitHash`, which rides on
the bundled commitment.

This is **the most substantive finding of this cycle** —
the methodology brief's bundle classification needed updating to
reflect the post-Step-5 reality. The Step 6.0 cumulative-state
note ("4 dual-bundle theorems") was correct *as a count of
originally-dual-bundle theorems*; after the Step 1-5 cascades,
only one dual-bundle theorem remains.

## Per-acceptance-criterion status

- [x] `lake build` green. **2665 jobs** (+1 from Step 6.0's
  2664 baseline — the new `ProtocolVCVioDual.lean` module). The
  Part A additions to `ProtocolVCVio.lean` did not change the
  job count (still imports only `Asymptotics.Security` +
  `QueryBound`, both already-pulled transitively).

- [x] `lean_verify` on each lifted theorem confirms axiom
  closure. **`_negl` forms close with carriers + standard logic
  only** — no bundle axioms enter; the bundles enter through
  hypotheses. **`_classical` forms preserve their original
  closure** unchanged.

- [x] One change record at
  `.colosseum/changes/2026-05-13T15-27-38Z-protocol-vcvio-dual-bundle.md`
  covering all lifts, both Step 6.0 finding resolutions, and the
  honesty classification.

- [x] No new axioms added. Bundle axioms unchanged.

## Verification result

`lake build` is green at HEAD:

```
✔ [2663/2665] Built Specs.Quartz.Protocol.ProtocolVCVioDual (1.5s)
✔ [2664/2665] Built Specs (1.3s)
Build completed successfully (2665 jobs).
```

### Axiom closure of the lifted theorems

Verified via `lean_verify` (post-rebuild):

- `Specs.Quartz.Protocol.ProtocolVCVioDual.handshake_sound_negl`
  axioms:
  `{propext, Classical.choice, Quot.sound, MrEnclave, TdxQuote,
    UserData, Groth16Proof, PublicInputs}`
  — **only carriers + standard logic**. Notably, neither
  `tdxVerifier` nor `groth16Verifier` appears. The bundles enter
  through hypotheses, not the closure.

- `Specs.Quartz.Protocol.ProtocolVCVioDual.handshake_sound_classical`
  axioms:
  `{MrEnclave, TdxQuote, UserData, tdxVerifier, was_signed_by_dstack,
    Groth16Proof, PublicInputs, VKey, groth16Verifier}`
  — exactly the original dual-bundle classical closure of
  `handshake_sound`. Re-export preserved unchanged.

- `Specs.Quartz.Protocol.ProtocolVCVioDual.handshakeFail_secure_of_dual_bundle_secure`
  axioms:
  `{propext, Classical.choice, Quot.sound}`
  — pure logical theorem. No carrier or bundle dependencies.

- `Specs.Quartz.Protocol.ProtocolVCVioDual.handshakeSoundnessGame_secure_of_dual_bundle_secure`
  axioms:
  `{propext, Classical.choice, Quot.sound, MrEnclave, TdxQuote,
    UserData, Groth16Proof, PublicInputs}`
  — carriers + standard logic. No bundles.

### Downstream regression check

Verified via `lean_verify` (post-rebuild):

- `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
  axioms:
  `{commitHashE, commitHashBytesE, tdxVerifier, groth16Verifier}`
  + carriers — **unchanged**. Quadruple-bundle composition
  preserved.

- `Specs.Quartz.Protocol.Handshake.handshake_sound` axioms:
  `{tdxVerifier, groth16Verifier}` + carriers — **unchanged**.
  Dual-bundle classical chain preserved.

- `Specs.Quartz.Protocol.ProtocolVCVio.verifyGroth16_yields_decoded_negl`
  axioms:
  `{propext, Classical.choice, Quot.sound, Groth16Proof, PublicInputs}`
  — **unchanged** from Step 6.0. The new `IsPPT` /
  `Decidable was_signed_by_dstack` additions did not pollute
  Step 6.0's closure.

## Files changed

### Modified

- `proofs/lean/Specs.lean` — added import of
  `Specs.Quartz.Protocol.ProtocolVCVioDual` companion module.
- `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean` —
  added `IsPPT` predicate (Part A.1), `Decidable
  was_signed_by_dstack` instance (Part A.2), and the new
  `VCVio.OracleComp.QueryTracking.QueryBound` import (for
  forward compatibility when `IsPPT` swaps to `PolyQueries`).

### Added

- `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioDual.lean` —
  new module (366 lines). Wires up the dual-bundle lift of
  `handshake_sound`: introduces `TdxVerifierSoundAdv` and
  `HandshakeSoundAdv` adversary types; defines the corresponding
  advantage and game packages; proves
  `handshake_sound_classical` (corollary),
  `handshake_sound_negl` (probabilistic lift),
  `handshakeFail_secure_of_dual_bundle_secure` (SecurityExp form),
  and `handshakeSoundnessGame_secure_of_dual_bundle_secure`
  (SecurityGame form with the `IsPPT` adversary filter).

### Not modified

- All other Lean source files. The lift is purely additive — no
  existing theorem statement, proof, or axiom is touched. The
  classical chain re-builds unchanged. Verified by post-build
  `lean_verify` on `cross_component_session_bind` and
  `handshake_sound` (closures unchanged).

## Adversarial review

Not run in this cycle. The dual-bundle lift's proof shape is
mechanical (one `negligible_add` step beyond Step 6.0's pattern);
the substantive risk surface is the same as Step 6.0's:

- the parametric advantage abstraction may hide complexity
  (vacuously true under trivial bounds);
- the `IsPPT := True` placeholder is informationally equivalent
  to no adversary-class restriction;
- the union-bound shape may not compose tightly when Steps 6.2 /
  6.3 stack more summands.

A formal `colosseum-adversarial` pass should run once Step 6.2
lands the first triple-bundle lift. Solo dual-lift is too small
to surface new composition findings.

## Outstanding follow-ups

### Step 6.2 (triple-bundle lifts) — explicitly queued

- [ ] **Lift `handshake_binds_ecies_key`** — adds
  `commitHashE` collision summand. Three-summand union bound.
- [ ] **Lift `session_confidentiality`** — same shape.
- [ ] **Lift `session_confidentiality_via_extractor`** — same shape.
- [ ] **Lift `cross_component_transfers_conservation`** — substitutes
  `commitHashBytesE` for `commitHashE` in the third summand.
- [ ] **Lift `cross_component_auction_winner_determinism`** — same.

### Step 6.3 (quadruple-bundle lift) — queued

- [ ] **Lift `cross_component_session_bind`** — four (or five if
  `groth16Verifier` decomposes into KS + circuit-eq) summands.

### Methodology infrastructure

- [ ] **Adopt VCV-io's `PolyQueries` as the `IsPPT` body**. This
  requires adversary types to gain `OracleComp` access and be
  indexed by a security parameter at the type level. Blocked on
  carrier-refinement work.
- [ ] **Discharge the negligibility hypotheses** (Step 6.0 list
  carries over): ArkLib Groth16 KS, reference DCAP verifier,
  PCK-signature unforgeability, `[Fintype]` carriers.

### Adversarial-review queue

- [ ] Run `colosseum-adversarial` against
  `handshake_sound_negl` once Step 6.2 lands the first triple-
  bundle lift. A composition with three summands surfaces
  union-bound-tightness findings that the dual-only case
  cannot.

## Cross-step continuity (Steps 1-6.0 → Step 6.1)

- **Companion-module pattern (5 instances, Steps 1-5)**:
  load-bearing here as in Step 6.0. The new
  `ProtocolVCVioDual.lean` imports only `ProtocolVCVio` (and
  transitively, the five companion modules). `Specs.lean` is
  the only top-level imported-by file. The companion-module
  invariant ("VCV-io classpath stays out of the
  `Decidable`-synthesis hot path") is preserved: the dual-lift
  module is imported only by `Specs.lean`, not by any
  classical protocol file. The new `Decidable
  was_signed_by_dstack` instance is `local`, so it does not
  leak into the classical chain's type-class search.

- **(d)-bucket pattern**: no new sub-variants. The
  *adversary-class-strong* variant flagged in Step 6.0 is made
  machine-checkable here via the `IsPPT` placeholder; the gap
  is named but not closed (closing requires oracle-access
  adversaries + `PolyQueries`).

- **Negligibility framework choice (Step 6.0)**: preserved
  unchanged. Every probabilistic theorem here continues to
  state results in terms of `negligible` directly. The choice
  remains reversible.

- **Bundle composition discipline**: the dual-bundle union
  bound is the *first non-trivial composition* in the lift
  sequence (Step 6.0 was single-bundle). The composition
  pattern `negligible_of_le ∘ negligible_add` is established
  here and will scale to three-summand (`+ negligible_add`)
  and four-summand union bounds in Steps 6.2 / 6.3.

- **Cumulative state**:
    - Steps 0-5: axiom count 40 → 26 (form progress, -35%)
    - Step 6.0: no axiom change; 1 protocol theorem lifted
      (single-bundle proof-of-concept).
    - Step 6.1 (this step): no axiom change; **+1 protocol
      theorem lifted** (`handshake_sound`, dual-bundle), **+1
      adversary-class predicate** (`IsPPT`), **+1
      decidability bridge** (`was_signed_by_dstack`). Total
      lifted-theorem count: 2 of 8 protocol theorems.
    - Steps 6.2-6.3 (remaining): lift the 6 remaining protocol
      theorems (5 triple-bundle + 1 quadruple-bundle).

## Readiness for Step 6.2 (triple-bundle lifts)

All Step 6.1 deliverables are in place. Step 6.2 can proceed by:

1. Defining a `CommitHashCollisionAdv` adversary type and
   advantage function in `ProtocolVCVio.lean` (or a new
   `ProtocolVCVioTriple.lean` sibling), mirroring the Step 6.0
   `Groth16SoundAdv` and Step 6.1 `TdxVerifierSoundAdv` pairs.

2. Stating the lifted theorems with three-summand union bounds:
   the protocol-fail advantage is bounded by
   `groth16SoundAdv + tdxVerifierSoundAdv + commitHashCollisionAdv`.

3. Proving via `negligible_add` (twice; once for each
   composition step).

4. (Optional) Adopting `PolyQueries` as the `IsPPT` body if
   adversary types have been refined by then.

**Step 6.2 is unblocked.** The dual-bundle pattern proven here
scales mechanically to triple-bundle. The remaining lifts are
scaling along the union-bound dimension, not re-architecting.
