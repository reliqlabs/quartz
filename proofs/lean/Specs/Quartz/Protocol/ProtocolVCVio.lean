/-
  Protocol-layer VCV-io scaffolding — Step 6.0 of the VCV-io refactor.

  --------------------------------------------------------------------
  Methodology rationale
  --------------------------------------------------------------------

  Steps 1-5 of the VCV-io refactor reduced 40 axioms to 26 by
  bundling load-bearing trust assumptions into records and surfacing
  five companion modules (`EciesVCVio`, `UserDataCommitVCVio`,
  `RawMessagesVCVio`, `DstackVCVio`, `ZkdcapVCVio`) that sketch the
  truthful `OracleSpec` / `OracleComp` interpretation of each
  primitive. Each companion module documents — but does not yet
  prove — the negligibility statement the corresponding bundled
  axiom *should* discharge to.

  This module is the **first proof-of-concept lift** of a protocol-
  layer theorem from its classical-`Prop` form into the VCV-io
  `OracleComp` + `negligible` form. It does three things:

  1. **Wires up the five companion `OracleSpec`s** into one combined
     protocol-layer specification `ProtocolSpec` (via VCV-io's
     `(+)` sum on `OracleSpec`).

  2. **Defines protocol-layer adversary types and advantage
     functions** using VCV-io's `SecurityGame` /
     `SecurityExp` apparatus from
     `VCVio.CryptoFoundations.Asymptotics.Security`.

  3. **Lifts ONE simple theorem** — `verifyGroth16_yields_decoded`
     — into both its classical and probabilistic forms. The
     classical form is preserved as a corollary; the probabilistic
     form states the negligibility-bound version directly in terms
     of `negligible`, parametrised by the (truthful) Groth16
     soundness advantage assumption.

  Theorem choice rationale: `verifyGroth16_yields_decoded` is the
  smallest non-trivial protocol-layer theorem in the post-Step-5
  axiom closure. Its classical form rides on only TWO bundled
  axioms (`groth16Verifier` and `tdxVerifier`). Lifting it
  demonstrates the negligibility-bound pattern with the minimum
  amount of bundle composition (the quadruple-bundle target
  `cross_component_session_bind` is **explicitly out of scope** for
  this run — that is Step 6.N work).

  --------------------------------------------------------------------
  Negligibility framework choice
  --------------------------------------------------------------------

  We use VCV-io's project-standard `negligible : (ℕ → ℝ≥0∞) → Prop`
  from `VCVio.CryptoFoundations.Asymptotics.Negligible` and its
  associated `SecurityGame` / `SecurityExp` apparatus from
  `VCVio.CryptoFoundations.Asymptotics.Security`. Three options
  were evaluated:

  * **Roll-our-own asymptotic predicate.** Rejected — duplicating
    VCV-io's `negligible` would split the methodology surface and
    fragment proof reuse. VCV-io's `negligible_add`, `negligible_sum`,
    `negligible_of_le`, `negligible_polynomial_mul`, and
    `negligible_const_mul` are exactly the closure properties the
    quadruple-bundle union bound (Step 6.N) needs.

  * **Use VCV-io's `negligible` + `SecurityGame`.** Selected. The
    framework is already in scope (we pin `VCVio` at v4.29.0), is
    well-tested (proves perfect secrecy of the one-time pad,
    DDH-based ElGamal IND-CPA, Schnorr soundness), and includes
    `secureAgainst_of_reduction`, `secureAgainst_of_close`, and
    `secureAgainst_of_hybrid` — the meta-theorems we need for
    composing the four bundle bounds in `cross_component_session_bind`
    when Step 6.N gets there.

  * **Use ArkLib's negligibility.** Rejected — ArkLib does not yet
    cover Groth16 and does not currently provide an independent
    asymptotic-negligibility framework. Re-evaluate after ArkLib
    publishes Groth16 knowledge-soundness reductions.

  The choice is **reversible**: every protocol-layer probabilistic
  theorem here is stated in terms of `negligible` directly (not
  `secureAgainst`), so a future swap to a different asymptotic-
  bound predicate would touch only this file and the companion
  modules. The `SecurityGame` / `SecurityExp` smart constructors
  are used here only for the protocol-side advantage definition;
  they can be inlined if needed.

  --------------------------------------------------------------------
  Scaffolding module structure
  --------------------------------------------------------------------

  * `ProtocolSpec` — sum of the five companion `OracleSpec`s. The
    index type is the nested sum
    `(EciesQuery ⊕ UserDataCommit ⊕ ByteSeq ⊕ TdxQuote)
        ⊕ VerifyGroth16Query`; each query routes to the
    corresponding companion oracle.

  * `Groth16SoundAdv` — the Groth16 soundness adversary type: a
    function from security parameter to a `ProbComp` outputting
    `(proof, inputs)` that the adversary claims verifies but does
    NOT correspond to a genuinely dstack-signed quote.

  * `groth16SoundAdvantage` — the advantage function of such an
    adversary at security parameter `n`. Currently parametric on
    an opaque `bound : ℕ → ℝ≥0∞` (the actual measure-theoretic
    quantity requires `[Fintype]` on the carriers, which is still
    blocked at the Step 5 boundary).

  * `verifyGroth16_yields_decoded_negl` — the lifted theorem,
    parametric on a negligibility assumption for the underlying
    Groth16 soundness advantage. Reduces protocol-side failure
    probability to `groth16SoundAdvantage` plus the
    `tdxVerifier`-completeness side condition.

  --------------------------------------------------------------------
  What this module does NOT do
  --------------------------------------------------------------------

  * It does **not** make the companion modules load-bearing for the
    other protocol theorems. `Handshake.handshake_sound`,
    `Confidentiality.session_confidentiality`,
    `CrossComponent.cross_component_session_bind`,
    `Conservation.cross_component_transfers_conservation`, and
    `AuctionDeterminism.cross_component_auction_winner_determinism`
    continue to ride on the classical-`Prop` bundled axioms.

  * It does **not** discharge the negligibility budget. The
    `negligible_groth16` + `negligible_circuit` assumptions are
    quantified as hypotheses, not proven. Discharging them
    requires ArkLib Groth16 knowledge-soundness coverage (cryptographic)
    plus a reference DCAP verifier in Lean (software-verification);
    neither is in scope for Step 6.0.

  * It does **not** attempt the quadruple-bundle target
    `cross_component_session_bind_negl`. That theorem's union bound
    has FIVE summands (the four bundles, with `groth16Verifier`
    decomposing into two). Lifting it requires composing all five
    companion-module negligibility assumptions and a non-trivial
    relational-logic proof. Step 6.N scope.

  Outstanding blockers for the rest of Step 6:

  * **Carrier refinement**: the 14 abstract carriers blocking
    concrete `Pr[...]` statements remain abstract. The lift here
    sidesteps this by parametrising over an opaque advantage
    function rather than computing it from first principles.

  * **Adversary efficiency model**: VCV-io's `SecurityGame.secureAgainst`
    quantifies over an `isPPT : Adv → Prop` predicate. We do not
    yet have a project-standard PPT predicate for our adversaries.
    Step 6.N can adopt VCV-io's `PolyQueries`-based notion or roll a
    project-specific one; reversible.
-/

import VCVio.CryptoFoundations.Asymptotics.Security
import VCVio.OracleComp.QueryTracking.QueryBound
import VCVio.OracleComp.SimSemantics.Append
import Specs.Quartz.Crypto.EciesVCVio
import Specs.Quartz.Crypto.UserDataCommitVCVio
import Specs.Quartz.Crypto.RawMessagesVCVio
import Specs.Quartz.Attestation.DstackVCVio
import Specs.Quartz.Attestation.ZkdcapVCVio
import Specs.Quartz.Protocol.Handshake

namespace Specs.Quartz.Protocol.ProtocolVCVio

open ENNReal
open OracleSpec OracleComp

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap
open Specs.Quartz.Crypto.UserDataCommitVCVio
open Specs.Quartz.Crypto.RawMessagesVCVio
open Specs.Quartz.Attestation.DstackVCVio
open Specs.Quartz.Attestation.ZkdcapVCVio
open Specs.Quartz.Protocol.Handshake

/-! ## Combined protocol-layer oracle specification -/

/-- The protocol-layer oracle specification, combining the five
    companion-module specs via VCV-io's `(+)` on `OracleSpec`.

    The index type is the nested sum
    `(((UserDataCommit ⊕ ByteSeq) ⊕ TdxQuote) ⊕ VerifyGroth16Query)`,
    where each summand routes to the corresponding companion oracle:

    * `inl (inl (inl uc))` — `commitHash` random oracle query on a
      structured `UserDataCommit` (Step 2 companion).
    * `inl (inl (inr b))` — `commitHashBytes` random oracle query
      on a `ByteSeq` (Step 3 companion).
    * `inl (inr q)` — `verifyTdxQuote` verification oracle query
      on a `TdxQuote` (Step 4 companion).
    * `inr (vkey, proof, inputs)` — `verifyGroth16` verification
      oracle query on a `VerifyGroth16Query` triple (Step 5
      companion).

    The `EciesVCVio` companion module models ECIES as
    `AsymmEncAlg Id` rather than an `OracleSpec`, so the ECIES
    primitive does **not** appear as a query branch here — its
    roundtrip is a deterministic property of `eciesAlg`, not an
    oracle query. -/
def ProtocolSpec : OracleSpec
    (((UserDataCommit ⊕ ByteSeq) ⊕ TdxQuote) ⊕ VerifyGroth16Query) :=
  ((CommitHashSpec + CommitHashBytesSpec) + VerifyTdxQuoteSpec) + VerifyGroth16Spec

/-! ## Honest deterministic simulator for `ProtocolSpec` (Cycle 6.13)

Round A attack #6 noted `ProtocolSpec` was defined but never *used*:
adversary types were `ℕ → ProbComp T` (no oracle access), so the
spec was structural scaffolding only and downstream lifts could not
distinguish a query-bounded adversary from a computationally
unbounded one.

Cycle 6.13 wires `OracleComp ProtocolSpec` into the adversary types.
The semantics for `Pr[...]` over an `OracleComp` with non-empty spec
require a `QueryImpl` that interprets each oracle query in a target
monad. We use the **honest deterministic interpretation**: each
query returns, via `pure`, exactly the value that the classical
specification function would return on the same input.

### Why "honest deterministic" is the right baseline

Each of the four component `OracleSpec`s wraps a classical-Prop
function from the underlying companion module:

* `CommitHashSpec` ↔ `commitHash : UserDataCommit → UserData`
* `CommitHashBytesSpec` ↔ `commitHashBytes : ByteSeq → UserData`
* `VerifyTdxQuoteSpec` ↔ `verifyTdxQuote : TdxQuote → Option (...)`
* `VerifyGroth16Spec` ↔ `verifyGroth16 : VKey → ... → Bool`

These functions are deterministic projections (or `Function.invFun`
applications) of the bundled record axioms. The "honest" simulator
responds to each query with `pure (f x)` where `f` is the
corresponding classical function. This is the canonical
*deterministic-oracle* model: the oracle's randomness is empty;
the adversary's only source of randomness is its own `unifSpec`
coin flips after `simulateQ`-routing.

This makes the upgraded lifts **strictly stronger than the no-
oracle-access form**: the adversary can now query the four
oracles, observe their (deterministic) responses, and produce its
candidate output. The win predicate is still applied to that
output, and the cryptographic-assumption layer (the
`negligible (groth16SoundnessAdv 𝒜)` hypothesis et al.) is now
parametric over a richer adversary class.

### Why not a *randomised* simulator?

A randomised handler (e.g. `randomOracle` from
`VCVio/OracleComp/QueryTracking/RandomOracle.lean`) is the
*right* model when the underlying primitive is a random oracle —
e.g. `commitHash` modelled as a uniform-random function from
`UserDataCommit` to `UserData`. Adopting it requires
`[Fintype UserData]` (and `[Fintype UserDataCommit]` for the
two-sided birthday bound), which are blocked on the carrier-
refinement work queued from Steps 2–5.

Until those carriers refine to concrete byte-list / `BitVec n`
representations, the honest-deterministic baseline is the
strongest we can state: it gives the adversary oracle access
*at the type level* (so `IsPPT := PolyQueries` becomes
meaningful) without smuggling in unverified `Fintype` content.

### Downstream consequence

After cycle 6.13, the lift theorems read:

    Pr[ winPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

for `𝒜 n : OracleComp ProtocolSpec T`. For an adversary that
makes no oracle queries, `simulateQ` reduces to the identity on
`OracleComp ∅ T = ProbComp T`, so the probability is the same as
the pre-cycle form. For an adversary that *does* query, the
simulator threads the classical-function responses through; the
probability is over the adversary's own coin flips alone.

The shape change unblocks cycle 6.14: `IsPPT` can now be
specialised to VCV-io's `PolyQueries` (security-parameter-indexed
polynomial query bound) because the adversary type is now an
`OracleComp` over a non-empty `OracleSpec`.
-/

/-- Honest deterministic responder for `CommitHashSpec`.
    Each `commitHash`-oracle query returns the classical
    `commitHash` value via `pure`. -/
noncomputable def commitHashHonestSim : QueryImpl CommitHashSpec ProbComp :=
  fun uc => (pure (commitHash uc) : ProbComp UserData)

/-- Honest deterministic responder for `CommitHashBytesSpec`.
    Each `commitHashBytes`-oracle query returns the classical
    `commitHashBytes` value via `pure`. -/
noncomputable def commitHashBytesHonestSim :
    QueryImpl CommitHashBytesSpec ProbComp :=
  fun b => (pure (commitHashBytes b) : ProbComp UserData)

/-- Honest deterministic responder for `VerifyTdxQuoteSpec`.
    Each `verifyTdxQuote`-oracle query returns the classical
    `verifyTdxQuote` value via `pure`. -/
noncomputable def verifyTdxQuoteHonestSim :
    QueryImpl VerifyTdxQuoteSpec ProbComp :=
  fun q => (pure (verifyTdxQuote q) : ProbComp (Option (MrEnclave × UserData)))

/-- Honest deterministic responder for `VerifyGroth16Spec`.
    Each `verifyGroth16`-oracle query returns the classical
    `verifyGroth16` value via `pure`. The query index is the
    triple `(vkey, proof, inputs)`. -/
noncomputable def verifyGroth16HonestSim :
    QueryImpl VerifyGroth16Spec ProbComp :=
  fun q => (pure (verifyGroth16 q.1 q.2.1 q.2.2) : ProbComp Bool)

/-- Combined honest deterministic simulator for `ProtocolSpec`.

    Routes each query through the corresponding companion-module
    responder via VCV-io's `QueryImpl.add` (`+`), preserving the
    nested-sum index structure of `ProtocolSpec`:

    * `inl (inl (inl uc))` → `commitHashHonestSim uc`
    * `inl (inl (inr b))`  → `commitHashBytesHonestSim b`
    * `inl (inr q)`        → `verifyTdxQuoteHonestSim q`
    * `inr (vkey, p, ins)` → `verifyGroth16HonestSim (vkey, p, ins)`

    Used by every cycle-6.13+ lift to convert
    `𝒜 n : OracleComp ProtocolSpec T` into a `ProbComp T` over
    which `Pr[winPred | ...]` is well-defined. -/
noncomputable def protocolSpecHonestSim : QueryImpl ProtocolSpec ProbComp :=
  ((commitHashHonestSim + commitHashBytesHonestSim) + verifyTdxQuoteHonestSim)
    + verifyGroth16HonestSim

/-! ## Adversary efficiency class (resolves Step 6.0 finding 1)

Step 6.0 surfaced an *adversary-class quantification gap*: the lifted
theorem `verifyGroth16_yields_decoded_negl` quantified over arbitrary
(possibly computationally-unbounded) adversaries, whereas the truthful
cryptographic statements only hold against efficient (PPT) adversaries.

### Framework choice

We adopt VCV-io's existing `PolyQueries` structure (from
`VCVio.OracleComp.QueryTracking.QueryBound`) as the project-standard
efficiency notion *whenever* an adversary has oracle access. VCV-io
already provides this scaffolding and it composes with `SecurityGame.
secureAgainst`'s `isPPT : Adv → Prop` parameter directly.

For the current scaffolding step, our adversary types
(`Groth16SoundAdv`, `TdxVerifierSoundAdv`) are *no-oracle-access*
`ProbComp` producers — they do not yet take query access to
`ProtocolSpec`. For such adversaries the standard cryptographic
"efficient" notion reduces to "the sampling computation terminates
in polynomial time", which VCV-io's `PolyQueries` does not constrain
(zero queries is trivially polynomially bounded).

We therefore expose `IsPPT` as a **project-standard placeholder
predicate** that is `True` for the current no-oracle-access adversary
types. The placeholder is a deliberate light touch: it threads the
"adversary class" parameter through `SecurityGame.secureAgainst`
exactly as VCV-io's apparatus expects, while leaving room to swap
in a tighter notion (VCV-io's `PolyQueries` directly, or a
project-specific runtime model) once the adversary types gain oracle
access.

### Why this is the lighter-touch option

The Step 6.0 brief asked us to evaluate two options:

1. **Use VCV-io's `PolyQueries` as-is.** Requires our adversary
   types to be `OracleComp`-valued and indexed by a security
   parameter at the type level (`α β : ℕ → Type`). Our current
   adversary types are `ℕ → ProbComp (...)` (no `α` carrier; the
   adversary takes no input). Rewriting them to fit `PolyQueries`'s
   shape would touch every lifted theorem.

2. **Add a project-standard wrapper.** The thin wrapper here exposes
   `IsPPT` on the current adversary types as `True`. This is
   structurally equivalent to quantifying over arbitrary adversaries
   (vacuous filter) but threads through the `isPPT` machinery so
   downstream reductions invoke
   `SecurityGame.secureAgainst_of_reduction` with the right shape.

Option 2 is lighter-touch and is what we adopt. The choice is
**reversible**: when adversary types gain oracle access (in the
carrier-refinement work queued from Steps 3-5), we swap the
`IsPPT` definition's body for a `PolyQueries`-based predicate
without changing any theorem statement.

### Honesty caveat

The placeholder `IsPPT := True` means the current lifts are
**informationally equivalent to quantifying over arbitrary
adversaries**. The "PPT filter" is documentary, not load-bearing —
it makes the adversary-class qualifier *explicit* in the theorem
statements, but does not yet *enforce* it. This is reported as a
(d)-bucket-adjacent finding (*"adversary-class-strong"*) in the
Step 6.0 change record; the placeholder makes the gap
machine-checkable but does not close it.

The path to closing the gap is documented and tractable: it
requires (a) refining adversaries to oracle-access types, then
(b) instantiating `IsPPT` to `PolyQueries`. Both are out of
scope here.
-/

/-- Project-standard efficiency predicate on adversaries.

    **Placeholder** (`True`) for the existing `*_AGAINST_UNBOUNDED_ADVERSARIES`
    packagings: it makes the adversary-class qualifier
    *machine-checkable at the call site* (every `secureAgainst IsPPT`
    instance is honestly a `secureAgainst (fun _ => True)` statement)
    without claiming the substantive PPT filter holds.

    **Cycle 6.14**: the substantive PPT predicate now lives at
    `IsPPT_proper` below, instantiating VCV-io's `PolyQueries`. The
    placeholder `IsPPT` is retained for backwards-compatibility with
    the existing `_AGAINST_UNBOUNDED_ADVERSARIES` packagings, which
    continue to honestly state the "all-adversaries" reading. A
    parallel set of `_AGAINST_PPT_ADVERSARIES` packagings consuming
    `IsPPT_proper` is queued as cycle 6.15 — those require a
    per-reduction `IsPPT_proper`-preservation lemma showing the
    reduction's `bind/pure ∘ proj` shape adds no oracle queries. -/
def IsPPT {Adv : Type} (_ : Adv) : Prop := True

/-- The placeholder is trivially satisfied by every adversary.
    Discharges the `isPPT A` hypothesis in
    `SecurityGame.secureAgainst` invocations during the current
    no-oracle-access lift phase. -/
@[simp] theorem IsPPT_trivial {Adv : Type} (A : Adv) : IsPPT A := trivial

/-! ## Substantive PPT predicate via `PolyQueries` (Cycle 6.14)

Cycle 6.13 wired `OracleComp ProtocolSpec` into adversary types so
that VCV-io's `PolyQueries` shape (security-parameter-indexed
polynomial query bound) becomes type-compatible. Cycle 6.14 takes
the next step: define a substantive PPT predicate that *actually*
constrains the adversary, rather than the cycle-6.12 placeholder.

### Why a parallel predicate, not a body swap of `IsPPT`

The body swap path (replace `IsPPT := True` with the
`PolyQueries`-based body) would weaken the conclusion of every
existing `*_AGAINST_UNBOUNDED_ADVERSARIES` packaging from
"secure against all adversaries (bounded or not)" to "secure
against PPT adversaries only". The packagings' naming would no
longer match their conclusion.

The cleaner end-state is to keep the placeholder `IsPPT` as the
"all-adversaries" label (the existing packagings honestly state
this) and introduce `IsPPT_proper` as a separate definition. A
parallel set of `_AGAINST_PPT_ADVERSARIES` packagings consuming
`IsPPT_proper` is queued as cycle 6.15; each needs a
per-reduction lemma showing the reduction preserves
`IsPPT_proper`.

### `DecidableEq` instances

`PolyQueries` requires `[DecidableEq ι]` on the OracleSpec's index
type. Our `ProtocolSpec` index is the nested sum
`(((UserDataCommit ⊕ ByteSeq) ⊕ TdxQuote) ⊕ VerifyGroth16Query)`,
where the four atomic carriers are abstract types with no native
`DecidableEq`. We supply `Classical.decEq` instances as
`noncomputable local` declarations, matching the precedent set in
the `was_signed_by_dstack` decidability section above
(`Classical.propDecidable`).

This is a non-constructive move: the instance asserts that any
two carrier values are decidably equal under classical logic, but
the underlying check is not computable. The pattern mirrors how
the `Decidable` instance for `was_signed_by_dstack` was justified:
the spec-layer adversary's *type* is well-defined under classical
decidability, while concrete carrier refinement (cycles that
substitute abstract carriers with `BitVec n` / byte-list
representations) will replace these with computable instances.

### `IsPPT_proper` shape

`IsPPT_proper` is polymorphic in the adversary's result type `T`,
specialised to our adversary shape `ℕ → OracleComp ProtocolSpec T`:

    def IsPPT_proper {T : Type} (𝒜 : ℕ → OracleComp ProtocolSpec T) : Prop :=
      Nonempty (PolyQueries
        (ι := ...) (spec := fun _ => ProtocolSpec)
        (α := fun _ => PUnit) (β := fun _ => T)
        (fun n (_ : PUnit) => 𝒜 n))

The `PUnit` α-type is a token: our adversaries take no input
beyond the security parameter `n`, and `PolyQueries`'s shape
demands an `α n → OracleComp ...` form, so we adapt with a unit
argument.

`Nonempty` (rather than `Exists`) is the standard `Prop` shape for
"there exists a witness with the given structure", because
`PolyQueries` is a structure (carrying the polynomial bound), not
a `Prop`. -/

/-- Classical decidability for the four abstract carrier types
    underlying `ProtocolSpec`'s index. Local instances —
    `noncomputable` and confined to this module — supplied via
    `Classical.decEq` to satisfy `PolyQueries`'s `[DecidableEq ι]`
    requirement. -/
noncomputable local instance instDecidableEqUserDataCommit :
    DecidableEq UserDataCommit := Classical.decEq _

noncomputable local instance instDecidableEqByteSeq :
    DecidableEq ByteSeq := Classical.decEq _

noncomputable local instance instDecidableEqTdxQuote :
    DecidableEq TdxQuote := Classical.decEq _

noncomputable local instance instDecidableEqVerifyGroth16Query :
    DecidableEq VerifyGroth16Query := Classical.decEq _

/-- **Substantive PPT predicate** (Cycle 6.14): an adversary
    `𝒜 : ℕ → OracleComp ProtocolSpec T` is PPT iff there exists a
    polynomial bound on its per-index query count, as a function
    of the security parameter `n`.

    This is the substantive Round A attack #5 closure on the
    content side: where the cycle-6.12 placeholder `IsPPT := True`
    was a documentary rename surfacing the gap at every call site,
    `IsPPT_proper` is a *real* PPT filter — adversaries with
    super-polynomially-many queries do not satisfy it.

    `IsPPT_proper` is polymorphic over the adversary's result type
    `T`; existing call sites unfold `XAdv = ℕ → OracleComp ProtocolSpec T`
    so the predicate specialises naturally.

    Currently consumed only by `IsPPT_proper.*` documentation
    (no `*_AGAINST_PPT_ADVERSARIES` packagings yet) — those land
    in cycle 6.15 along with per-reduction preservation lemmas. -/
noncomputable def IsPPT_proper {T : Type}
    (𝒜 : ℕ → OracleComp ProtocolSpec T) : Prop :=
  Nonempty (PolyQueries
    (ι := (((UserDataCommit ⊕ ByteSeq) ⊕ TdxQuote) ⊕ VerifyGroth16Query))
    (spec := fun _ : ℕ => ProtocolSpec)
    (α := fun _ : ℕ => PUnit) (β := fun _ : ℕ => T)
    (fun n (_ : PUnit) => 𝒜 n))

/-! ## `IsPPT_proper`-preservation under reductions (Cycle 6.14.b)

Every protocol-layer reduction in `ProtocolVCVio{Dual,Triple,Quad}.lean`
has the same shape: `fun n => 𝒜 n >>= pure ∘ proj`. Such a reduction
makes the same oracle queries as `𝒜 n` plus zero (because `pure ∘ proj`
is pure), so the same per-index polynomial query bound witnesses
`IsPPT_proper` of the reduced adversary.

The generic lemma below packages this once for all four reductions,
discharging the `IsPPT_proper (reduce_X 𝒜)` side of each
`_AGAINST_PPT_ADVERSARIES` packaging that cycle 6.14.c (queued) will
build.
-/

/-- Generic `IsPPT_proper`-preservation under the `bind/pure ∘ f` shape.

    If `𝒜` is a `OracleComp ProtocolSpec`-valued PPT adversary at
    each security parameter, then `fun n => 𝒜 n >>= pure ∘ f` is
    also PPT — the post-composition with `pure ∘ f` makes no new
    oracle queries, so the source's polynomial bound witnesses the
    reduced adversary's `IsPPT_proper` too.

    Proof: extract the source's PolyQueries witness `⟨qb, hqb⟩`;
    return the same `qb`; rewrite `>>= pure ∘ f` as `f <$> _` via
    `← map_eq_bind_pure_comp`; `isPerIndexQueryBound_map_iff` reduces
    the per-index query bound on the mapped computation to the bound
    on the source. -/
theorem IsPPT_proper_of_bind_pure_comp {S T : Type}
    (𝒜 : ℕ → OracleComp ProtocolSpec S) (f : S → T)
    (h : IsPPT_proper 𝒜) :
    IsPPT_proper (fun n => 𝒜 n >>= pure ∘ f) := by
  obtain ⟨⟨qb, hqb⟩⟩ := h
  refine ⟨⟨qb, ?_⟩⟩
  intro n _
  show IsPerIndexQueryBound (𝒜 n >>= pure ∘ f) _
  rw [← map_eq_bind_pure_comp, isPerIndexQueryBound_map_iff]
  exact hqb n PUnit.unit

/-! ## Decidable Bool/Prop bridges (resolves Step 6.0 finding 2)

Step 6.0 surfaced a *win-condition Bool/Prop mismatch*: the lifted
adversary's win event mixes `verifyGroth16 ... = true` (a `Bool`
test) with `¬ was_signed_by_dstack q` (a `Prop` with no
decidability content). VCV-io's `Pr[...]` apparatus measures
`Decidable` events; the mismatch blocks computing the event
probability concretely.

### Resolution: Decidable reframing via `Classical.propDecidable`

We add a `noncomputable` `Decidable` instance for
`was_signed_by_dstack` via `Classical.propDecidable`. This matches
the precedent set in `Specs.Quartz.Crypto.Ecies` for `DecidableEq
PubKey` (noncomputable local instance via `Classical.propDecidable`
because `PubKey` is an abstract carrier).

This is the lighter-touch resolution (per the brief): we do not
reformulate the win condition through an extractor, we simply give
the propositional predicate enough decidability content to be
measured.

### Why this is justifiable

The brief offered two options:

1. **Extractor reformulation**: lift the win condition to return
   a `Bool` by introducing a decision oracle. Cleaner semantically
   but adds an extractor adversary, requires modifying the win
   condition, and propagates through every downstream lift.

2. **Decidable reframing**: add `Decidable` via `Classical.
   propDecidable`. Touches one declaration, matches the existing
   precedent for abstract-carrier predicates, and preserves all
   downstream win-condition formulations unchanged.

Option 2 is selected. The instance is `noncomputable local` so it
does not leak into downstream type-class search (mirroring the
`Ecies.DecidableEq PubKey` discipline that prevents instance-
synthesis timeouts in `UserDataCommit`'s `Decidable (∃ c, ...)`
goals).

### Honesty caveat

`Classical.propDecidable` is non-constructive — it asserts
decidability of any proposition under classical logic. The instance
adds `Classical.choice` (already in the closure of every theorem
that uses `propDecidable`) to the axiom set but does *not* claim
that `was_signed_by_dstack` is computationally decidable. It just
makes the proposition syntactically `Decidable` so `Pr[...]` can
type-check.

This is the standard cryptographic-spec move when the win-condition
predicate is over abstract / off-chain witnesses. The win
condition's *meaning* is unchanged; only its decidability shape
in the type theory is adjusted.

### Live consumers (post-cycle-6.4–6.11)

Round A attack #10 (2026-05-14, advisory) noted this instance was
"dead" because Step 6.0 lifts did not actually consume a `Pr[…]`
over `was_signed_by_dstack`. That observation is now stale: cycles
6.4–6.11 def-tied every protocol-layer `_negl` lift to a
`noncomputable def *FailAdv := Pr[winPred | 𝒜 n]` shape, and the
seven non-degenerate winPreds (`groth16SoundnessWinPred`,
`handshakeSoundnessWinPred`, `handshakeBindsWinPred`,
`transfersConsWinPred`, `auctionDetermWinPred`,
`crossSessionBindWinPred`, and the `_imp_*_projected` forward
implications) all reference `was_signed_by_dstack q`. The
decidability instance is therefore **load-bearing** for the
`Pr[…]` typing of every cycle-6.4–6.11 lift.

The remaining (still live) caveat: while `Pr[winPred | 𝒜 n]` is
well-typed, its concrete numerical value cannot be computed from
the abstract carriers alone — `evalDist` lacks a measurable
structure over `TdxQuote`. The lifts prove pointwise *bounds* on
the probability, not a concrete value; the bound's discharge
against a concrete cryptographic primitive (Groth16 KS, etc.)
remains the externally-deferred discharge path.
-/

/-- Decidable instance for `was_signed_by_dstack` via classical
    logic.

    `was_signed_by_dstack` is a `Prop` predicate witnessing
    off-chain reality (a TDX quote was genuinely produced by a
    dstack TEE) — it has no computational decidability content at
    the spec layer. We supply decidability via
    `Classical.propDecidable` so that win conditions of the form
    `verifyGroth16 ... = true ∧ ¬ was_signed_by_dstack q` are
    `Decidable` and can be measured by `Pr[...]`.

    Marked `noncomputable local` to avoid leaking into downstream
    type-class search (matching the `Ecies.DecidableEq PubKey`
    discipline). -/
noncomputable local instance was_signed_by_dstack_decidable
    (q : TdxQuote) : Decidable (was_signed_by_dstack q) :=
  Classical.propDecidable _

/-! ## Groth16 soundness adversary and advantage

The truthful formulation of `groth16Verifier.sound` is that no PPT
adversary can produce a `(proof, inputs)` pair such that the
verifier accepts under the canonical `zkdcapVKey` but the
associated TDX quote is NOT dstack-signed, except with negligible
probability over the trusted-setup randomness AND the
circuit-correctness gap (the doubled-negligibility from Step 5).

We model the adversary as a function from security parameter to a
`ProbComp` returning a candidate `(proof, inputs)` pair. The
advantage function is the probability that the candidate "wins"
(verifier accepts but the quote is not genuinely signed).

Currently the advantage is **parametric over an opaque bound**:
the actual measure-theoretic quantity requires `[Fintype]` on
`Groth16Proof` and `PublicInputs` (Step 5 carrier-refinement
blocker). The parametric statement is honest — it says: "*if*
the underlying Groth16 soundness advantage is negligible, *then*
the protocol-side fail event is also negligible". The hypothesis
is what ArkLib (cryptographic side) and a reference DCAP verifier
(software-verification side) would discharge.
-/

/-- A Groth16 soundness adversary: at each security parameter `n`,
    outputs a candidate `(proof, inputs)` pair. The "win" condition
    is that `verifyGroth16 zkdcapVKey proof inputs = true` AND
    `¬ was_signed_by_dstack (inputs_to_quote inputs)`.

    **Cycle 6.13**: the adversary is now an `OracleComp ProtocolSpec`-
    valued function rather than a `ProbComp`-valued one. The four
    component oracles (`CommitHashSpec`, `CommitHashBytesSpec`,
    `VerifyTdxQuoteSpec`, `VerifyGroth16Spec`) are available to the
    adversary at query time; the adversary's own internal randomness
    is still drawn from `unifSpec` (the universal-uniform oracle
    that `OracleComp` exposes via `OracleComp.lift` of `ProbComp`
    primitives).

    The advantage definition (`groth16SoundnessAdv`) routes
    `simulateQ protocolSpecHonestSim` over the adversary before
    measuring the win-probability, so the four protocol oracles
    are interpreted by the honest-deterministic responder defined
    above. -/
def Groth16SoundAdv : Type := ℕ → OracleComp ProtocolSpec (Groth16Proof × PublicInputs)

/-- The advantage of a Groth16 soundness adversary at security
    parameter `n`, parametrised on an opaque bound.

    Conceptually:

        Pr[verifyGroth16 zkdcapVKey proof inputs = true ∧
           ¬ was_signed_by_dstack (inputs_to_quote inputs)
          | (proof, inputs) ← 𝒜 n]

    Concretely we cannot compute this `Pr[...]` because:

    1. `Groth16Proof` and `PublicInputs` lack `[Fintype]`
       instances (Step 5 carrier blocker).
    2. The win condition mixes a `Bool` test
       (`verifyGroth16 ... = true`) with a `Prop`-only predicate
       (`was_signed_by_dstack`), and `was_signed_by_dstack` is not
       `Decidable` — it is a propositional witness about
       off-chain reality.

    The advantage is therefore parametrised on an opaque bound
    `b : Groth16SoundAdv → ℕ → ℝ≥0∞`. The reduction below
    states the protocol-side bound *in terms of* this opaque
    advantage, leaving the discharge to ArkLib + circuit-
    equivalence work. -/
abbrev Groth16SoundAdvantage : Type := Groth16SoundAdv → ℕ → ℝ≥0∞

/-- The Groth16 soundness security game: maps each adversary to
    its advantage at each security parameter, given a parametric
    advantage function.

    A `SecurityGame Groth16SoundAdv` package is the standard
    VCV-io shape for stating "soundness is negligible against PPT
    adversaries". -/
def groth16SoundnessGame (adv : Groth16SoundAdvantage) :
    SecurityGame Groth16SoundAdv where
  advantage := adv

/-! ## Content-bearing advantage definitions (Cycle 6.4 — Round A fix)

Round A adversarial review (`.colosseum/attacks/lean-negl-lifts-2026-05-14/`)
established that the prior form of `verifyGroth16_yields_decoded_negl` was
content-free: its `protocolFailAdv` was a free `ℝ≥0∞`-valued function symbol
with no tie to the actual protocol-fail event, making the theorem reducible
to `negligible_of_le` + `negligible_add` closure properties of `negligible`.

The defs below replace the free symbols with `Pr[…]`-based probability events
over the adversary's `ProbComp` output. The bound is now *proven* (not
assumed) via `probEvent_mono` and the classical implication
`verifyTdxQuote_complete : was_signed_by_dstack q → ∃ mr ud, verifyTdxQuote q = some (mr, ud)`.

The Type-alias `Groth16SoundAdvantage` is retained for backwards-compatibility
with cycles 6.5–6.11 (downstream lifts in `ProtocolVCVio{Dual,Triple,Quad}.lean`
parametrise their `groth16Adv` argument over it). Those cycles will replace
the Type-alias with content-bearing defs analogous to those below.
-/

/-- **Win predicate for the Groth16 soundness game.** A candidate
    `(proof, inputs)` pair "wins" the soundness game when the verifier
    accepts but the associated TDX quote is not actually signed by dstack.
    This is the event whose probability the cryptographic-assumption layer
    is supposed to bound. -/
def groth16SoundnessWinPred (p : Groth16Proof × PublicInputs) : Prop :=
  verifyGroth16 zkdcapVKey p.1 p.2 = true ∧
  ¬ was_signed_by_dstack (inputs_to_quote p.2)

/-- **Protocol-fail predicate**: the verifier accepts but the TDX quote
    does not decode (no `(mr, ud)` is recovered). This is the event whose
    probability `verifyGroth16_yields_decoded_negl` bounds. -/
def verifyGroth16FailPred (p : Groth16Proof × PublicInputs) : Prop :=
  verifyGroth16 zkdcapVKey p.1 p.2 = true ∧
  ¬ ∃ mr ud, verifyTdxQuote (inputs_to_quote p.2) = some (mr, ud)

/-- **Content-bearing advantage** for the Groth16 soundness game: the
    probability that the adversary's `(proof, inputs)` output causes the
    verifier to accept on an un-signed quote. This is a `def`, not a
    `Type`-only alias — the body mentions `verifyGroth16`, `zkdcapVKey`,
    `was_signed_by_dstack`, and `inputs_to_quote`, so an external auditor
    can read off exactly which cryptographic event is being bounded.

    **Cycle 6.13**: the adversary is now an `OracleComp ProtocolSpec`-
    valued function, so we apply `simulateQ protocolSpecHonestSim` to
    interpret the four protocol oracles deterministically before
    measuring the win-probability. For a no-oracle-access adversary
    (one whose `OracleComp` body is constructed entirely via `pure`
    / `unifSpec` queries with no `ProtocolSpec` queries) the
    simulation is the identity, so this advantage agrees with the
    pre-cycle-6.13 `Pr[winPred | 𝒜 n]` form. -/
noncomputable def groth16SoundnessAdv (𝒜 : Groth16SoundAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ groth16SoundnessWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- **Content-bearing advantage** for the protocol-fail event: the
    probability that the adversary's `(proof, inputs)` output causes the
    verifier to accept on a quote that does not decode.

    **Cycle 6.13**: same simulator-wrapping as `groth16SoundnessAdv`. -/
noncomputable def verifyGroth16FailAdv (𝒜 : Groth16SoundAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ verifyGroth16FailPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- The protocol-fail event implies the Groth16 soundness-win event:
    if the verifier accepts but no `(mr, ud)` is decoded, then the quote
    cannot have been signed by dstack (because `tdxVerifier.complete`
    would otherwise produce the decoding). This is the pointwise
    implication that the Round A-corrected `verifyGroth16_yields_decoded_negl`
    closes over via `probEvent_mono`. -/
theorem verifyGroth16FailPred_imp_groth16SoundnessWinPred
    (p : Groth16Proof × PublicInputs)
    (h : verifyGroth16FailPred p) : groth16SoundnessWinPred p :=
  ⟨h.1, fun h_signed => h.2 (verifyTdxQuote_complete _ h_signed)⟩

/-! ## Lifted protocol theorem: `verifyGroth16_yields_decoded_negl`

The classical-`Prop` form of `verifyGroth16_yields_decoded`
(in `Specs/Quartz/Attestation/Zkdcap.lean`) says:

    If `verifyGroth16 zkdcapVKey proof inputs = true`,
    then `∃ mr ud, verifyTdxQuote (inputs_to_quote inputs)
      = some (mr, ud)`.

This rides on two bundled axioms: `groth16Verifier.sound` (Step 5,
doubled-negligibility) and `tdxVerifier.complete` (Step 4,
preconditional-completeness). Both are classical-`Prop` and drop
their truthful qualifiers.

The lifted form states the same conclusion as a negligibility
bound: the *probability* that an honest run accepting the proof
fails to decode is bounded by the Groth16 soundness advantage
of a hypothetical extractor adversary, which is assumed
negligible.

Specifically, the lifted form says: for any adversary 𝒜 that
produces `(proof, inputs)`, the probability that `verifyGroth16
zkdcapVKey proof inputs = true ∧ ¬ ∃ mr ud, verifyTdxQuote
(inputs_to_quote inputs) = some (mr, ud)` is bounded by the
Groth16 soundness advantage.

The proof goes through `tdxVerifier.complete`:
* `groth16Verifier.sound` gives `was_signed_by_dstack (inputs_to_quote inputs)`
  from the verifier accepting, EXCEPT with the soundness-advantage probability.
* `tdxVerifier.complete` gives `∃ mr ud, verifyTdxQuote q = some (mr, ud)`
  from `was_signed_by_dstack q` — unconditionally at the classical level.

So the failure event is exactly the Groth16 soundness failure event;
the bound passes through with equality.
-/

/-- **Classical form (preserved as a corollary)**: `verifyGroth16_yields_decoded`.

    Re-exported from `Zkdcap.lean` for convenience. Rides on the
    bundled `groth16Verifier` (Step 5) + `tdxVerifier` (Step 4)
    classical-`Prop` axioms. -/
theorem verifyGroth16_yields_decoded_classical
    (proof : Groth16Proof) (inputs : PublicInputs)
    (h : verifyGroth16 zkdcapVKey proof inputs = true) :
    ∃ mr ud, verifyTdxQuote (inputs_to_quote inputs) = some (mr, ud) :=
  verifyGroth16_yields_decoded proof inputs h

/-- **Probabilistic form (the Step 6.0 lift, Cycle-6.4-corrected)**:
    `verifyGroth16_yields_decoded_negl`.

    Given:

    * an adversary `𝒜 : Groth16SoundAdv` that outputs a candidate
      `(proof, inputs)` pair,
    * a negligibility assumption on the Groth16 soundness-win event
      under `𝒜`: `h_negl : negligible (groth16SoundnessAdv 𝒜)`,

    Then the protocol-fail event — `verifier accepts ∧ ¬ ∃ mr ud,
    verifyTdxQuote (inputs_to_quote inputs) = some (mr, ud)` — is also
    negligible under `𝒜`: `negligible (verifyGroth16FailAdv 𝒜)`.

    **Cycle 6.4 correction notes** (Round A response):

    - The advantage and the protocol-fail advantage are now `def`s
      (`groth16SoundnessAdv`, `verifyGroth16FailAdv`) over `Pr[…]`
      events, not free `ℝ≥0∞`-valued function symbols. The user can no
      longer instantiate them to `fun _ _ => 0` and trivialize the
      conclusion.
    - The pointwise bound is *proven* (not assumed) via
      `probEvent_mono` + `verifyGroth16FailPred_imp_groth16SoundnessWinPred`,
      the latter resting on `verifyTdxQuote_complete` (which is itself
      a projection of the bundled `tdxVerifier` axiom). The hypothesis
      list shrinks from three parameters (`adv`, `protocolFailAdv`,
      `h_bound`) to one (`h_negl`).
    - The remaining hypothesis `h_negl` is the substantive cryptographic
      assumption — that the actual Groth16 verifier's soundness-win
      probability is negligible — which is what ArkLib Groth16-KS
      coverage + a Lean reference DCAP verifier would discharge.

    Proof: by `probEvent_mono` on `verifyGroth16FailPred ⇒
    groth16SoundnessWinPred` (forward soundness via `tdxVerifier.complete`),
    we get `verifyGroth16FailAdv 𝒜 n ≤ groth16SoundnessAdv 𝒜 n` pointwise.
    Then `negligible_of_le` closes from `h_negl`. -/
theorem verifyGroth16_yields_decoded_negl
    (𝒜 : Groth16SoundAdv)
    (h_negl : negligible (groth16SoundnessAdv 𝒜)) :
    negligible (verifyGroth16FailAdv 𝒜) := by
  refine negligible_of_le ?_ h_negl
  intro n
  exact probEvent_mono (fun p _ hp =>
    verifyGroth16FailPred_imp_groth16SoundnessWinPred p hp)

/-- **Convenience packaging**: the lifted protocol theorem expressed
    as a `SecurityExp` (asymptotic security experiment), reducing the
    protocol-fail experiment to the Groth16 soundness experiment.

    Given the same advantage-bound hypothesis, the protocol-fail
    experiment is `secure` (advantage negligible) whenever the
    Groth16 soundness experiment is `secure`.

    This is the canonical "single security reduction" shape — it
    plugs directly into VCV-io's `SecurityGame.secureAgainst_of_reduction`
    when Step 6.N composes this with the other three bundled
    soundness reductions. -/
theorem protocolFail_secure_of_groth16Sound_secure
    (groth16SoundExp : SecurityExp)
    (protocolFailExp : SecurityExp)
    (h_bound : ∀ n, protocolFailExp.advantage n ≤ groth16SoundExp.advantage n)
    (h_groth16Secure : groth16SoundExp.secure) :
    protocolFailExp.secure :=
  -- `SecurityExp.secure = negligible advantage`, so this is just
  -- `negligible_of_le`.
  SecurityExp.secure_of_pointwise_bound
    protocolFailExp groth16SoundExp.advantage h_groth16Secure h_bound

/-! ## Outstanding follow-ups (Step 6.N work)

* **Lift the dual-bundle theorem `handshake_sound`**. It rides on
  `tdxVerifier.sound` + `groth16Verifier.sound`. The lifted form
  is a union bound over two negligibility assumptions. The bound
  is structurally identical to the pattern above but with two
  summands.

* **Lift the triple-bundle theorems**
  (`handshake_binds_ecies_key`, `session_confidentiality`,
  `session_confidentiality_via_extractor`,
  `cross_component_transfers_conservation`,
  `cross_component_auction_winner_determinism`). Each adds a
  `commitHashE` / `commitHashBytesE` collision-probability summand
  to the union bound.

* **Lift the quadruple-bundle theorem
  `cross_component_session_bind`**. Five-summand union bound: two
  commit-hash collisions, one TDX forgery, two Groth16 forgery
  (doubled-negligibility decomposition). This is the load-bearing
  protocol-layer trust statement; the union-bound bookkeeping is
  non-trivial.

* **Adopt a project-standard PPT predicate**. Currently the lifts
  here quantify over arbitrary adversaries; VCV-io's `PolyQueries`
  / `QueryRuntime` framework provides the standard one. The Step
  6.N lifts should adopt it once the company-wide adversary class
  is decided.

* **Discharge the negligibility hypotheses** by importing the
  appropriate reductions:
    - `negligible_groth16` from ArkLib (once available).
    - `negligible_circuit` from a Lean reference DCAP verifier
      (separate effort).
    - `negligible_commitHash` / `negligible_commitHashBytes` from
      VCV-io's `randomOracle` + birthday bound (requires
      `[Fintype UserData]`, blocked on carrier refinement).
    - `negligible_tdxVerifier` from a PCK-signature unforgeability
      reduction (requires DCAP formalisation).
-/

end Specs.Quartz.Protocol.ProtocolVCVio
