/-
Copyright (c) 2026 Quartz authors. All rights reserved.
Released under Apache 2.0 license.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import VCVio.OracleComp.QueryTracking.LoggingOracle
import VCVio.OracleComp.QueryTracking.Birthday
import VCVio.OracleComp.Constructions.BitVec
import Specs.Quartz.Protocol.ProtocolVCVio

/-!
# Random-oracle model for the commit-hash primitives (Cycle 6.22)

This module hosts the **substantive Option-(a)** closure of the
(d-pigeonhole-impossible) sub-bucket for `commitHashE` and
`commitHashBytesE`. Cycle 6.13 wired `OracleComp ProtocolSpec` into the
adversary types and provided an honest-deterministic simulator
(`protocolSpecHonestSim`). Cycle 6.15 def-tied the collision advantages
to `Pr[…]` events. Cycles 6.16-6.21 refined every carrier to a concrete
Lean type (most importantly `UserData = BitVec 512` in cycle 6.18,
which gave us `Fintype UserData` and unblocked the random-oracle
discharge — on the range side; see the blocker note below for the
domain-side issue).

The natural target semantics for `commitHash` (and `commitHashBytes`)
is the random-oracle model:

* `commitHash : UserDataCommit → UserData` is replaced by a query to a
  uniformly-random function with caching for consistency.
* The collision advantage of any q-query adversary is bounded by the
  **birthday bound**: `qb^2 / (2 · |UserData|)` where
  `|UserData| = 2^512`.

This module imports the extra VCV-io dependencies the cycle-6.13
honest simulator did not need:

* `VCVio.OracleComp.QueryTracking.RandomOracle` — the `randomOracle`
  handler (lazy uniform sampling with caching).
* `VCVio.OracleComp.QueryTracking.LoggingOracle` — the `loggingOracle`
  handler that the birthday-bound theorem uses.
* `VCVio.OracleComp.QueryTracking.Birthday` — the actual bound theorem.
* `VCVio.OracleComp.Constructions.BitVec` — `SampleableType (BitVec n)`,
  required by `randomOracle` over a `BitVec`-valued range spec.

It also opens a fresh local namespace
`Specs.Quartz.Protocol.ProtocolVCVioROModel` so the new RO-side
definitions sit cleanly alongside the cycle-6.13 honest-deterministic
ones without `local instance` scoping issues.

## What this module provides (cycle 6.22.a)

* `commitHashROSim : QueryImpl CommitHashSpec (StateT _ ProbComp)`
* `commitHashBytesROSim : QueryImpl CommitHashBytesSpec (StateT _ ProbComp)`
* Explicit `DecidableEq`, `Fintype`, `Inhabited` instances on the
  carriers and the spec ranges, plumbing the `randomOracle` and
  birthday-bound requirements through the cycle-6.21 concrete carriers.

## What this module provides (cycle 6.22.b)

* `commitHash_logCollision_birthday_bound` — the standard textbook
  birthday bound `n²/(2·2^512)` on the probability of a log collision
  for any `OracleComp CommitHashSpec α` issuing at most `n` queries.
* `commitHashBytes_logCollision_birthday_bound` — the byte-domain
  analogue, same bound.

Both proved from VCV-io's `probEvent_logCollision_le_birthday_total`.
Closure: `{propext, Classical.choice, Quot.sound}` only — no
protocol-layer or cryptographic axioms.

## What remains (cycle 6.22.c, queued)

The bound is in *log-collision* form. The win-pred form used by the
protocol-layer adversaries (`commitHashCollisionAdvRO 𝒜 n ≤ …`)
requires the forward implication "adversary's win event implies the
cache contains a log collision", then composition with the bound
proven here. The downstream lift migration (the four lifts currently
consuming `commitHash_inj`) consumes the win-pred form.
-/

namespace Specs.Quartz.Protocol.ProtocolVCVioROModel

open ENNReal
open OracleSpec OracleComp
open Specs.Quartz.Crypto
open Specs.Quartz.Crypto.UserDataCommitVCVio
open Specs.Quartz.Crypto.RawMessagesVCVio
open Specs.Quartz.Protocol.ProtocolVCVio

/-! ## `DecidableEq` instances for the RO simulator

`randomOracle` requires `DecidableEq` on the OracleSpec's index type.
`CommitHashSpec : OracleSpec UserDataCommit`, so we need
`DecidableEq UserDataCommit`. Similarly `DecidableEq ByteSeq` for
`CommitHashBytesSpec`. Post-cycle-6.20 these types are concrete
(`UserDataCommit` is a structure of `List UInt8`/`String`/`BitVec` fields;
`ByteSeq = List UInt8`), so the instances can in principle derive
automatically. We supply them via `Classical.decEq` here for
uniformity with the cycle-6.14.a pattern and to avoid relying on
deriving-instance availability for the structure. -/

noncomputable local instance instDecidableEqUserDataCommitRO :
    DecidableEq UserDataCommit := Classical.decEq _

noncomputable local instance instDecidableEqByteSeqRO :
    DecidableEq ByteSeq := Classical.decEq _

/-! ## `SampleableType` instances for the spec ranges

`randomOracle` requires `[∀ t : spec.Domain, SampleableType (spec.Range t)]`.
For our specs the range is the constant function `fun _ => UserData`
where `UserData = BitVec 512` (cycle 6.18). VCV-io provides
`FinEnum (BitVec n)` and `FinEnum.SampleableType` (a derived
instance for any `[FinEnum + Nonempty]`), but the type-class
search through the dependent `Range t` projection needs an
explicit nudge. We supply per-spec instances that unfold the
range to `UserData` and apply the underlying `BitVec` instance. -/

instance instSampleableTypeCommitHashRange :
    ∀ t : CommitHashSpec.Domain, SampleableType (CommitHashSpec.Range t) :=
  fun _ => inferInstanceAs (SampleableType (BitVec 512))

instance instSampleableTypeCommitHashBytesRange :
    ∀ t : CommitHashBytesSpec.Domain,
      SampleableType (CommitHashBytesSpec.Range t) :=
  fun _ => inferInstanceAs (SampleableType (BitVec 512))

/-! ## `OracleSpec.{DecidableEq, Fintype, Inhabited}` instances

The cycle-6.22.b blocker note further down incorrectly claimed that
VCV-io's `probEvent_logCollision_le_birthday_total` requires `Fintype`
on the *index* type. Re-reading
`VCVio/OracleComp/QueryTracking/Birthday.lean:20-21` shows the actual
typeclass requirements are:

* `[DecidableEq ι]` on the index — we provide via `Classical.decEq`.
* `[spec.DecidableEq]` (DecidableEq on domain + per-range) — derives.
* `[spec.Fintype]` (Fintype on each *range* only, via
  `PFunctor.Fintype` at `ToMathlib/PFunctor/Basic.lean:231`) —
  derives from `Fintype (BitVec 512)`.
* `[spec.Inhabited]` (Inhabited on each *range* only) — derives from
  `Inhabited (BitVec 512)` (via `⟨0⟩`).

All four hold for `CommitHashSpec` post cycle-6.18 + cycle-6.14.a.
We declare the spec-level instances explicitly so the typeclass
unifier doesn't need to walk through the unfolded `OracleSpec.ofFn`
shape (`CommitHashSpec` is literally `fun _ => UserData`; `ofFn` is
the reducible identity wrapper, but the explicit instance is cheaper
and more diagnostic-friendly than relying on `ofFn` unfolding). -/

noncomputable instance instCommitHashSpecDecidableEq :
    CommitHashSpec.DecidableEq where
  decidableEq_A := instDecidableEqUserDataCommitRO
  decidableEq_B _ := inferInstanceAs (DecidableEq (BitVec 512))

instance instCommitHashSpecFintype : CommitHashSpec.Fintype where
  fintype_B _ := inferInstanceAs (Fintype (BitVec 512))

instance instCommitHashSpecInhabited : CommitHashSpec.Inhabited where
  inhabited_B _ := inferInstanceAs (Inhabited (BitVec 512))

noncomputable instance instCommitHashBytesSpecDecidableEq :
    CommitHashBytesSpec.DecidableEq where
  decidableEq_A := instDecidableEqByteSeqRO
  decidableEq_B _ := inferInstanceAs (DecidableEq (BitVec 512))

instance instCommitHashBytesSpecFintype : CommitHashBytesSpec.Fintype where
  fintype_B _ := inferInstanceAs (Fintype (BitVec 512))

instance instCommitHashBytesSpecInhabited : CommitHashBytesSpec.Inhabited where
  inhabited_B _ := inferInstanceAs (Inhabited (BitVec 512))

/-- Sanity probe: with the spec-level instances above, the
    `HasEvalPMF (OracleComp CommitHashSpec)` instance from
    `VCVio/OracleComp/EvalDist.lean:153` synthesises, which makes
    `Pr[…]` notation well-typed over `OracleComp CommitHashSpec`.
    This is the prerequisite that the original cycle-6.22.b blocker
    note claimed was unsatisfiable. -/
noncomputable example : HasEvalPMF (OracleComp CommitHashSpec) := inferInstance

noncomputable example : HasEvalPMF (OracleComp CommitHashBytesSpec) := inferInstance

/-! ## `Inhabited` instances on the index types

`probEvent_logCollision_le_birthday_total` requires `[Inhabited ι]` on
the spec's index in order to project out a default range to bound
against. We supply concrete `default` witnesses for each. -/

instance instInhabitedUserDataCommit : Inhabited UserDataCommit where
  default := { domainSep := [], eciesPubkey := 0, contractAddr := "", nonce := 0 }

instance instInhabitedByteSeqRO : Inhabited ByteSeq where
  default := []

/-! ## Random-oracle simulators

Each replaces the cycle-6.13 honest-deterministic responder
(`commitHashHonestSim`, `commitHashBytesHonestSim`) with VCV-io's
`randomOracle`. The simulator's target monad is
`StateT spec.QueryCache ProbComp`: the state is the lazy cache that
guarantees consistent responses to repeated queries on the same input,
and the underlying `ProbComp` supplies the uniform sampling. -/

/-- Random-oracle responder for `CommitHashSpec`. Each new
    `UserDataCommit` query samples a fresh uniform `UserData = BitVec 512`;
    repeated queries on the same input return the cached value. -/
noncomputable def commitHashROSim :
    QueryImpl CommitHashSpec (StateT CommitHashSpec.QueryCache ProbComp) :=
  randomOracle

/-- Random-oracle responder for `CommitHashBytesSpec`. Same shape over
    `ByteSeq → UserData`. -/
noncomputable def commitHashBytesROSim :
    QueryImpl CommitHashBytesSpec
      (StateT CommitHashBytesSpec.QueryCache ProbComp) :=
  randomOracle

/-! ## Notes on combining with the other protocol oracles

The cycle-6.13 `protocolSpecHonestSim` was a clean
`QueryImpl ProtocolSpec ProbComp` because all four component
responders shared the same `ProbComp` target. Composing
`commitHashROSim` (in `StateT _ ProbComp`) with the deterministic
`verifyTdxQuoteHonestSim` / `verifyGroth16HonestSim` (in `ProbComp`)
requires either:

1. Lifting the deterministic responders through the `StateT` monad
   transformer via `QueryImpl.liftTarget` (clean but adds a state-
   passing burden on every query), or
2. Building a heterogeneous-target simulator using `QueryImpl.addLift`
   from `VCVio.OracleComp.SimSemantics.Append` (the variant explicitly
   designed for mixed lift targets).

Cycle 6.22.b would prove the birthday bound on the *individual*
`commitHashCollisionAdv` (an adversary whose only oracle queries are
to the commit-hash spec). For that statement we evaluate the
adversary's behaviour under `simulateQ commitHashROSim` (or
`loggingOracle` for the proof side) directly, without integrating
the four protocol oracles. Cycle 6.22.c (downstream lift migration)
is where the heterogeneous combined simulator becomes necessary; we
defer that construction until the bound theorem is in place. -/

/-! ## Cycle 6.22.b — log-collision birthday bound

The substantive cycle 6.22.b deliverable: VCV-io's
`probEvent_logCollision_le_birthday_total`
(`VCVio/OracleComp/QueryTracking/Birthday.lean:396`) directly bounds
the probability that the `loggingOracle` trace records any pair of
queries with equal outputs but distinct inputs. Specialised to
`CommitHashSpec`, whose range is `UserData = BitVec 512`, the bound is
`n²/(2·2^512)` for any computation issuing at most `n` queries.

### Closure history

An earlier draft of this module claimed the bound was blocked because
`OracleSpec.Fintype` required `Fintype` on the index type
`UserDataCommit`. That reading was wrong. The actual signature at
`VCVio/OracleComp/QueryTracking/Birthday.lean:20-21` requires:

* `[DecidableEq ι]` on the index — provided above via `Classical.decEq`.
* `[spec.DecidableEq]` (DecidableEq on domain + per-range) — derives.
* `[spec.Fintype]` (`PFunctor.Fintype` requires Fintype on each
  *range* only, per `ToMathlib/PFunctor/Basic.lean:231`) — derives
  from `Fintype (BitVec 512)`.
* `[spec.Inhabited]` (Inhabited on each *range* only) — derives.
* `[Inhabited ι]` on the index — provided above with a concrete
  default value.

`Fintype UserDataCommit` is *not* required, so cycle 6.21's
production-faithful refinement (variable-length `domainSep`/`addr`)
does not interact with the bound. -/

/-- **Birthday bound for `CommitHashSpec` log-collisions**.

For any `OracleComp CommitHashSpec α` issuing at most `n` queries (in
the `IsTotalQueryBound` sense), the probability that the
`loggingOracle` trace contains two entries with equal outputs but
distinct inputs is at most `n² / (2 · 2^512)`. Standard textbook
birthday bound, instantiated via VCV-io's
`probEvent_logCollision_le_birthday_total`. -/
theorem commitHash_logCollision_birthday_bound {α : Type}
    (oa : OracleComp CommitHashSpec α)
    (n : ℕ) (hbound : IsTotalQueryBound oa n) :
    Pr[fun z => LogHasCollision z.2 |
        (simulateQ loggingOracle oa).run] ≤
      (n ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) := by
  have hcard : Fintype.card (CommitHashSpec.Range default) = 2 ^ 512 :=
    card_bitVec 512
  have hC_pos : 0 < Fintype.card (CommitHashSpec.Range default) := by
    rw [hcard]; exact Nat.pos_of_ne_zero (Nat.pos_iff_ne_zero.mp (Nat.two_pow_pos 512))
  have hrange : ∀ t, Fintype.card (CommitHashSpec.Range default) ≤
      Fintype.card (CommitHashSpec.Range t) := fun _ => le_refl _
  have h := probEvent_logCollision_le_birthday_total oa n hbound hC_pos hrange
  -- Rewrite the bound's RHS from `Fintype.card (...)` to `2^512`.
  refine h.trans (le_of_eq ?_)
  rw [hcard]; push_cast; rfl

/-- **Birthday bound for `CommitHashBytesSpec` log-collisions**.

The byte-domain analogue: same range type `UserData = BitVec 512`,
same `n² / (2 · 2^512)` bound. -/
theorem commitHashBytes_logCollision_birthday_bound {α : Type}
    (oa : OracleComp CommitHashBytesSpec α)
    (n : ℕ) (hbound : IsTotalQueryBound oa n) :
    Pr[fun z => LogHasCollision z.2 |
        (simulateQ loggingOracle oa).run] ≤
      (n ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) := by
  have hcard : Fintype.card (CommitHashBytesSpec.Range default) = 2 ^ 512 :=
    card_bitVec 512
  have hC_pos : 0 < Fintype.card (CommitHashBytesSpec.Range default) := by
    rw [hcard]; exact Nat.pos_of_ne_zero (Nat.pos_iff_ne_zero.mp (Nat.two_pow_pos 512))
  have hrange : ∀ t, Fintype.card (CommitHashBytesSpec.Range default) ≤
      Fintype.card (CommitHashBytesSpec.Range t) := fun _ => le_refl _
  have h := probEvent_logCollision_le_birthday_total oa n hbound hC_pos hrange
  refine h.trans (le_of_eq ?_)
  rw [hcard]; push_cast; rfl

/-! ## Cycle 6.22.c — RO-shape collision-finder advantage

The cycle-6.15 `commitHashCollisionAdv` (in `ProtocolVCVioTriple.lean`)
defines the collision-finder advantage as
`Pr[winPred | simulateQ protocolSpecHonestSim (𝒜 n)]`, evaluated under
the *honest deterministic* interpretation of `commitHash`. That is
the wrong probability model for a collision bound: under deterministic
hashing the advantage is either 0 (no collisions exist) or 1 (they
do); negligibility is not a meaningful notion.

The cryptographically meaningful model is the random oracle: the
adversary makes oracle queries, each of which returns a fresh uniform
range value, and the cache (or log) records the trace. The chance
that any two queries collide is bounded by the birthday formula
`q²/(2·|Range|)`.

This section provides the RO-shape adversary type, the corresponding
advantage definition (using the log-collision event), and the
birthday bound on it, parallel to the cycle-6.15 honest-deterministic
shape. Cycle 6.22.d (queued) wires these into the four downstream
lifts (`handshake_binds_ecies_key_negl`,
`session_confidentiality_negl`,
`session_confidentiality_via_extractor_negl`,
`cross_component_session_bind_negl`).

### Why use the log-collision event as the advantage shape

A natural alternative is the "explicit win" event: the adversary
outputs a pair `(uc₁, uc₂)`, the game queries both, and the win is
`uc₁ ≠ uc₂ ∧ oracle(uc₁) = oracle(uc₂)`. That advantage is also
bounded by the birthday formula (with `q + 2` queries), but the proof
requires unpacking the log structure after `𝒜 n >>= query >>= query`
to find the verifier's two log entries — non-trivial index management.

The log-collision shape is strictly stronger (any explicit-win event
implies a log collision, since the adversary must have queried both
inputs to assert the win) and the bound applies in one line via
`commitHash_logCollision_birthday_bound`. Downstream lifts that need
the explicit-win shape can derive it from the log-collision shape
without re-proving the bound. -/

/-- An RO-shape `commitHash` collision-finder adversary: an oracle
    computation over `CommitHashSpec` that issues some number of
    queries and returns nothing of interest (the existence of a
    collision is read off the trace, not the output). -/
def CommitHashCollisionAdvRO : Type :=
  ℕ → OracleComp CommitHashSpec Unit

/-- The RO-shape advantage of a `commitHash` collision-finder: the
    probability that the `loggingOracle` trace contains two distinct
    queries with equal outputs. This event is semantically
    "the adversary's queries witnessed a collision" — strictly
    stronger than (and an upper bound on) any "the adversary
    explicitly output a colliding pair" event. -/
noncomputable def commitHashCollisionAdvRO
    (𝒜 : CommitHashCollisionAdvRO) (n : ℕ) : ℝ≥0∞ :=
  Pr[fun z => LogHasCollision z.2 |
      (simulateQ loggingOracle (𝒜 n)).run]

/-- **Birthday bound on the RO-shape commit-hash collision advantage**.

    Direct consequence of `commitHash_logCollision_birthday_bound`. -/
theorem commitHashCollisionAdvRO_le_birthday_bound
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) (n : ℕ) :
    commitHashCollisionAdvRO 𝒜 n ≤ (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) :=
  commitHash_logCollision_birthday_bound (𝒜 n) qb (hbound n)

/-- An RO-shape `commitHashBytes` collision-finder adversary. -/
def CommitHashBytesCollisionAdvRO : Type :=
  ℕ → OracleComp CommitHashBytesSpec Unit

/-- The RO-shape advantage of a `commitHashBytes` collision-finder. -/
noncomputable def commitHashBytesCollisionAdvRO
    (𝒜 : CommitHashBytesCollisionAdvRO) (n : ℕ) : ℝ≥0∞ :=
  Pr[fun z => LogHasCollision z.2 |
      (simulateQ loggingOracle (𝒜 n)).run]

/-- **Birthday bound on the RO-shape commit-hash-bytes collision
    advantage**. Direct consequence of
    `commitHashBytes_logCollision_birthday_bound`. -/
theorem commitHashBytesCollisionAdvRO_le_birthday_bound
    (𝒜 : CommitHashBytesCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) (n : ℕ) :
    commitHashBytesCollisionAdvRO 𝒜 n ≤ (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) :=
  commitHashBytes_logCollision_birthday_bound (𝒜 n) qb (hbound n)

/-! ## What cycle 6.22.d (queued) will use

Cycle 6.22.c (this section) provides the RO-shape advantage and bound.
Cycle 6.22.d migrates the four downstream lifts:

1. `handshake_binds_ecies_key_negl` (ProtocolVCVioTriple.lean) —
   currently consumes `commitHashCollisionAdv` (honest-sim shape) as
   one of its parametric negligibility hypotheses (per the
   over-bundled triple-bundle packaging). Migration: switch the
   packaging to consume `commitHashCollisionAdvRO`.
2. `session_confidentiality_negl` (same module) — same pattern.
3. `session_confidentiality_via_extractor_negl` (same module) — same.
4. `cross_component_session_bind_negl` (ProtocolVCVioQuad.lean) —
   consumes both `commitHashCollisionAdv` and
   `commitHashBytesCollisionAdv` in the quad-bundle packaging.
   Migration: switch both to RO-shape advantages.

The lift proof bodies themselves don't consume these hypotheses (per
the cycle-6.4–6.11 over-bundling finding); only the
`*_secure_of_*_bundle_secure` packaging wrappers do. The migration
is therefore confined to the packaging wrappers.

### Round A attack #8 closure status (refreshed)

* Surface-side closure: cycle 6.15 (def-tying) — DONE.
* Substantive RO scaffolding: cycle 6.22.a — DONE.
* Substantive RO bound (log-collision form): cycle 6.22.b — DONE
  (above).
* Substantive RO bound (advantage form): cycle 6.22.c — DONE (this
  section).
* Downstream packaging migration: cycle 6.22.d — queued.
* Substantive RO bound (win-pred form, lifted into `commitHashCollisionAdv`-
  shaped advantage): cycle 6.22.c — queued.
* Downstream lift migration: cycle 6.22.c — queued. -/

end Specs.Quartz.Protocol.ProtocolVCVioROModel
