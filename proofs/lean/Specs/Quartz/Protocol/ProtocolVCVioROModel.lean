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
* Explicit `DecidableEq` instances on the carrier types and
  `SampleableType` instances on the spec ranges, plumbing the
  `randomOracle` requirements through the cycle-6.21 concrete carriers.

## Cycle 6.22.b blocker — see in-file note below

The substantive birthday-bound theorem requires `OracleSpec.Fintype`
on `CommitHashSpec`, which requires `Fintype` on the *index* type
`UserDataCommit`. Cycle 6.21 made `UserDataCommit`'s fields
`List UInt8`/`String` (matching production-faithful variable-length
shapes), so the index is infinite and `OracleSpec.Fintype` does not
hold. Three remediation paths are documented below; all are out of
session scope.
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

/-! ## Cycle 6.22.b BLOCKER (2026-05-23) — `spec.Fintype` incompatibility

The intended cycle 6.22.b deliverable was a theorem of the shape:

    commitHashCollisionAdvRO 𝒜 n ≤ (qb + 2)² / (2 · 2^512)

…proved via VCV-io's `probEvent_logCollision_le_birthday_total` in
`VCVio/OracleComp/QueryTracking/Birthday.lean:396`. That theorem's
file-level variable declaration (line 21) requires
`[spec.DecidableEq] [spec.Fintype] [spec.Inhabited]`. Specifically,
`OracleSpec.Fintype spec` extends `PFunctor.Fintype` which requires
`Fintype` on BOTH the *index* type and the *range* type.

For `CommitHashSpec : OracleSpec UserDataCommit`:

* Range = `UserData = BitVec 512` — **Fintype OK** (post cycle 6.18).
* Index = `UserDataCommit` — **Fintype FAILS**. `UserDataCommit`
  has `domainSep : DomainSep = List UInt8` and
  `contractAddr : Addr = String` fields, both infinite types
  post cycle 6.20.

This is a genuine incompatibility between two design choices:

* Cycle 6.21's carrier refinement chose `List UInt8`/`String` for
  variable-length fields to match production semantics faithfully.
* VCV-io's birthday bound was designed for fixed-size index types
  (typical in cryptographic specs where the adversary submits
  finite-domain inputs).

### Three remediation paths, all out of session scope

(a) **Bound the spec's index artificially**: introduce a parallel
    spec `BoundedCommitHashSpec` over `Vector UInt8 N × ... ×
    Vector UInt8 M` for fixed maxima. Prove the bound under the
    bounded spec. Connect to production via the observation that
    deployed `domainSep` is `"QUARTZ-HS-V1"` (12 bytes, fits) and
    `contractAddr` is a bech32 (fixed-length, fits). Loses
    generality over arbitrary deployments but is the cleanest
    local fix. Estimated effort: ~2 days. Recommended next step.

(b) **Weaken VCV-io's bound to drop `[spec.Fintype]` on the index**:
    the birthday argument doesn't fundamentally need Fintype on the
    domain — only on the range. Sending an upstream PR to VCV-io
    would relax this. Cross-repo work, weeks of coordination.

(c) **Refactor cycle 6.21**: revert
    `DomainSep`/`Addr`/`ByteSeq` to fixed-width carriers
    (`BitVec`-based) at the cost of losing production
    correspondence on variable-length fields. Loses the cycle-6.21
    win that the deployed `domainSep`/`addr` shape is faithfully
    modelled. Not recommended.

### Methodology v0.4 ask: variable-length-domain birthday bounds

Adding to the colosseum methodology v0.4 ask candidates: when an
`OracleSpec` has a variable-length domain (matching real-world
variable-length hash inputs), VCV-io's birthday-bound infrastructure
does not apply without artificial bounding. The right end state is
upstream relaxation of the `spec.Fintype` requirement in
`probEvent_logCollision_le_birthday_total` to `Fintype` on range
only. Methodology should flag this whenever a spec's domain refines
to `List`/`String` / other infinite carriers and a downstream
collision-bound theorem is queued.

### What cycle 6.22.a (this module) leaves in place

The scaffolding (`*ROSim` simulators, `SampleableType (BitVec 512)`
instances, explicit `DecidableEq UserDataCommit` instances) is real
preparation. When one of the three remediation paths above lands,
the bound theorem slots in directly above the existing simulator
definitions.

The cycle-6.15 `commitHashCollisionAdv` continues to be well-typed
and consumed by the protocol-layer triple-bundle / quad-bundle
lifts as a parametric negligibility hypothesis. The substantive
content (the bound proof) remains externally deferred.

### Reframe for Round A attack #8 closure status

* Surface-side closure: cycle 6.15 (def-tying) — DONE.
* Substantive Option-(a) closure: cycle 6.22 — partially done.
  Scaffolding landed (cycle 6.22.a, this module). Bound theorem
  blocked by `spec.Fintype` requirement; three remediation paths
  documented. -/

end Specs.Quartz.Protocol.ProtocolVCVioROModel
