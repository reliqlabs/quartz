/-
  VCV-io integration for the UserDataCommit primitive — the truthful
  random-oracle model of `commitHash`.

  Companion module to `Specs/Quartz/Crypto/UserDataCommit.lean`.

  --------------------------------------------------------------------
  Why this module exists (methodology rationale):
  --------------------------------------------------------------------

  The core `UserDataCommit.lean` module retains a single bundled
  trust-boundary axiom

      commitHashE : UserDataCommit ↪ UserData

  which packages "the hash function exists" and "the hash is
  collision-free over the structured domain" into a single
  `Function.Embedding`.

  **This bundled axiom is mathematically impossible.** Pigeonhole
  forbids any injection from an open-cardinality `UserDataCommit`
  (whose `domainSep`, `contractAddr`, `nonce`, `eciesPubkey` fields
  range over abstract carriers without size bounds) into the
  fixed-width 64-byte `UserData` slot. The core module retains it
  because the downstream theorems (`pkOfUserData_commitHash`,
  `handshake_binds_ecies_key`, `session_confidentiality_via_extractor`)
  consume `commitHash_inj` as a deterministic equality.

  The truthful statement — and the one VCV-io is built to support —
  is that the hash function is modelled as a **random oracle**, and
  collisions over the queried set are negligible probability:

      Pr[collision among q queries to commitHash] ≤ q² / 2^|UserData|

  This module sketches that random-oracle model. It is intentionally
  kept small and free of `evalDist`/`Pr[...]` apparatus — those carry
  significant `[Fintype]` / `[Inhabited]` setup that the
  abstract-type carriers in `UserDataCommit.lean` cannot satisfy
  without further refinement.

  The module's job is documentary and structural: it shows what the
  honest statement *looks like* in VCV-io's idiom, so that future
  work (Steps 6+ of the refactor plan) has a concrete handle to
  migrate the protocol-layer theorems onto.

  --------------------------------------------------------------------
  What this module does NOT do:
  --------------------------------------------------------------------

  * It does **not** replace `commitHashE` with the negligibility
    statement at the core layer. The core module's downstream
    consumers still ride on deterministic injectivity.

  * It does **not** prove negligibility — that requires a concrete
    `[Fintype UserData]` instance (currently absent — `UserData` is
    a fully abstract axiom from `Dstack.lean`) and the birthday
    bound, neither of which is in scope for Step 2.

  * It does **not** provide a usable random-oracle handler — the
    abstract-type carriers cannot be enumerated, so no concrete
    distribution can be built. The handler signature is documentary.

  Outstanding follow-up: once `UserData` is refined to a concrete
  fixed-width type (e.g. `BitVec 512`) and `UserDataCommit`'s
  carrier types are either bounded or replaced by concrete bytes,
  the `commitHash_collision_negl` theorem below can be proven from
  VCV-io's `randomOracle` apparatus directly.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import Specs.Quartz.Crypto.UserDataCommit

namespace Specs.Quartz.Crypto.UserDataCommitVCVio

open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack

/-- Random-oracle specification for `commitHash`.

    In VCV-io's data model an `OracleSpec ι` is a function
    `ι → Type` mapping each query index to that oracle's response
    type. We use `ι := UserDataCommit` (the *input* to the oracle)
    and respond with `UserData` (the 64-byte output slot). This is
    the canonical "single random oracle keyed on its domain" shape.

    Note: to use this spec with the `randomOracle` handler one
    additionally needs `[CommitHashSpec.Fintype]` and
    `[CommitHashSpec.Inhabited]` instances — currently *not*
    derivable because `UserData` (the response type) and
    `UserDataCommit` (the index type, via its abstract carriers)
    are not `Fintype`. -/
def CommitHashSpec : OracleSpec UserDataCommit := fun _ => UserData

/-- The `commitHash` operation, expressed as an `OracleComp` query
    against `CommitHashSpec`.

    This is the *truthful* shape: `commitHash uc` is not a pure
    function but a *query* to the random oracle. Two calls with
    the same input return the same answer (via the lazy caching
    `randomOracle` handler), but the answers are uniformly random
    over `UserData` from the adversary's perspective.

    Currently kept as a documentary definition; full integration
    requires the `[Fintype]` / `[Inhabited]` instances mentioned
    above. -/
noncomputable def commitHashOC (uc : UserDataCommit) :
    OracleComp CommitHashSpec UserData :=
  OracleComp.lift (OracleQuery.query (spec := CommitHashSpec) uc)

/-
  **Honesty target (sketch, unproved)**: collisions in the random-
  oracle `commitHash` are negligible probability.

  The truthful statement that replaces the impossible
  `commitHash_inj` axiom from `UserDataCommit.lean`. Stated here
  in informal form (as a comment) because proving it requires:

    1. `[Fintype UserData]` (or a `Card`-style bound), currently
       absent — `UserData` is fully abstract in `Dstack.lean`.
    2. The birthday bound from
       `VCVio/OracleComp/QueryTracking/Birthday.lean`.
    3. A bound on the adversary's query count.

  Informal statement:

      ∀ (uc₁ uc₂ : UserDataCommit), uc₁ ≠ uc₂ →
      Pr[h₁ = h₂ | h₁ ← commitHashOC uc₁; h₂ ← commitHashOC uc₂]
      ≤ negligible(security_parameter)

  where `negligible(λ)` is the `Asymptotics.negligible` shape
  VCV-io provides in `CryptoFoundations/Asymptotics/Negligible.lean`.

  **Why it is not a `theorem` here**: the abstract carriers in
  `UserDataCommit.lean` (DomainSep, Addr, Nonce, PubKey, UserData)
  are not `Fintype`. Without finiteness, `Pr[...]` cannot be
  instantiated. Demoting to a `theorem` requires either
  refinement of those carriers or a parametric statement
  `[Fintype UserData] -> negligible ...`.

  Documented as commentary so the methodology audit surface
  explicitly carries the "what we cannot yet prove" flag without
  introducing a `sorry` or a fake placeholder.
-/

end Specs.Quartz.Crypto.UserDataCommitVCVio
