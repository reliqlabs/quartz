/-
  VCV-io integration for the byte-level `commitHashBytes` primitive
  — the truthful random-oracle model of the SHA-256-based byte hash
  used in Quartz's `user_data` encoding path.

  Companion module to `Specs/Quartz/Crypto/RawMessages.lean`.

  --------------------------------------------------------------------
  Why this module exists (methodology rationale):
  --------------------------------------------------------------------

  The core `RawMessages.lean` module retains a single bundled
  trust-boundary axiom

      commitHashBytesE : ByteSeq ↪ UserData

  which packages "the byte-hash function exists" and "the byte-hash
  is collision-free over `ByteSeq`" into a single
  `Function.Embedding`.

  **This bundled axiom is mathematically impossible.** Pigeonhole
  forbids any injection from an open-cardinality `ByteSeq` (an
  opaque byte-sequence carrier with no size bound) into the
  fixed-width 64-byte `UserData` slot. The core module retains
  it because the downstream theorems
  (`distinct_raw_session_create_gives_distinct_user_data`,
  `distinct_raw_session_set_pub_key_gives_distinct_user_data`,
  `userDataOfSessionCreate_inj`, `userDataOfSessionSetPubKey_inj`,
  `distinct_transfer_request_gives_distinct_user_data`,
  `userDataOfTransferRequest_inj`,
  `distinct_resolve_message_gives_distinct_user_data`,
  `userDataOfResolveMessage_inj`) consume `commitHashBytes_inj`
  as a deterministic equality.

  This is the second parallel surfacing of the same impossibility
  pattern in the VCV-io refactor — Step 2's `commitHashE` (on
  the structured `UserDataCommit` domain) was the first. Both
  carry the same shape: an injective embedding from an
  open-cardinality preimage into a fixed-width hash codomain. The
  truthful statement in both cases is negligible-probability
  collision in a random-oracle model.

  The truthful statement — and the one VCV-io is built to support —
  is that the byte-hash is modelled as a **random oracle**, and
  collisions over the queried set are negligible probability:

      Pr[collision among q queries to commitHashBytes] ≤ q² / 2^|UserData|

  This module sketches that random-oracle model. It is intentionally
  kept small and free of `evalDist`/`Pr[...]` apparatus — those carry
  significant `[Fintype]` / `[Inhabited]` setup that the
  abstract-type carriers (`ByteSeq`, `UserData`) cannot satisfy
  without further refinement.

  The module's job is documentary and structural: it shows what the
  honest statement *looks like* in VCV-io's idiom, so that future
  work (Steps 6+ of the refactor plan) has a concrete handle to
  migrate the protocol-layer + cross-module theorems onto.

  --------------------------------------------------------------------
  What this module does NOT do:
  --------------------------------------------------------------------

  * It does **not** replace `commitHashBytesE` with the
    negligibility statement at the core layer. The core module's
    downstream consumers (in `RawMessages.lean`,
    `TransferMessages.lean`, `AuctionMessages.lean`) still ride on
    deterministic injectivity.

  * It does **not** prove negligibility — that requires a concrete
    `[Fintype UserData]` instance (currently absent — `UserData`
    is a fully abstract axiom from `Dstack.lean`) and the birthday
    bound, neither of which is in scope for Step 3.

  * It does **not** provide a usable random-oracle handler — the
    abstract-type carriers cannot be enumerated, so no concrete
    distribution can be built. The handler signature is documentary.

  Outstanding follow-up: once `UserData` is refined to a concrete
  fixed-width type (e.g. `BitVec 512`) and `ByteSeq` is refined to
  a concrete byte-list / `List UInt8` carrier (or similar), the
  `commitHashBytes_collision_negl` theorem below can be proven from
  VCV-io's `randomOracle` apparatus directly.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import Specs.Quartz.Crypto.RawMessages

namespace Specs.Quartz.Crypto.RawMessagesVCVio

open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack

/-- Random-oracle specification for `commitHashBytes`.

    In VCV-io's data model an `OracleSpec ι` is a function
    `ι → Type` mapping each query index to that oracle's response
    type. We use `ι := ByteSeq` (the *input* to the oracle) and
    respond with `UserData` (the 64-byte output slot). This is
    the canonical "single random oracle keyed on its byte-string
    domain" shape.

    Note: to use this spec with the `randomOracle` handler one
    additionally needs `[CommitHashBytesSpec.Fintype]` and
    `[CommitHashBytesSpec.Inhabited]` instances — currently *not*
    derivable because `UserData` (the response type) and
    `ByteSeq` (the index type) are abstract axioms with no
    `Fintype`/`Inhabited` content. -/
def CommitHashBytesSpec (n : Nat) : OracleSpec ByteSeq := fun _ => UserData n

/-- The `commitHashBytes` operation, expressed as an `OracleComp`
    query against `CommitHashBytesSpec`.

    This is the *truthful* shape: `commitHashBytes b` is not a
    pure function but a *query* to the random oracle. Two calls
    with the same input return the same answer (via the lazy
    caching `randomOracle` handler), but the answers are
    uniformly random over `UserData` from the adversary's
    perspective.

    Currently kept as a documentary definition; full integration
    requires the `[Fintype]` / `[Inhabited]` instances mentioned
    above. -/
noncomputable def commitHashBytesOC (n : Nat) (b : ByteSeq) :
    OracleComp (CommitHashBytesSpec n) (UserData n) :=
  OracleComp.lift (OracleQuery.query (spec := CommitHashBytesSpec n) b)

/-
  **Honesty target (sketch, unproved)**: collisions in the random-
  oracle `commitHashBytes` are negligible probability.

  The truthful statement that replaces the impossible
  `commitHashBytes_inj` axiom from `RawMessages.lean`. Stated here
  in informal form (as a comment) because proving it requires:

    1. `[Fintype UserData]` (or a `Card`-style bound), currently
       absent — `UserData` is fully abstract in `Dstack.lean`.
    2. The birthday bound from
       `VCVio/OracleComp/QueryTracking/Birthday.lean`.
    3. A bound on the adversary's query count.

  Informal statement:

      ∀ (b₁ b₂ : ByteSeq), b₁ ≠ b₂ →
      Pr[h₁ = h₂ | h₁ ← commitHashBytesOC b₁; h₂ ← commitHashBytesOC b₂]
      ≤ negligible(security_parameter)

  where `negligible(λ)` is the `Asymptotics.negligible` shape
  VCV-io provides in `CryptoFoundations/Asymptotics/Negligible.lean`.

  **Why it is not a `theorem` here**: the abstract carriers
  `ByteSeq` and `UserData` are not `Fintype`. Without finiteness,
  `Pr[...]` cannot be instantiated. Demoting to a `theorem`
  requires either refinement of those carriers or a parametric
  statement `[Fintype UserData] -> negligible ...`.

  Documented as commentary so the methodology audit surface
  explicitly carries the "what we cannot yet prove" flag without
  introducing a `sorry` or a fake placeholder.

  --------------------------------------------------------------------

  This is the second module in the refactor sequence to carry
  this companion-sketch pattern (after Step 2's
  `UserDataCommitVCVio.lean`). The two sketches together cover
  both impossibility points in the cryptographic trust boundary
  surfaced by the VCV-io migration:

    * `UserDataCommitVCVio.commitHashOC`     — structured-domain hash
    * `RawMessagesVCVio.commitHashBytesOC`  — byte-domain hash

  Step 6 (protocol-layer OracleComp lift) will need both of these
  random-oracle models to express the truthful collision-bound
  versions of the protocol theorems.
-/

end Specs.Quartz.Crypto.RawMessagesVCVio
