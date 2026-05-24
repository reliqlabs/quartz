/-
  VCV-io integration for the dstack TDX quote-verification primitive
  — the truthful verification-oracle model of `verifyTdxQuote`.

  Companion module to `Specs/Quartz/Attestation/Dstack.lean`.

  --------------------------------------------------------------------
  Why this module exists (methodology rationale):
  --------------------------------------------------------------------

  The core `Dstack.lean` module retains a single bundled trust-boundary
  record axiom

      tdxVerifier : TdxVerifier

  whose `sound` / `complete` fields are classical-`Prop` implications:

      sound    : verifyTdxQuote q = some (mr, ud) → was_signed_by_dstack q
      complete : was_signed_by_dstack q → ∃ mr ud, verifyTdxQuote q = some (mr, ud)

  **Both implications are honest under named computational assumptions
  but classically over-strong as stated.** Concretely:

  * `sound` is the cryptographic DCAP-soundness assumption: a quote
    that passes the verifier was — *with negligible probability of
    forgery* — produced by a genuine TEE. The classical-Prop form
    drops the negligibility qualifier, making it vacuously stronger
    than what DCAP actually guarantees. An adversary with sufficient
    computational power could in principle forge a quote that passes
    `verify` without holding a genuine PCK; soundness is
    *computational*, not absolute.

  * `complete` is conditional on Intel-collateral freshness and PCK
    non-revocation. A genuine dstack TEE whose attestation collateral
    has expired, or whose PCK chain has been revoked, will fail
    `verify` even though `was_signed_by_dstack` still (operationally)
    holds. The classical-Prop form drops those preconditions.

  This is the **third parallel surfacing** of the impossible /
  classically-over-strong axiom pattern in the VCV-io refactor:

    * Step 2: `commitHashE : UserDataCommit ↪ UserData` (impossible
      injection from open-cardinality to fixed-width)
    * Step 3: `commitHashBytesE : ByteSeq ↪ UserData` (same shape on
      the byte side)
    * Step 4 (here): `tdxVerifier.sound` / `tdxVerifier.complete`
      (classical-Prop implications hiding probabilistic /
      preconditional gaps)

  The Step 2/3 shape is *mathematically* impossible (pigeonhole). The
  Step 4 shape is *operationally* over-strong (the implication is
  true under a named assumption, but the named assumption is
  computational/preconditional, not absolute). Both bucket into the
  same methodology category: "axiom is stated stronger than the
  underlying primitive actually guarantees".

  The truthful statements — and the ones VCV-io is built to support
  — are negligibility bounds against an oracle-querying adversary:

      Pr[adversary forges a quote that passes verify but was NOT
         signed by dstack] ≤ negligible(security_parameter)

      Pr[honest dstack-signed quote with fresh, non-revoked
         collateral fails to decode] = 0  (conditional completeness)

  This module sketches the verification-oracle model. It is
  intentionally kept small and free of `evalDist` / `Pr[...]`
  apparatus — those carry significant `[Fintype]` / `[Inhabited]`
  setup that the abstract-type carriers (`TdxQuote`, `MrEnclave`,
  `UserData`) cannot satisfy without further refinement.

  The module's job is documentary and structural: it shows what the
  honest statement *looks like* in VCV-io's idiom, so that future
  work (Steps 6+ of the refactor plan) has a concrete handle to
  migrate the protocol-layer + attestation theorems onto.

  --------------------------------------------------------------------
  What this module does NOT do:
  --------------------------------------------------------------------

  * It does **not** replace `tdxVerifier` with the negligibility
    formulation at the core layer. The core module's downstream
    consumers (in `Zkdcap.lean`, `Protocol/Handshake.lean`,
    `Protocol/Confidentiality.lean`, `Protocol/CrossComponent.lean`,
    `Protocol/Conservation.lean`, `Protocol/AuctionDeterminism.lean`)
    still ride on the classical-Prop implications.

  * It does **not** prove the negligibility bound — that requires
    a concrete adversary game, a `[Fintype TdxQuote]` instance
    (currently absent), and a reduction to the underlying DCAP
    signature scheme. Neither is in scope for Step 4.

  * It does **not** provide a usable verification-oracle handler —
    the abstract-type carriers cannot be enumerated, so no concrete
    distribution can be built. The handler signature is documentary.

  Outstanding follow-up: once `TdxQuote` is refined to a concrete
  byte-list / `BitVec n` carrier and a concrete DCAP verifier
  semantics is plugged in, the `tdxVerifier_soundness_negl` theorem
  below can be proven from a reduction to PCK-signature
  unforgeability.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import Specs.Quartz.Attestation.Dstack

namespace Specs.Quartz.Attestation.DstackVCVio

open Specs.Quartz.Attestation.Dstack

/-- Verification-oracle specification for `verifyTdxQuote`.

    In VCV-io's data model an `OracleSpec ι` is a function
    `ι → Type` mapping each query index to that oracle's response
    type. We use `ι := TdxQuote` (the *input* to the verifier) and
    respond with `Option (MrEnclave × UserData)` (decoded fields on
    success, `none` on failure). This is the canonical
    "single verification oracle keyed on its quote input" shape.

    Note: to use this spec with a probabilistic handler one
    additionally needs `[VerifyTdxQuoteSpec.Fintype]` and
    `[VerifyTdxQuoteSpec.Inhabited]` instances — currently *not*
    derivable because `TdxQuote`, `MrEnclave`, and `UserData` are
    abstract axioms with no `Fintype`/`Inhabited` content.

    Note (vs Step 2/3 random-oracle specs): this is a
    *verification* oracle (input → bool/option), not a *random*
    oracle (input → uniform-random hash output). The handler
    semantics differ: a verification oracle's response is
    deterministic given the underlying primitive's public state
    (verification key, collateral), whereas a random oracle's
    response is lazily-uniform-random per query. -/
def VerifyTdxQuoteSpec (n : Nat) : OracleSpec TdxQuote := fun _ => Option (MrEnclave × UserData n)

/-- The `verifyTdxQuote` operation, expressed as an `OracleComp`
    query against `VerifyTdxQuoteSpec`.

    This is the *truthful* shape: `verifyTdxQuote q` is not a pure
    function but a *query* to the verification oracle. The oracle's
    handler models the real-world DCAP verifier (Intel PCK chain
    walk + signature checks + collateral freshness checks). Two
    calls on the same quote return the same answer; the answer is
    a deterministic function of the verifier's public state, not
    of randomness.

    Adversarial soundness against this oracle is the truthful
    formulation of the classical `verifyTdxQuote_sound` axiom:
    no PPT adversary can produce a `q` such that the oracle
    returns `some _` but `was_signed_by_dstack q` is false,
    except with negligible probability over the verifier's
    setup randomness.

    Currently kept as a documentary definition; full integration
    requires the `[Fintype]` / `[Inhabited]` instances mentioned
    above plus a concrete reduction to PCK-signature
    unforgeability. -/
noncomputable def verifyTdxQuoteOC (n : Nat) (q : TdxQuote) :
    OracleComp (VerifyTdxQuoteSpec n) (Option (MrEnclave × UserData n)) :=
  OracleComp.lift (OracleQuery.query (spec := VerifyTdxQuoteSpec n) q)

/-
  **Honesty target (sketch, unproved): soundness negligibility**

  The truthful statement that replaces the classical-Prop
  `tdxVerifier.sound` field from `Dstack.lean`. Stated here in
  informal form (as a comment) because proving it requires:

    1. `[Fintype TdxQuote]` (or a `Card`-style bound), currently
       absent — `TdxQuote` is fully abstract in `Dstack.lean`.
    2. A concrete adversary game model (PPT adversary querying
       the oracle, attempting to output a non-genuine accepted
       quote).
    3. A reduction to PCK signature unforgeability (the
       underlying cryptographic assumption from Intel's DCAP
       design).
    4. VCV-io's `Negligible` apparatus from
       `CryptoFoundations/Asymptotics/Negligible.lean`.

  Informal statement (soundness):

      ∀ (𝒜 : PPT-Adversary VerifyTdxQuoteSpec) (n : security_parameter),
      Pr[ verify(q) = some (mr, ud) ∧ ¬ was_signed_by_dstack q
        | (q, mr, ud) ← 𝒜.run(n) ]
      ≤ negligible(n)

  Informal statement (completeness, conditional):

      ∀ (q : TdxQuote),
      was_signed_by_dstack q ∧ freshCollateral q ∧ ¬revoked q
      → ∃ mr ud, verify q = some (mr, ud)

  where `freshCollateral` / `revoked` are predicates on the
  Intel-collateral state. (The current classical-Prop axiom
  collapses these preconditions; the truthful form makes them
  explicit.)

  **Why these are not `theorem`s here**: as in Steps 2 and 3,
  the abstract carriers (`TdxQuote`, `MrEnclave`, `UserData`)
  are not `Fintype`. Without finiteness, `Pr[...]` cannot be
  instantiated. Demoting to `theorem`s requires either
  refinement of those carriers or a parametric statement
  `[Fintype TdxQuote] -> negligible ...`.

  Additionally, the soundness reduction needs an underlying
  signature-unforgeability assumption that is not itself
  modelled in this module. (DCAP's underlying primitive is
  ECDSA over secp256r1, plus Intel's PCK certification chain
  — both modellable in VCV-io once the carrier types are
  concrete, but neither in scope for Step 4.)

  Documented as commentary so the methodology audit surface
  explicitly carries the "what we cannot yet prove" flag without
  introducing a `sorry` or a fake placeholder.

  --------------------------------------------------------------------

  Step 6 (protocol-layer OracleComp lift) will consume this
  companion plus `EciesVCVio`, `UserDataCommitVCVio`,
  `RawMessagesVCVio`, and the forthcoming `ZkdcapVCVio` (Step 5)
  to express the truthful collision- and forgery-bounded
  versions of the protocol theorems. The composition will
  use a union bound across:

      Pr[ protocol_attack ] ≤ Pr[ commitHash_collision ]
                            + Pr[ commitHashBytes_collision ]
                            + Pr[ tdxVerifier_forgery ]
                            + Pr[ groth16_forgery ]

  Each summand is supplied by one companion module.
-/

end Specs.Quartz.Attestation.DstackVCVio
