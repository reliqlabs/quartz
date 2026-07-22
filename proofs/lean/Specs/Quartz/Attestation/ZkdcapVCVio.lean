/-
  VCV-io integration for the zkdcap zero-knowledge verification
  primitive — the truthful verification-oracle model of `verifyZk`.

  Companion module to `Specs/Quartz/Attestation/Zkdcap.lean`.

  --------------------------------------------------------------------
  Why this module exists (methodology rationale):
  --------------------------------------------------------------------

  The core `Zkdcap.lean` module retains a single bundled trust-boundary
  record axiom

      zkVerifier : ZkVerifier

  (proof-system-neutral; live instantiation UltraHonk) whose `sound`
  field is a classical-`Prop` implication:

      sound : verify vkey proof inputs = true →
              was_signed_by_dstack (inputsToQuote inputs)

  **This implication is honest under TWO composed computational
  assumptions but classically over-strong as stated.** Concretely:

  * **UltraHonk knowledge soundness** (boundary K1): a proof that
    verifies under a trusted vkey was — *with negligible probability
    of forgery* — produced by a prover that knew a satisfying witness
    for the compiled Noir relation. The classical-Prop form drops the
    negligibility qualifier, making it vacuously stronger than what
    the release-pinned Barretenberg verifier actually guarantees. The
    underlying assumption is the PLONK-family / IOP soundness bound,
    asymptotic over a security parameter `λ`.

  * **Circuit-vs-R_v1 equivalence**: the zkdcap Noir circuit
    faithfully encodes the exact versioned relation R_v1 (zkdcap
    intent v0.3.0 §1.2) — implemented PCK-chain and collateral
    signatures, quote/QE signatures and bindings, selected PCK-CRL and
    TCB/QE comparisons, an intersected validity range, measurements,
    report data, status, certificate serial/FMSPC, and separate TCB
    Info / QE Identity evaluation numbers. This is a
    *circuit-correctness* claim against a reference implementation of
    **R_v1 only** (NOT the full Intel-QVL relation R_target; that
    equivalence is known false). Neither end is itself currently
    formally verified, so the bound is computational
    (correctness-modulo-implementation-bugs).

  This is the **fourth parallel surfacing** of the
  classically-over-strong (d)-bucket pattern in the VCV-io refactor:

    * Step 2: `commitHashE : UserDataCommit ↪ UserData` (impossible
      injection from open-cardinality to fixed-width — *sub-shape:
      mathematically impossible*)
    * Step 3: `commitHashBytesE : ByteSeq ↪ UserData` (same shape
      on the byte side — *sub-shape: mathematically impossible*)
    * Step 4: `tdxVerifier.sound` / `tdxVerifier.complete`
      (classical-Prop implications dropping DCAP-soundness
      negligibility and collateral-freshness preconditions —
      *sub-shape: classically over-strong*)
    * Step 5 (here): `zkVerifier.sound` (classical-Prop implication
      dropping both UltraHonk knowledge-soundness and zkdcap
      circuit-vs-R_v1 equivalence negligibility qualifiers —
      *sub-shape: classically over-strong, DOUBLED*)

  Step 5 differs from Step 4 in that the over-strength is *doubled*:
  two independent computational assumptions are folded into one
  classical-Prop implication. The truthful negligibility bound
  decomposes as

      negligible(λ) = negligible_ultrahonk(λ) + negligible_circuit(λ)

  where the two summands have independent justifications
  (cryptographic for UltraHonk, software-verification for
  circuit-vs-R_v1 equivalence) and independent paths to discharge.

  The truthful statements — and the ones VCV-io is built to support —
  are negligibility bounds against an oracle-querying adversary:

      Pr[adversary outputs (proof, inputs) such that
         verify(vkey, proof, inputs) = true ∧
         ¬ was_signed_by_dstack(inputsToQuote inputs)]
      ≤ negligible(security_parameter)

  This module sketches the verification-oracle model. It is
  intentionally kept small and free of `evalDist` / `Pr[...]`
  apparatus — those carry significant `[Fintype]` / `[Inhabited]`
  setup that the abstract-type carriers (`ZkProof`,
  `PublicInputs`, `VKey`, plus the cross-module carriers
  `TdxQuote`, `MrEnclave`, `UserData`) cannot satisfy without
  further refinement.

  The module's job is documentary and structural: it shows what
  the honest statement *looks like* in VCV-io's idiom, so that
  future work (Steps 6+ of the refactor plan) has a concrete
  handle to migrate the protocol-layer + cross-module theorems
  onto.

  --------------------------------------------------------------------
  What this module does NOT do:
  --------------------------------------------------------------------

  * It does **not** replace `zkVerifier` with the negligibility
    formulation at the core layer. The core module's downstream
    consumers (in `Protocol/Handshake.lean`,
    `Protocol/Confidentiality.lean`, `Protocol/CrossComponent.lean`,
    `Protocol/Conservation.lean`, `Protocol/AuctionDeterminism.lean`)
    still ride on the classical-Prop implication.

  * It does **not** prove the negligibility bound — that requires
    (a) a concrete adversary game model, (b) `[Fintype]` instances
    on the carriers (currently absent), (c) a reduction to UltraHonk
    knowledge-soundness (cryptographic), and (d) a circuit-equivalence
    proof against a reference implementation of R_v1
    (software-verification, separate effort). Neither (c) nor (d)
    is in scope for Step 5.

  * It does **not** provide a usable verification-oracle handler —
    the abstract-type carriers cannot be enumerated, so no concrete
    distribution can be built. The handler signature is documentary.

  Outstanding follow-up: once `ZkProof` / `PublicInputs` / `VKey`
  are refined to concrete byte-list / `BitVec n` carriers AND the
  zkdcap circuit is given a reference model of R_v1 that a SNARK
  library can relate to, the `zkVerifier_soundness_negl` theorem
  below can be proven from a reduction to UltraHonk knowledge
  soundness + a circuit-vs-R_v1 equivalence theorem.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import Specs.Quartz.Attestation.Zkdcap

namespace Specs.Quartz.Attestation.ZkdcapVCVio

open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap

/-- The (vkey, proof, inputs) tuple that keys a single zkdcap
    verification query.

    In VCV-io's `OracleSpec` data model the index type is the
    *input* to the oracle. For a zero-knowledge verifier the natural
    index is the full call site — verification key, proof, and
    public inputs together — because the verifier is a pure
    function of these three. Two calls on the same triple return
    the same answer; different triples can return different
    answers. -/
abbrev VerifyZkQuery : Type := VKey × ZkProof × PublicInputs

/-- Back-compat alias for the historical `VerifyGroth16Query`. The
    neutral name is `VerifyZkQuery`. -/
abbrev VerifyGroth16Query : Type := VerifyZkQuery

/-- Verification-oracle specification for `verifyZk`.

    Maps each `(vkey, proof, inputs)` query index to the
    verifier's `Bool` response. This is the canonical
    "single verification oracle keyed on its full call site" shape.

    Note: to use this spec with a probabilistic handler one
    additionally needs `[VerifyZkSpec.Fintype]` and
    `[VerifyZkSpec.Inhabited]` instances — currently *not*
    derivable because `VKey`, `ZkProof`, and `PublicInputs`
    are abstract carriers with no `Fintype`/`Inhabited` content.

    Note (vs Step 2/3 random-oracle specs): this is a
    *verification* oracle (input → Bool), not a *random* oracle
    (input → uniform-random hash output). The handler semantics
    differ: a verification oracle's response is deterministic
    given the verifier's public state (the vkey fixes the
    verifier; once fixed, verification is a pure computation),
    whereas a random oracle's response is lazily-uniform-random
    per query.

    Note (vs Step 4's verification-oracle spec): like
    `VerifyTdxQuoteSpec`, this is a verification oracle keyed on
    the input. The shapes differ in the response type
    (`Option (MrEnclave × UserData)` for DCAP, plain `Bool` here)
    and in the index structure (single `TdxQuote` for DCAP, a
    `VKey × ZkProof × PublicInputs` triple here — ZK proof
    verification additionally takes the vkey as input, whereas
    DCAP verification has the PCK chain implicit in the
    verifier's static state). -/
def VerifyZkSpec : OracleSpec VerifyZkQuery := fun _ => Bool

/-- Back-compat alias for the historical `VerifyGroth16Spec`. The
    neutral name is `VerifyZkSpec`. -/
abbrev VerifyGroth16Spec : OracleSpec VerifyGroth16Query := VerifyZkSpec

/-- The `verifyZk` operation, expressed as an `OracleComp`
    query against `VerifyZkSpec`.

    This is the *truthful* shape: `verifyZk vkey proof inputs`
    is not a pure function but a *query* to the verification
    oracle. The oracle's handler models the real-world
    Noir/Barretenberg UltraHonk verifier (the release-pinned
    Barretenberg checks against the vkey). Two calls on the same
    triple return the same answer; the answer is a deterministic
    function of the verifier's public state, not of randomness.

    Adversarial soundness against this oracle is the truthful
    formulation of the classical `verifyZk_sound` axiom:
    no PPT adversary can produce a `(proof, inputs)` pair such
    that the oracle returns `true` under the canonical vkey but
    `was_signed_by_dstack (inputs_to_quote inputs)` is false,
    except with negligible probability over the UltraHonk
    knowledge-soundness bound AND the circuit-vs-R_v1
    equivalence gap.

    Currently kept as a documentary definition; full integration
    requires the `[Fintype]` / `[Inhabited]` instances mentioned
    above plus a concrete reduction to UltraHonk knowledge
    soundness composed with a circuit-equivalence claim. -/
noncomputable def verifyZkOC
    (vkey : VKey) (proof : ZkProof) (inputs : PublicInputs) :
    OracleComp VerifyZkSpec Bool :=
  OracleComp.lift (OracleQuery.query (spec := VerifyZkSpec) (vkey, proof, inputs))

/-- Back-compat alias for the historical `verifyGroth16OC`. The
    neutral name is `verifyZkOC`. -/
noncomputable abbrev verifyGroth16OC
    (vkey : VKey) (proof : Groth16Proof) (inputs : PublicInputs) :
    OracleComp VerifyGroth16Spec Bool :=
  verifyZkOC vkey proof inputs

/-
  **Honesty target (sketch, unproved): soundness negligibility**

  The truthful statement that replaces the classical-Prop
  `zkVerifier.sound` field from `Zkdcap.lean`. Stated here in
  informal form (as a comment) because proving it requires:

    1. `[Fintype ZkProof]` / `[Fintype PublicInputs]` /
       `[Fintype VKey]` (or `Card`-style bounds), currently
       absent — all three are abstract carriers in `Zkdcap.lean`.
    2. A concrete adversary game model (PPT adversary querying
       the oracle, attempting to output `(proof, inputs)` that
       verify but whose `inputs_to_quote` mapping is not
       genuinely dstack-signed).
    3. A reduction to UltraHonk knowledge-soundness (the underlying
       cryptographic assumption, boundary K1 — not yet formalised).
    4. A circuit-equivalence theorem between the zkdcap Noir
       circuit and a reference model of the exact relation R_v1
       (the underlying software-verification claim — separate
       effort, not in scope for the VCV-io refactor).
    5. VCV-io's `Negligible` apparatus from
       `CryptoFoundations/Asymptotics/Negligible.lean`.

  Informal statement (soundness — doubled-negligibility form):

      ∀ (𝒜 : PPT-Adversary VerifyZkSpec) (n : security_parameter),
      Pr[ verify(vkey, proof, inputs) = true ∧
          ¬ was_signed_by_dstack (inputs_to_quote inputs)
        | (proof, inputs) ← 𝒜.run(n) ]
      ≤ negligible_ultrahonk(n) + negligible_circuit(n)

  where:
    * `negligible_ultrahonk(n)` is the UltraHonk knowledge-soundness
      bound (boundary K1), going to zero asymptotically as the
      security parameter grows.
    * `negligible_circuit(n)` is the bound on circuit-vs-R_v1
      equivalence — bug-rate bound on the zkdcap Noir encoding vs a
      reference model of R_v1 (NOT the full Intel-QVL relation).

  This is the **DOUBLED-negligibility** form: two independent
  computational assumptions sum (union bound) into one
  negligibility budget. Step 4's `tdxVerifier_soundness_negl`
  is *single*-negligibility (only the PCK-signature
  unforgeability assumption). The doubling here reflects the
  composition of two trust layers (cryptographic UltraHonk +
  software-verification circuit-vs-R_v1 equivalence).

  Informal statement (completeness — implicit):

      ∀ (proof : ZkProof) (inputs : PublicInputs),
      "proof is a valid UltraHonk proof of the zkdcap circuit for inputs"
      ∧ "inputs_to_quote inputs has fresh Intel collateral"
      ∧ "inputs_to_quote inputs is not on a revoked PCK"
      → verify(vkey, proof, inputs) = true

  Completeness is conditional in the same way as
  `tdxVerifier.complete` was — fresh collateral / non-revocation
  preconditions apply to the in-quote PCK chain.

  **Why these are not `theorem`s here**: as in Steps 2-4, the
  abstract carriers (`ZkProof`, `PublicInputs`, `VKey`) are not
  `Fintype`. Without finiteness, `Pr[...]` cannot be instantiated.
  Demoting to `theorem`s requires either refinement of those
  carriers or a parametric statement
  `[Fintype VKey] [Fintype ZkProof] [Fintype PublicInputs]
   -> negligible ...`.

  Additionally, the soundness reduction needs an underlying
  UltraHonk knowledge-soundness assumption that is not itself
  modelled in this module. And the circuit-equivalence claim needs
  a reference model of R_v1 formalised in Lean (for the implemented
  projection of the DCAP-quote wire-format protocol). Neither is in
  scope for Step 5.

  Documented as commentary so the methodology audit surface
  explicitly carries the "what we cannot yet prove" flag without
  introducing a `sorry` or a fake placeholder.

  --------------------------------------------------------------------

  Step 6 (protocol-layer OracleComp lift) will consume this
  companion plus `EciesVCVio`, `UserDataCommitVCVio`,
  `RawMessagesVCVio`, and `DstackVCVio` to express the truthful
  collision- and forgery-bounded versions of the protocol
  theorems. The composition will use a union bound across:

      Pr[ protocol_attack ] ≤ Pr[ commitHash_collision ]
                            + Pr[ commitHashBytes_collision ]
                            + Pr[ tdxVerifier_forgery ]
                            + Pr[ zk_forgery ]
                              where zk_forgery itself is
                              negligible_ultrahonk + negligible_circuit

  Each summand is supplied by one companion module. This is the
  **quadruple-bundle union bound** that `cross_component_session_bind`
  will become after the Step 6 demotion. The `zk_forgery` summand
  itself further decomposes into two summands, reflecting the
  doubled-negligibility nature of the zkdcap soundness assumption.
-/

end Specs.Quartz.Attestation.ZkdcapVCVio
