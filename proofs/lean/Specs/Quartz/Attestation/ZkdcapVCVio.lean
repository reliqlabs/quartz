/-
  VCV-io integration for the zkdcap Groth16 verification primitive
  — the truthful verification-oracle model of `verifyGroth16`.

  Companion module to `Specs/Quartz/Attestation/Zkdcap.lean`.

  --------------------------------------------------------------------
  Why this module exists (methodology rationale):
  --------------------------------------------------------------------

  The core `Zkdcap.lean` module retains a single bundled trust-boundary
  record axiom

      groth16Verifier : Groth16Verifier

  whose `sound` field is a classical-`Prop` implication:

      sound : verify vkey proof inputs = true →
              was_signed_by_dstack (inputsToQuote inputs)

  **This implication is honest under TWO composed computational
  assumptions but classically over-strong as stated.** Concretely:

  * **Groth16 knowledge soundness over BN254**: a Groth16 proof
    that verifies under a trusted vkey was — *with negligible
    probability of forgery* — produced by a prover that knew a
    satisfying R1CS witness. The classical-Prop form drops the
    negligibility qualifier, making it vacuously stronger than
    what gnark / BN254 actually guarantee. The underlying
    assumption is the KZG / power-knowledge / generic-group-model
    bound (concretely ~2^{-100} soundness error over 254-bit BN
    curves, asymptotic over a security parameter `λ`).

  * **Circuit-vs-reference-DCAP equivalence**: the zkdcap R1CS
    circuit faithfully encodes (a) Intel SGX PCK chain validation
    up to the hard-coded Root CA, (b) DCAP quote-v4 signature
    verification, and (c) the binding of in-quote `report_data` /
    `mr_td` fields to the circuit's public inputs. This is a
    *circuit-correctness* claim against a Rust reference
    implementation — neither end is itself currently formally
    verified, so the bound is computational
    (correctness-modulo-implementation-bugs, with a probability
    of circuit-bug-induced acceptance of a non-genuine quote).

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
    * Step 5 (here): `groth16Verifier.sound` (classical-Prop
      implication dropping both Groth16 knowledge-soundness and
      zkdcap circuit-equivalence negligibility qualifiers —
      *sub-shape: classically over-strong, DOUBLED*)

  Step 5 differs from Step 4 in that the over-strength is *doubled*:
  two independent computational assumptions are folded into one
  classical-Prop implication. The truthful negligibility bound
  decomposes as

      negligible(λ) = negligible_groth16(λ) + negligible_circuit(λ)

  where the two summands have independent justifications
  (cryptographic for Groth16, software-verification for circuit
  equivalence) and independent paths to discharge.

  The truthful statements — and the ones VCV-io is built to support —
  are negligibility bounds against an oracle-querying adversary:

      Pr[adversary outputs (proof, inputs) such that
         verify(vkey, proof, inputs) = true ∧
         ¬ was_signed_by_dstack(inputsToQuote inputs)]
      ≤ negligible(security_parameter)

  This module sketches the verification-oracle model. It is
  intentionally kept small and free of `evalDist` / `Pr[...]`
  apparatus — those carry significant `[Fintype]` / `[Inhabited]`
  setup that the abstract-type carriers (`Groth16Proof`,
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

  * It does **not** replace `groth16Verifier` with the
    negligibility formulation at the core layer. The core module's
    downstream consumers (in `Protocol/Handshake.lean`,
    `Protocol/Confidentiality.lean`, `Protocol/CrossComponent.lean`,
    `Protocol/Conservation.lean`, `Protocol/AuctionDeterminism.lean`)
    still ride on the classical-Prop implication.

  * It does **not** prove the negligibility bound — that requires
    (a) a concrete adversary game model, (b) `[Fintype]` instances
    on the carriers (currently absent), (c) a reduction to BN254
    knowledge-soundness (cryptographic, ArkLib-roadmap), and (d)
    a circuit-equivalence proof against a reference DCAP verifier
    (software-verification, separate effort). Neither (c) nor (d)
    is in scope for Step 5.

  * It does **not** provide a usable verification-oracle handler —
    the abstract-type carriers cannot be enumerated, so no concrete
    distribution can be built. The handler signature is documentary.

  Outstanding follow-up: once `Groth16Proof` / `PublicInputs` /
  `VKey` are refined to concrete byte-list / `BitVec n` carriers
  AND the zkdcap circuit is given a Rust-side reference DCAP
  verifier that ArkLib (or equivalent) can model, the
  `groth16Verifier_soundness_negl` theorem below can be proven
  from a reduction to BN254 knowledge-soundness + a circuit-
  equivalence theorem.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import Specs.Quartz.Attestation.Zkdcap

namespace Specs.Quartz.Attestation.ZkdcapVCVio

open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap

/-- The (vkey, proof, inputs) tuple that keys a single zkdcap
    verification query.

    In VCV-io's `OracleSpec` data model the index type is the
    *input* to the oracle. For a Groth16 verifier the natural
    index is the full call site — verification key, proof, and
    public inputs together — because the verifier is a pure
    function of these three. Two calls on the same triple return
    the same answer; different triples can return different
    answers. -/
abbrev VerifyGroth16Query : Type := VKey × Groth16Proof × PublicInputs

/-- Verification-oracle specification for `verifyGroth16`.

    Maps each `(vkey, proof, inputs)` query index to the
    verifier's `Bool` response. This is the canonical
    "single verification oracle keyed on its full call site" shape.

    Note: to use this spec with a probabilistic handler one
    additionally needs `[VerifyGroth16Spec.Fintype]` and
    `[VerifyGroth16Spec.Inhabited]` instances — currently *not*
    derivable because `VKey`, `Groth16Proof`, and `PublicInputs`
    are abstract axioms with no `Fintype`/`Inhabited` content.

    Note (vs Step 2/3 random-oracle specs): this is a
    *verification* oracle (input → Bool), not a *random* oracle
    (input → uniform-random hash output). The handler semantics
    differ: a verification oracle's response is deterministic
    given the verifier's public state (the vkey embeds the setup
    randomness; once fixed, verification is a pure pairing
    computation), whereas a random oracle's response is
    lazily-uniform-random per query.

    Note (vs Step 4's verification-oracle spec): like
    `VerifyTdxQuoteSpec`, this is a verification oracle keyed on
    the input. The shapes differ in the response type
    (`Option (MrEnclave × UserData)` for DCAP, plain `Bool` here)
    and in the index structure (single `TdxQuote` for DCAP, a
    `VKey × Groth16Proof × PublicInputs` triple here — Groth16
    verification additionally takes the vkey as input, whereas
    DCAP verification has the PCK chain implicit in the
    verifier's static state). -/
def VerifyGroth16Spec : OracleSpec VerifyGroth16Query := fun _ => Bool

/-- The `verifyGroth16` operation, expressed as an `OracleComp`
    query against `VerifyGroth16Spec`.

    This is the *truthful* shape: `verifyGroth16 vkey proof inputs`
    is not a pure function but a *query* to the verification
    oracle. The oracle's handler models the real-world gnark
    Groth16 verifier (BN254 pairing checks against the vkey).
    Two calls on the same triple return the same answer; the
    answer is a deterministic function of the verifier's public
    state, not of randomness.

    Adversarial soundness against this oracle is the truthful
    formulation of the classical `verifyGroth16_sound` axiom:
    no PPT adversary can produce a `(proof, inputs)` pair such
    that the oracle returns `true` under the canonical vkey but
    `was_signed_by_dstack (inputs_to_quote inputs)` is false,
    except with negligible probability over the trusted-setup
    randomness AND the circuit-correctness gap.

    Currently kept as a documentary definition; full integration
    requires the `[Fintype]` / `[Inhabited]` instances mentioned
    above plus a concrete reduction to BN254 knowledge-
    soundness composed with a circuit-equivalence claim. -/
noncomputable def verifyGroth16OC
    (vkey : VKey) (proof : Groth16Proof) (inputs : PublicInputs) :
    OracleComp VerifyGroth16Spec Bool :=
  OracleComp.lift (OracleQuery.query (spec := VerifyGroth16Spec) (vkey, proof, inputs))

/-
  **Honesty target (sketch, unproved): soundness negligibility**

  The truthful statement that replaces the classical-Prop
  `groth16Verifier.sound` field from `Zkdcap.lean`. Stated here
  in informal form (as a comment) because proving it requires:

    1. `[Fintype Groth16Proof]` / `[Fintype PublicInputs]` /
       `[Fintype VKey]` (or `Card`-style bounds), currently
       absent — all three are fully abstract in `Zkdcap.lean`.
    2. A concrete adversary game model (PPT adversary querying
       the oracle, attempting to output `(proof, inputs)` that
       verify but whose `inputs_to_quote` mapping is not
       genuinely dstack-signed).
    3. A reduction to BN254 knowledge-soundness (the underlying
       cryptographic assumption — ArkLib roadmap; not yet
       formalised).
    4. A circuit-equivalence theorem between the zkdcap R1CS
       circuit and a reference DCAP verifier semantics (the
       underlying software-verification claim — separate effort,
       not in scope for the VCV-io refactor).
    5. VCV-io's `Negligible` apparatus from
       `CryptoFoundations/Asymptotics/Negligible.lean`.

  Informal statement (soundness — doubled-negligibility form):

      ∀ (𝒜 : PPT-Adversary VerifyGroth16Spec) (n : security_parameter),
      Pr[ verify(vkey, proof, inputs) = true ∧
          ¬ was_signed_by_dstack (inputs_to_quote inputs)
        | (proof, inputs) ← 𝒜.run(n) ]
      ≤ negligible_groth16(n) + negligible_circuit(n)

  where:
    * `negligible_groth16(n)` is the BN254 knowledge-soundness
      bound — concretely ~2^{-100} for 254-bit BN curves, going
      to zero asymptotically as the security parameter grows.
    * `negligible_circuit(n)` is the bound on
      circuit-vs-reference-DCAP-verifier equivalence — bug-rate
      bound on the zkdcap R1CS encoding vs an Intel-spec DCAP
      reference verifier.

  This is the **DOUBLED-negligibility** form: two independent
  computational assumptions sum (union bound) into one
  negligibility budget. Step 4's `tdxVerifier_soundness_negl`
  is *single*-negligibility (only the PCK-signature
  unforgeability assumption). The doubling here reflects the
  composition of two trust layers (cryptographic Groth16 +
  software-verification circuit-equivalence).

  Informal statement (completeness — implicit):

      ∀ (proof : Groth16Proof) (inputs : PublicInputs),
      "proof is a valid Groth16 proof of the zkdcap R1CS for inputs"
      ∧ "inputs_to_quote inputs has fresh Intel collateral"
      ∧ "inputs_to_quote inputs is not on a revoked PCK"
      → verify(vkey, proof, inputs) = true

  Completeness is conditional in the same way as
  `tdxVerifier.complete` was — fresh collateral / non-revocation
  preconditions apply to the in-quote PCK chain.

  **Why these are not `theorem`s here**: as in Steps 2-4, the
  abstract carriers (`Groth16Proof`, `PublicInputs`, `VKey`)
  are not `Fintype`. Without finiteness, `Pr[...]` cannot be
  instantiated. Demoting to `theorem`s requires either
  refinement of those carriers or a parametric statement
  `[Fintype VKey] [Fintype Groth16Proof] [Fintype PublicInputs]
   -> negligible ...`.

  Additionally, the soundness reduction needs an underlying
  BN254 knowledge-soundness assumption that is not itself
  modelled in this module — ArkLib provides a partial
  framework for SNARK security games but does not yet cover
  Groth16 specifically (only Pinocchio-style PCPs / IOPs).
  And the circuit-equivalence claim needs a reference DCAP
  verifier formalised in Lean (analogous to ArkLib's
  formal-verification approach for primitives, but for the
  full DCAP-quote-v4 wire-format protocol). Neither is in
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
                            + Pr[ groth16_forgery ]
                              where groth16_forgery itself is
                              negligible_groth16 + negligible_circuit

  Each summand is supplied by one companion module. This is the
  **quadruple-bundle union bound** that `cross_component_session_bind`
  will become after the Step 6 demotion. The `groth16_forgery`
  summand itself further decomposes into two summands, reflecting
  the doubled-negligibility nature of the zkdcap soundness
  assumption.
-/

end Specs.Quartz.Attestation.ZkdcapVCVio
