/-
  Trust boundary: zkdcap Groth16 verifier soundness — VCV-io substrate.

  Quartz's `DstackZkAttestation` flow (in
  `crates/contracts/core/src/handler/execute/attested.rs`) does not
  verify the TDX quote on-chain directly. Instead, an off-chain prover
  (the gnark-based zkdcap circuit) produces a Groth16 proof that
  *some* TDX quote with the claimed user-data and MR_ENCLAVE verifies
  under DCAP. The Xion ZK module (`/xion.zk.v1.Query/ProofVerifyGnark`)
  checks the proof.

  Here we bridge from Groth16 acceptance back to the underlying
  `was_signed_by_dstack` predicate from `Dstack.lean`. This is the
  soundness assumption of the zkdcap circuit composed with Groth16
  knowledge soundness.

  --------------------------------------------------------------------
  Historical context: this module previously held **7** axioms.
  --------------------------------------------------------------------

  Refactor (VCV-io migration, 2026-05-13, Step 5):

  * `Groth16Proof`, `PublicInputs`, `VKey` remain as opaque carrier
    axioms. They are externally-supplied wire-format types (BN254
    proof bytes; concatenated 32-byte `fr.Element` public-input
    values; gnark verification-key bytes identified on-chain by
    `vkey_name`). Discharging them requires a concrete byte-level
    model of gnark's wire format — out of scope for this step.
  * `verifyGroth16`, `inputs_to_quote`, `verifyGroth16_sound`, AND
    the named-constant `zkdcapVKey` are **bundled** into a single
    trust-boundary record axiom `groth16Verifier : Groth16Verifier`.
    The four public names are preserved as `noncomputable def` /
    `theorem` projections, so downstream files
    (`Protocol/Handshake.lean`, etc.) re-build unchanged.

    Bundling rationale: the four together encode "there is a gnark
    verifier with a canonical verification key, it has an input-to-
    quote semantic mapping, and it is sound (a verified proof entails
    that the underlying TDX quote was signed by dstack)". Packaging
    them into one record axiom is the analog of Step 4's `TdxVerifier`
    pattern, extended to also fold in the canonical-vkey witness
    (which cannot be demoted to a `def` because `VKey` is fully
    abstract — there is no constructive way to produce a `VKey`
    inhabitant in Lean without another axiom).

  Net effect on Quartz's verified surface: **7 axioms → 4 axioms**.

  --------------------------------------------------------------------
  HONESTY-LENS FINDING (load-bearing — do not paper over):
  --------------------------------------------------------------------

  The bundled `groth16Verifier : Groth16Verifier` record axiom
  contains ONE classical-`Prop` verification implication that is
  **honest under named computational assumptions but classically
  over-strong as stated**:

    `groth16Verifier.sound :
       verify vkey proof inputs = true →
       was_signed_by_dstack (inputsToQuote inputs)`

  Truthful under TWO composed computational assumptions:

    1. **Groth16 knowledge soundness over BN254** (with KZG / Pinocchio-
       style argument). A Groth16 proof that verifies under a trusted
       key was produced by a prover that knew a satisfying witness —
       *except with negligible probability of forgery* over the
       discrete-log / power-knowledge / generic-group-model bound.

    2. **Circuit-equivalence between zkdcap's R1CS encoding and a
       reference DCAP verifier**. The zkdcap circuit faithfully
       encodes (a) Intel SGX PCK chain validation up to the
       hard-coded Root CA, (b) the DCAP quote-v4 signature check,
       and (c) the binding of the in-quote `report_data` / `mr_td`
       fields to the public inputs. This is itself a circuit-
       verification claim against a Rust reference implementation
       of DCAP — neither end is currently formally verified.

  The *classical-Prop* form drops the negligibility qualifier from
  (1) AND the circuit-correctness qualifier from (2), making the
  axiom vacuously stronger than what gnark + zkdcap actually
  guarantees. An adversary with sufficient computational power
  could in principle forge a Groth16 proof that passes `verify`
  for a `(proof, inputs)` pair whose `inputs_to_quote` mapping
  does not satisfy `was_signed_by_dstack`; both halves of the
  composition are computational, not absolute.

  This implication is in the **(d) classical-Prop verification
  implication that hides a probabilistic gap** bucket. It is the
  *same sub-shape* as Step 4's `tdxVerifier.sound`: classical-Prop
  drops a knowledge-soundness / circuit-equivalence negligibility
  qualifier. (Unlike Steps 2–3's *mathematically impossible*
  sub-shape, this is *operationally over-strong*: true under the
  composition of two named cryptographic assumptions.)

  The TRUTHFUL VCV-io statement models `verifyGroth16` as a
  verification *oracle* against `OracleSpec`:

      groth16Verifier_soundness_negl (𝒜 : Adversary) :
        Pr[ verify vkey proof inputs = true ∧
            ¬ was_signed_by_dstack (inputsToQuote inputs)
          | (proof, inputs) ← 𝒜.run(security_parameter) ]
        ≤ negligible_groth16 + negligible_circuit

  where:
    * `negligible_groth16` is the BN254 knowledge-soundness bound
      (concretely ~2^{-100} for 254-bit BN curves, asymptotic over
      the security parameter).
    * `negligible_circuit` is the bound for circuit-vs-reference
      DCAP-verifier equivalence (a separate computational claim
      that requires its own formal-verification effort).

  The companion module `ZkdcapVCVio.lean` sketches the `OracleSpec`
  + `OracleComp` shape for this lift. It is documentary at Step 5
  and becomes load-bearing at Step 6 (protocol-layer OracleComp
  lift).

  **Downstream theorems carrying Zkdcap-axiom closure** (verified
  via `lean_verify` post-migration; each rides on at least one of
  `{groth16Verifier}` plus the carrier triple):

    1. `Specs.Quartz.Attestation.Zkdcap.verifyGroth16_yields_decoded`
       (this module — the 1 theorem ledgered for this module)
    2. `Specs.Quartz.Protocol.Handshake.handshake_sound`
    3. `Specs.Quartz.Protocol.Handshake.handshake_binds_ecies_key`
    4. `Specs.Quartz.Protocol.Confidentiality.session_confidentiality`
    5. `Specs.Quartz.Protocol.Confidentiality.session_confidentiality_via_extractor`
    6. `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
    7. `Specs.Quartz.Protocol.Conservation.cross_component_transfers_conservation`
    8. `Specs.Quartz.Protocol.AuctionDeterminism.cross_component_auction_winner_determinism`

  Theorem 6 (`cross_component_session_bind`) rides on FOUR bundled
  (d)-bucket axioms simultaneously after Step 5:
  `{tdxVerifier, commitHashE, commitHashBytesE, groth16Verifier}`
  — a **quadruple-bundle composition** (previously triple-bundle
  through Step 4; this step adds the fourth). When Step 6 demotes
  all four bundles to their truthful negligibility / oracle-handler
  shapes, this theorem's bound will be a **quadruple union bound**:

      Pr[ cross_component_session_bind fails ]
        ≤ Pr[ commitHashE collision ]            -- structured commit
        + Pr[ commitHashBytesE collision ]       -- byte-level commit
        + Pr[ tdxVerifier forgery ]              -- TDX DCAP forgery
        + Pr[ groth16Verifier forgery ]          -- zkdcap Groth16 forgery

  each summand supplied by one companion module
  (`UserDataCommitVCVio`, `RawMessagesVCVio`, `DstackVCVio`,
  `ZkdcapVCVio`).

  Same demotion-blocking rationale as Steps 2–4: downstream
  consumers ride on deterministic implication, not on probability
  bounds. Migrating them requires lifting the protocol-layer
  theorems into `OracleComp` with a soundness-error budget. That
  is Step 6+ scope, not Step 5.
-/

-- NOTE: This module is intentionally kept free of `VCVio` imports.
-- Downstream files rely on instance synthesis that VCVio's
-- transitive closure slows past the default heartbeat budget.
-- The VCV-io integration (verification-oracle model + soundness-
-- negligibility-bound sketch) lives in the sibling module
-- `Specs/Quartz/Attestation/ZkdcapVCVio.lean`, imported only where
-- probabilistic refinements are needed.

import Specs.Quartz.Attestation.Dstack

namespace Specs.Quartz.Attestation.Zkdcap

open Specs.Quartz.Attestation.Dstack

/-- A Groth16 proof over BN254 (gnark-native encoding).

    **Cycle 6.21 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8`. The gnark-native BN254 Groth16 proof serialisation
    is fixed-length (192 bytes for a 3-element G1×G2 proof structure)
    but we model it as variable-length here to avoid pinning the
    Lean spec to a specific serialisation convention; future cycles
    can tighten to `Vector UInt8 192` if the wire format stabilises. -/
abbrev Groth16Proof : Type := List UInt8

/-- The public inputs to the zkdcap circuit: concatenated 32-byte
    big-endian `fr.Element` values. Corresponds to the `public_inputs`
    field of `QueryVerifyGnarkRequest` in `attested.rs`.

    **Cycle 6.21 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8` (the concatenated fr.Element bytes). The number of
    field elements depends on the specific zkdcap circuit; modelling
    as a flat byte sequence avoids pinning that count at the spec
    layer. -/
abbrev PublicInputs : Type := List UInt8

/-- A Groth16 verification key, identified on-chain by `vkey_name`
    (and optionally `vkey_id`) in `QueryVerifyGnarkRequest`.

    **Cycle 6.21 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8`. The gnark-native vkey serialisation length depends
    on the circuit (number of public inputs); modelling as
    variable-length leaves room for circuit refactors without
    breaking the spec. -/
abbrev VKey : Type := List UInt8

/-- **Bundled trust-boundary record**: the zkdcap Groth16 verifier
    packaged with its canonical verification key, its
    inputs-to-quote semantic mapping, and its (classical-Prop)
    soundness claim.

    Bundling rationale: prior to Step 5 of the VCV-io refactor the
    verifier function, the canonical vkey, the inputs-to-quote map,
    and the soundness claim were FOUR independent axioms. Bundling
    them into a single record axiom (`groth16Verifier`) packages
    "there is a verifier with a canonical vkey, it has a
    well-defined input-to-quote semantics, and it is sound" into
    one trust-boundary commitment. The four public names
    (`verifyGroth16`, `zkdcapVKey`, `inputs_to_quote`,
    `verifyGroth16_sound`) are recovered as projections so
    downstream files re-build unchanged.

    Note: `zkdcapVKey` is folded into this record (rather than being
    demoted to a `def`) because `VKey` is a fully abstract carrier
    axiom — there is no constructive way to produce a `VKey`
    inhabitant in Lean without introducing a separate `[Inhabited
    VKey]` axiom. Folding it into the record axiom keeps the trust
    surface to a single named record while preserving the
    abstractness of `VKey`.

    **Honesty caveat** (see file header): the `sound` field is a
    classical-Prop statement that drops both (a) the Groth16
    knowledge-soundness negligibility qualifier and (b) the
    circuit-vs-reference-DCAP-verifier correctness qualifier. The
    truthful `OracleComp` formulation is sketched in
    `ZkdcapVCVio.lean`. -/
structure Groth16Verifier where
  /-- The canonical verification key registered for zkdcap on the
      target chain. The on-chain config carries the *name*
      (`Config::zkdcap_vkey`); this field models the resolved key
      itself. -/
  vkey : VKey
  /-- Operational mirror of the Xion ZK module's gnark verifier.

      Returns `true` iff the proof is accepted by the on-chain
      `/xion.zk.v1.Query/ProofVerifyGnark` endpoint under the given
      verification key. -/
  verify : VKey → Groth16Proof → PublicInputs → Bool
  /-- The zkdcap circuit binds its public inputs to a TDX quote.
      This field encodes the *circuit-level* semantic mapping: given
      a set of public inputs, there is an associated quote whose
      user-data / MR_ENCLAVE are determined by the inputs.

      At this layer we keep the mapping abstract — the relevant
      consequence (`sound`, below) is what protocol proofs consume. -/
  inputsToQuote : PublicInputs → TdxQuote
  /-- **Soundness** (trust-boundary field): if the on-chain ZK module
      accepts a zkdcap proof under the canonical verification key,
      then the associated TDX quote was genuinely signed by dstack.

      Composes two computational trust assumptions:
      1. Groth16 knowledge soundness (BN254).
      2. The zkdcap circuit faithfully encodes DCAP quote verification.

      **Honesty caveat** (carries over from the structure docstring):
      this is a classical-Prop implication. Both composed assumptions
      are *computational*; the truthful negligibility-bound
      formulation is in `ZkdcapVCVio.lean`. -/
  sound (proof : Groth16Proof) (inputs : PublicInputs) :
    verify vkey proof inputs = true →
    was_signed_by_dstack (inputsToQuote inputs)

/-- **Bundled trust-boundary axiom**: the canonical zkdcap Groth16
    verifier exists.

    Replaces the previous quartet (`verifyGroth16` axiom +
    `zkdcapVKey` axiom + `inputs_to_quote` axiom +
    `verifyGroth16_sound` axiom) with a single bundled record
    axiom. The four public names are recovered as projections
    immediately below.

    **Honesty caveat** carries over from the `Groth16Verifier`
    structure docstring — the bundled record's `sound` field is
    a classical-Prop implication that hides a doubled
    computational-soundness gap; the truthful formulation lives
    in `ZkdcapVCVio.lean`. -/
axiom groth16Verifier : Groth16Verifier

/-- The verification key registered for zkdcap on the target chain.
    The on-chain config carries the *name* (`Config::zkdcap_vkey`);
    this definition projects the resolved key from `groth16Verifier`.

    Previously an axiom; now a derived definition. Marked
    `noncomputable` because `groth16Verifier` is an axiom. -/
noncomputable def zkdcapVKey : VKey :=
  groth16Verifier.vkey

/-- Operational mirror of the Xion ZK module's gnark verifier.

    Returns `true` iff the proof is accepted by the on-chain
    `/xion.zk.v1.Query/ProofVerifyGnark` endpoint under the given
    verification key.

    Previously an axiom; now a derived definition. -/
noncomputable def verifyGroth16 : VKey → Groth16Proof → PublicInputs → Bool :=
  groth16Verifier.verify

/-- The zkdcap circuit binds its public inputs to a TDX quote.
    Previously an axiom; now a derived definition. -/
noncomputable def inputs_to_quote : PublicInputs → TdxQuote :=
  groth16Verifier.inputsToQuote

/-- **Theorem (formerly an axiom): Soundness** of zkdcap Groth16
    verification under the canonical vkey — if the on-chain ZK
    module accepts a zkdcap proof, then the associated TDX quote
    was genuinely signed by dstack.

    Previously an independent axiom; now derived as a projection
    of the bundled `groth16Verifier` record (with `zkdcapVKey`
    unfolded to expose the canonical-vkey instantiation).

    **Honesty caveat** (carries over from `groth16Verifier`): this
    is a classical-Prop implication. Both composed assumptions
    (Groth16 knowledge-soundness over BN254, and zkdcap circuit
    correctness against a reference DCAP verifier) are
    computational, not absolute. Downstream consumers should
    eventually migrate to the `groth16Verifier_soundness_negl`
    shape sketched in `ZkdcapVCVio.lean`. -/
theorem verifyGroth16_sound (proof : Groth16Proof) (inputs : PublicInputs) :
    verifyGroth16 zkdcapVKey proof inputs = true →
    was_signed_by_dstack (inputs_to_quote inputs) :=
  groth16Verifier.sound proof inputs

/-- **Derived corollary**: a verified zkdcap proof yields a quote
    whose DCAP fields can be projected.

    This is the bridge theorem that protocol-layer reasoning (e.g.
    `DstackZkAttestation` handler soundness) will consume: ZK
    acceptance entails the existence of decodable DCAP evidence. -/
theorem verifyGroth16_yields_decoded
    (n : Nat) (proof : Groth16Proof) (inputs : PublicInputs)
    (h : verifyGroth16 zkdcapVKey proof inputs = true) :
    ∃ mr ud, verifyTdxQuote n (inputs_to_quote inputs) = some (mr, ud) :=
  verifyTdxQuote_complete n _ (verifyGroth16_sound proof inputs h)

end Specs.Quartz.Attestation.Zkdcap
