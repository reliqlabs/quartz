/-
  Trust boundary: zkdcap zero-knowledge verifier soundness — VCV-io substrate.

  Quartz's `DstackZkAttestation` flow (in
  `crates/contracts/core/src/handler/execute/attested.rs`) does not
  verify the TDX quote on-chain directly. Instead, an off-chain prover
  (the zkdcap circuit) produces a zero-knowledge proof that *some* TDX
  quote with the claimed user-data and MR_ENCLAVE verifies under the
  implemented DCAP relation. The supplier artifact is a monolithic Noir
  circuit proven with Barretenberg UltraHonk, checked on-chain by the
  Xion ZK module endpoint `/xion.zk.v1.Query/ProofVerifyUltraHonk`,
  under scope id `zkdcap-tdx-v4-tdreport10-21`. The previously named
  `dcap-ultrahonk-v1` registration is legacy: upstream forbids reusing
  that name or id, and no production key is registrable yet, so this
  module deliberately names no live key. See
  `.colosseum/boundaries/zkdcap--quartz.md` section 4.

  Here we bridge from proof acceptance back to the underlying
  `was_signed_by_dstack` predicate from `Dstack.lean`. This is the
  soundness assumption of the zkdcap circuit composed with the proof
  system's knowledge soundness.

  --------------------------------------------------------------------
  Proof-system neutrality (boundary v1.1.0, "proof-system-neutral
  verifier interface"; formerly cited as obligation O6):
  --------------------------------------------------------------------

  The verifier is modelled by a **proof-system-neutral** interface
  `ZkVerifier`. The structure names no concrete proving system; its
  live instantiation `zkVerifier` (aliased `ultraHonkVerifier`) is
  Noir/Barretenberg UltraHonk and maps to boundary assumption
  **K1 (UltraHonk soundness)**: the release-pinned Barretenberg
  verifier accepts only proofs of the compiled Noir relation. K1 and
  this requirement were carried over from the upstream boundary document
  that zkdcap deleted on 2026-08-06; both are now defined in
  `.colosseum/boundaries/zkdcap--quartz.md` section 8, which also
  records why these are cited by NAME: the upstream O-numbering is not
  stable across lineages, and "O6" means something else in the last
  upstream version of that document.

  The former gnark/Groth16/BN254 path is historical only — not a
  fallback, parity target, or inherited assumption. The historical
  names (`Groth16Verifier`, `groth16Verifier`, `verifyGroth16`,
  `Groth16Proof`, `verifyGroth16_sound`) are retained as thin
  `abbrev`/`theorem` aliases so downstream modules keep resolving; new
  reasoning should prefer the neutral names.

  --------------------------------------------------------------------
  Historical context: this module previously held **7** axioms.
  --------------------------------------------------------------------

  * `ZkProof` (`Groth16Proof` alias), `PublicInputs`, `VKey` remain as
    opaque carrier abbrevs over `List UInt8`. They are
    externally-supplied wire-format types (proof bytes; the 21-field
    v1 journal / public inputs; verification-key bytes identified
    on-chain by `vkey_name`). Discharging them requires a concrete
    byte-level model of the UltraHonk wire format — out of scope here.
  * `verifyZk`, `inputs_to_quote`, `verifyZk_sound`, AND the
    named-constant `zkdcapVKey` are **bundled** into a single
    trust-boundary record axiom `zkVerifier : ZkVerifier`. The public
    names are preserved as `noncomputable def` / `theorem` projections
    (with historical aliases), so downstream files
    (`Protocol/Handshake.lean`, etc.) re-build unchanged.

    Bundling rationale: the four together encode "there is a ZK
    verifier with a canonical verification key, it has an input-to-
    quote semantic mapping, and it is sound (a verified proof entails
    that the underlying TDX quote was signed by dstack)". Packaging
    them into one record axiom is the analog of Step 4's `TdxVerifier`
    pattern, extended to also fold in the canonical-vkey witness
    (which cannot be demoted to a `def` because `VKey` carries no
    constructive inhabitant in Lean without another axiom).

  Net effect on Quartz's verified surface: **7 axioms → 4 axioms**
  (the single record axiom is now `zkVerifier`).

  --------------------------------------------------------------------
  HONESTY-LENS FINDING (load-bearing — do not paper over):
  --------------------------------------------------------------------

  The bundled `zkVerifier : ZkVerifier` record axiom contains ONE
  classical-`Prop` verification implication that is **honest under
  named computational assumptions but classically over-strong as
  stated**:

    `zkVerifier.sound :
       verify vkey proof inputs = true →
       was_signed_by_dstack (inputsToQuote inputs)`

  Truthful under TWO composed computational assumptions:

    1. **UltraHonk knowledge soundness** (boundary K1). A proof that
       verifies under a trusted key was produced by a prover that knew
       a satisfying witness for the compiled Noir relation — *except
       with negligible probability of forgery* over the underlying
       argument's soundness bound.

    2. **Circuit-equivalence to the exact versioned relation R_v1**.
       The zkdcap circuit faithfully encodes the implemented relation
       described in zkdcap intent v0.3.0 §1.2: implemented PCK-chain
       and collateral signatures, quote/QE signatures and bindings,
       selected PCK-CRL and TCB/QE comparisons, an intersected
       validity range, measurements, report data, status, certificate
       serial/FMSPC, and separate TCB Info / QE Identity evaluation
       numbers. This is equivalence to **R_v1 only** — NOT to the full
       Intel-QVL relation `R_target` (equivalence to `R_target` is
       known false; see the boundary doc).

  The *classical-Prop* form drops the negligibility qualifier from (1)
  AND the circuit-correctness qualifier from (2), making the axiom
  vacuously stronger than what UltraHonk + zkdcap actually guarantees.
  An adversary with sufficient computational power could in principle
  forge a proof that passes `verify` for a `(proof, inputs)` pair whose
  `inputs_to_quote` mapping does not satisfy `was_signed_by_dstack`;
  both halves of the composition are computational, not absolute.

  This implication is in the **(d) classical-Prop verification
  implication that hides a probabilistic gap** bucket. It is the
  *same sub-shape* as Step 4's `tdxVerifier.sound`: classical-Prop
  drops a knowledge-soundness / circuit-equivalence negligibility
  qualifier.

  The TRUTHFUL VCV-io statement models `verifyZk` as a verification
  *oracle* against `OracleSpec`:

      zkVerifier_soundness_negl (𝒜 : Adversary) :
        Pr[ verify vkey proof inputs = true ∧
            ¬ was_signed_by_dstack (inputsToQuote inputs)
          | (proof, inputs) ← 𝒜.run(security_parameter) ]
        ≤ negligible_ultrahonk + negligible_circuit

  where:
    * `negligible_ultrahonk` is the UltraHonk knowledge-soundness
      bound (asymptotic over the security parameter).
    * `negligible_circuit` is the bound for circuit-vs-R_v1
      equivalence (a separate computational claim that requires its
      own formal-verification effort).

  The companion module `ZkdcapVCVio.lean` sketches the `OracleSpec`
  + `OracleComp` shape for this lift.

  **Downstream theorems carrying Zkdcap-axiom closure** (each rides on
  the `zkVerifier` record axiom plus the carrier triple):

    1. `Specs.Quartz.Attestation.Zkdcap.verifyGroth16_yields_decoded`
    2. `Specs.Quartz.Protocol.Handshake.handshake_sound`
    3. `Specs.Quartz.Protocol.Handshake.handshake_binds_ecies_key`
    4. `Specs.Quartz.Protocol.Confidentiality.session_confidentiality`
    5. `Specs.Quartz.Protocol.Confidentiality.session_confidentiality_via_extractor`
    6. `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
    7. `Specs.Quartz.Protocol.Conservation.cross_component_transfers_conservation`
    8. `Specs.Quartz.Protocol.AuctionDeterminism.cross_component_auction_winner_determinism`

  Theorem 6 (`cross_component_session_bind`) rides on FOUR bundled
  (d)-bucket axioms simultaneously: `{tdxVerifier, commitHashE,
  commitHashBytesE, zkVerifier}` — a **quadruple-bundle composition**.
  When the demotion to truthful negligibility / oracle-handler shapes
  lands, this theorem's bound will be a **quadruple union bound**:

      Pr[ cross_component_session_bind fails ]
        ≤ Pr[ commitHashE collision ]            -- structured commit
        + Pr[ commitHashBytesE collision ]       -- byte-level commit
        + Pr[ tdxVerifier forgery ]              -- TDX DCAP forgery
        + Pr[ zkVerifier forgery ]               -- zkdcap ZK forgery

  each summand supplied by one companion module
  (`UserDataCommitVCVio`, `RawMessagesVCVio`, `DstackVCVio`,
  `ZkdcapVCVio`). The `zkVerifier` summand itself decomposes into
  `negligible_ultrahonk + negligible_circuit` (see `ZkdcapVCVio.lean`
  and `ProtocolVCVioQuad.lean`).
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

/-- Opaque proof-carrier bytes emitted by the prover.

    The live path is a Noir/Barretenberg UltraHonk proof. The
    byte-level serialisation is fixed by the proving toolchain but is
    modelled as a variable-length `List UInt8` here to avoid pinning
    the Lean spec to a specific wire format. -/
abbrev ZkProof : Type := List UInt8

/-- Back-compat alias for the historical gnark Groth16 proof carrier.
    Retained so downstream modules keep resolving; the live carrier is
    `ZkProof` (UltraHonk). -/
abbrev Groth16Proof : Type := ZkProof

/-- The public inputs / journal to the zkdcap circuit: the current
    21-field v1 journal, modelled as a flat byte sequence. Corresponds
    to the `public_inputs` field of the on-chain verify request. -/
abbrev PublicInputs : Type := List UInt8

/-- A proof-system verification key, identified on-chain by `vkey_name`
    (and optionally `vkey_id`) in the verify request. Modelled as
    variable-length bytes; the released v1 key is 3,680 bytes. -/
abbrev VKey : Type := List UInt8

/-- **Proof-system-neutral trust-boundary record**: a zero-knowledge
    verifier packaged with its canonical verification key, its
    inputs-to-quote semantic mapping, and its (classical-Prop)
    soundness claim.

    Proof-system neutrality (obligation O6): this structure names no
    concrete proving system. The live instantiation (`zkVerifier` /
    `ultraHonkVerifier`, below) is Noir/Barretenberg UltraHonk, checked
    on-chain by `/xion.zk.v1.Query/ProofVerifyUltraHonk`. Maps to
    boundary assumption **K1 (UltraHonk soundness)**.

    Bundling rationale: prior to the VCV-io refactor the verifier
    function, the canonical vkey, the inputs-to-quote map, and the
    soundness claim were FOUR independent axioms. Bundling them into a
    single record axiom (`zkVerifier`) packages "there is a verifier
    with a canonical vkey, it has a well-defined input-to-quote
    semantics, and it is sound" into one trust-boundary commitment. The
    public names are recovered as projections so downstream files
    re-build unchanged.

    Note: `zkVerifier.vkey` is folded into this record (rather than
    being demoted to a `def`) because `VKey` carries no constructive
    inhabitant in Lean without a separate `[Inhabited VKey]` axiom.
    Folding it in keeps the trust surface to a single named record.

    **Honesty caveat** (see file header): the `sound` field is a
    classical-Prop statement that drops both (a) the UltraHonk
    knowledge-soundness negligibility qualifier and (b) the
    circuit-vs-R_v1 correctness qualifier. The truthful `OracleComp`
    formulation is sketched in `ZkdcapVCVio.lean`. -/
structure ZkVerifier where
  /-- The canonical verification key registered for zkdcap on the
      target chain. The on-chain config carries the *name*
      (`Config::zkdcap_vkey`); this field models the resolved key. -/
  vkey : VKey
  /-- Operational mirror of the Xion ZK module's verifier.

      Returns `true` iff the proof is accepted by the on-chain
      `/xion.zk.v1.Query/ProofVerifyUltraHonk` endpoint under the given
      verification key. -/
  verify : VKey → ZkProof → PublicInputs → Bool
  /-- The zkdcap circuit binds its public inputs to a TDX quote. This
      field encodes the *circuit-level* semantic mapping: given a set
      of public inputs, there is an associated quote whose user-data /
      MR_ENCLAVE are determined by the inputs. Kept abstract here. -/
  inputsToQuote : PublicInputs → TdxQuote
  /-- **Soundness** (trust-boundary field): if the on-chain ZK module
      accepts a zkdcap proof under the canonical verification key, then
      the associated TDX quote was genuinely signed by dstack.

      Composes two computational trust assumptions:
      1. UltraHonk knowledge soundness (boundary K1).
      2. The zkdcap circuit faithfully encodes the exact versioned
         relation R_v1 (NOT the full Intel-QVL relation R_target).

      **Honesty caveat**: this is a classical-Prop implication. Both
      composed assumptions are *computational*; the truthful
      negligibility-bound formulation is in `ZkdcapVCVio.lean`. -/
  sound (proof : ZkProof) (inputs : PublicInputs) :
    verify vkey proof inputs = true →
    was_signed_by_dstack (inputsToQuote inputs)

/-- Back-compat alias for the historical `Groth16Verifier` record
    structure. The neutral name is `ZkVerifier`. -/
abbrev Groth16Verifier : Type := ZkVerifier

/-- **Bundled trust-boundary axiom**: the canonical zkdcap
    zero-knowledge verifier exists.

    Replaces the previous quartet (`verify` axiom + canonical-vkey
    axiom + inputs-to-quote axiom + soundness axiom) with a single
    bundled record axiom. The public names are recovered as projections
    immediately below.

    **Live instantiation**: Noir/Barretenberg UltraHonk (`dcap-
    ultrahonk-v1`), aliased `ultraHonkVerifier`. Maps to boundary K1.

    **Honesty caveat** carries over from the `ZkVerifier` structure
    docstring — the bundled record's `sound` field is a classical-Prop
    implication that hides a doubled computational-soundness gap; the
    truthful formulation lives in `ZkdcapVCVio.lean`. -/
axiom zkVerifier : ZkVerifier

/-- The live UltraHonk instantiation of the neutral verifier interface
    (boundary assumption K1). A transparent alias of `zkVerifier`;
    named to make the live proof system explicit at the trust
    boundary. -/
noncomputable abbrev ultraHonkVerifier : ZkVerifier := zkVerifier

/-- Back-compat alias for the historical `groth16Verifier` axiom name.
    The gnark path is historical only; the live path is
    `ultraHonkVerifier`. -/
noncomputable abbrev groth16Verifier : ZkVerifier := zkVerifier

/-- The verification key registered for zkdcap on the target chain.
    The on-chain config carries the *name* (`Config::zkdcap_vkey`);
    this definition projects the resolved key from `zkVerifier`.

    Marked `noncomputable` because `zkVerifier` is an axiom. -/
noncomputable def zkdcapVKey : VKey :=
  zkVerifier.vkey

/-- Operational mirror of the Xion ZK module's verifier.

    Returns `true` iff the proof is accepted by the on-chain
    `/xion.zk.v1.Query/ProofVerifyUltraHonk` endpoint under the given
    verification key. -/
noncomputable def verifyZk : VKey → ZkProof → PublicInputs → Bool :=
  zkVerifier.verify

/-- Back-compat alias for the historical `verifyGroth16` name. The
    neutral name is `verifyZk`. -/
noncomputable abbrev verifyGroth16 : VKey → ZkProof → PublicInputs → Bool :=
  verifyZk

/-- The zkdcap circuit binds its public inputs to a TDX quote.
    Projection of the bundled `zkVerifier` record. -/
noncomputable def inputs_to_quote : PublicInputs → TdxQuote :=
  zkVerifier.inputsToQuote

/-- **Soundness** (proof-system-neutral) of zkdcap verification under
    the canonical vkey — if the on-chain ZK module accepts a zkdcap
    proof, then the associated TDX quote was genuinely signed by
    dstack.

    Derived as a projection of the bundled `zkVerifier` record (with
    `zkdcapVKey` unfolded to expose the canonical-vkey instantiation).

    **Honesty caveat** (carries over from `zkVerifier`): this is a
    classical-Prop implication. Both composed assumptions (UltraHonk
    knowledge-soundness, K1, and zkdcap circuit correctness against the
    exact relation R_v1) are computational, not absolute. Downstream
    consumers should eventually migrate to the
    `zkVerifier_soundness_negl` shape sketched in `ZkdcapVCVio.lean`. -/
theorem verifyZk_sound (proof : ZkProof) (inputs : PublicInputs) :
    verifyZk zkdcapVKey proof inputs = true →
    was_signed_by_dstack (inputs_to_quote inputs) :=
  zkVerifier.sound proof inputs

/-- Back-compat alias for the historical `verifyGroth16_sound`. The
    neutral name is `verifyZk_sound`. -/
theorem verifyGroth16_sound (proof : Groth16Proof) (inputs : PublicInputs) :
    verifyGroth16 zkdcapVKey proof inputs = true →
    was_signed_by_dstack (inputs_to_quote inputs) :=
  verifyZk_sound proof inputs

/-- **Derived corollary**: a verified zkdcap proof yields a quote
    whose DCAP fields can be projected.

    This is the bridge theorem that protocol-layer reasoning (e.g.
    `DstackZkAttestation` handler soundness) will consume: ZK
    acceptance entails the existence of decodable DCAP evidence.

    Takes `(tdxVerifier n).freshAtTime t` and
    `(tdxVerifier n).signedRecently (inputs_to_quote inputs)` as
    preconditions so the contract-side block-time discharge is
    visible. -/
theorem verifyGroth16_yields_decoded
    (n : Nat) (proof : ZkProof) (inputs : PublicInputs)
    (h : verifyZk zkdcapVKey proof inputs = true)
    (t : Time)
    (h_fresh_at : (tdxVerifier n).freshAtTime t)
    (h_recently : (tdxVerifier n).signedRecently (inputs_to_quote inputs)) :
    ∃ mr ud, verifyTdxQuote n (inputs_to_quote inputs) = some (mr, ud) :=
  verifyTdxQuote_complete n _ t h_fresh_at h_recently
    (verifyZk_sound proof inputs h)

end Specs.Quartz.Attestation.Zkdcap
