/-
  Trust boundary: dstack TDX quote attestation soundness — VCV-io substrate.

  Quartz uses Intel TDX quotes produced by the dstack CVM (see
  `crates/enclave/core/src/attestor.rs`). On-chain, these quotes are
  consumed either directly (`DstackAttestation`) or via a Groth16
  proof of correct DCAP verification (`DstackZkAttestation`, handled
  in `crates/contracts/core/src/handler/execute/attested.rs`).

  We axiomatize the soundness of TDX quote verification: a quote
  verifier returning `some (mr, user_data)` constitutes evidence
  that dstack actually produced the quote, binding the supplied
  measurement and user data.

  --------------------------------------------------------------------
  Historical context: this module previously held **8** axioms.
  --------------------------------------------------------------------

  Refactor (VCV-io migration, 2026-05-13, Step 4):

  * `TdxQuote`, `MrEnclave`, `UserData` remain as opaque carrier
    axioms. They are externally-supplied wire-format types
    (DCAP-quote-v4 byte blob, MRTD/RTMR digest, 64-byte report_data
    field). Discharging them requires a concrete byte-level model
    out of scope for this step.
  * `was_signed_by_dstack` remains as the propositional witness for
    off-chain reality (a genuine dstack TEE produced the quote with
    valid Intel PCK signatures up to the SGX Root CA). This is the
    analog of `Axioms.Crypto.was_signed_by` from verified-cosmwasm
    — a witness no Lean proof can construct, only consume. Honest
    computational assumption.
  * `RtmrLog : Type` is **removed** as a dead axiom — no
    declaration or theorem anywhere in the Quartz Lean tree
    references it. Inventoried during Step 4 axiom scan and
    confirmed via `lean_verify` / global `RtmrLog` reference scan.
  * `verifyTdxQuote`, `verifyTdxQuote_sound`, `verifyTdxQuote_complete`
    are **bundled** into a single trust-boundary record axiom
    `tdxVerifier : TdxVerifier`. The verifier function, its
    soundness, and its completeness become *fields* of one record
    rather than three independent axioms. The three public names
    are preserved as `noncomputable def` / `theorem` projections,
    so downstream files (`Zkdcap.lean`, `Protocol/CrossComponent.lean`,
    `Protocol/Handshake.lean`, `Protocol/Confidentiality.lean`,
    `Protocol/Conservation.lean`, `Protocol/AuctionDeterminism.lean`)
    re-build unchanged.

  Net effect on Quartz's verified surface: **8 axioms → 5 axioms**.

  --------------------------------------------------------------------
  HONESTY-LENS FINDING (load-bearing — do not paper over):
  --------------------------------------------------------------------

  The bundled `tdxVerifier : TdxVerifier` record axiom contains TWO
  classical-`Prop` verification implications that are **honest under
  a named computational assumption but classically over-strong as
  stated**:

    1. `tdxVerifier.sound : verifyTdxQuote q = some (mr, ud) →
                            was_signed_by_dstack q`
       Truthful under the DCAP-soundness assumption: a quote that
       passes the on-chain DCAP verifier was (with negligible
       probability of forgery) produced by a genuine TEE. The
       *classical-Prop* form drops the "negligible probability of
       forgery" qualifier, making it vacuously stronger than the
       cryptographic reality.

    2. `tdxVerifier.complete : was_signed_by_dstack q →
                               ∃ mr ud, verifyTdxQuote q = some (mr, ud)`
       Truthful under the DCAP-completeness assumption: a genuine
       dstack quote with current Intel collateral decodes to its
       measurement and user-data. The *classical-Prop* form drops
       the freshness / collateral-validity / non-revocation
       preconditions, making it again vacuously stronger.

  Both implications are in the **(d) classical-Prop verification
  implication that hides a probabilistic / preconditional gap**
  bucket. The TRUTHFUL VCV-io statements model `verifyTdxQuote` as
  a verification *oracle* against `OracleSpec`:

      tdxVerifier_soundness_negl (𝒜 : Adversary) :
        Pr[was_signed_by_dstack q = false ∧ verifyTdxQuote q = some _
           | (q, _) ← 𝒜.run]
        ≤ negligible(security_parameter)

      tdxVerifier_completeness_negl (q : TdxQuote)
          (h_sig : was_signed_by_dstack q)
          (h_fresh : freshCollateral q)
          (h_unrev : ¬revoked q) :
        ∃ mr ud, verifyTdxQuote q = some (mr, ud)

  The companion module `DstackVCVio.lean` sketches the `OracleSpec`
  + `OracleComp` shape for this lift. It is documentary at Step 4
  and becomes load-bearing at Step 6 (protocol-layer OracleComp
  lift).

  **Downstream theorems carrying Dstack-axiom closure** (verified
  via `lean_verify` post-migration; each rides on at least one of
  `{tdxVerifier, was_signed_by_dstack}` plus the carrier triple):

    1. `Specs.Quartz.Attestation.Dstack.projections_some_of_verify`
       (this module)
    2. `Specs.Quartz.Attestation.Zkdcap.verifyGroth16_yields_decoded`
    3. `Specs.Quartz.Protocol.Handshake.handshake_sound`
    4. `Specs.Quartz.Protocol.Handshake.handshake_binds_ecies_key`
    5. `Specs.Quartz.Protocol.Confidentiality.session_confidentiality`
    6. `Specs.Quartz.Protocol.Confidentiality.session_confidentiality_via_extractor`
    7. `Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind`
    8. `Specs.Quartz.Protocol.Conservation.cross_component_transfers_conservation`
    9. `Specs.Quartz.Protocol.AuctionDeterminism.cross_component_auction_winner_determinism`

  Of these:

  * Theorems 2 and 7 ride on BOTH the bundled `tdxVerifier`
    (Step 4 finding) AND the bundled `commitHashE` / `commitHashBytesE`
    (Step 2 / Step 3 findings) — these are the **multi-impossibility
    composition theorems** flagged in Step 3's change record.
  * Step 3's prediction that "Step 4 will surface analogous shape
    for `verifyTdxQuote_sound`" is **confirmed** by this finding.

  Same demotion-blocking rationale as Steps 2 and 3 applies:
  downstream consumers ride on deterministic implication, not on
  probability bounds. Migrating them requires lifting the
  protocol-layer theorems into `OracleComp` with a soundness-error
  budget. That is Step 6+ scope, not Step 4.
-/

-- NOTE: This module is intentionally kept free of `VCVio` imports.
-- Downstream files rely on instance synthesis that VCVio's
-- transitive closure slows past the default heartbeat budget.
-- The VCV-io integration (verification-oracle model + soundness/
-- completeness negligibility-bound sketch) lives in the sibling
-- module `Specs/Quartz/Attestation/DstackVCVio.lean`, imported only
-- where probabilistic refinements are needed.

namespace Specs.Quartz.Attestation.Dstack

/-- An abstract TDX quote. In wire format this is the
    DCAP-quote-v4 byte blob produced by dstack.

    **Cycle 6.21 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8` (variable-length byte sequence). Typical DCAP
    quote v4 blobs are ~5000 bytes but the exact length depends
    on the PCK certificate chain inlined in the quote. -/
abbrev TdxQuote : Type := List UInt8

/-- The measurement of the enclave image (MRTD / RTMR composition).
    Used in `state.rs::Config::mr_enclave`.

    **Cycle 6.17 (carrier refinement, 2026-05-20)**: refined from
    `axiom MrEnclave : Type` to `abbrev MrEnclave : Type := BitVec 384`.
    Intel TDX's MRTD (build-time measurement) is a 48-byte / 384-bit
    SHA-384 digest. `BitVec 384` mirrors this exactly and provides
    automatic `Fintype`/`DecidableEq`/`Inhabited` instances. -/
abbrev MrEnclave : Type := BitVec 384

/-- The 64-byte user-data field embedded in the TDX quote's
    `report_data`. Quartz binds this to a domain-separated hash
    of session/handshake state.

    **Cycle 6.18 (carrier refinement, 2026-05-20)**: refined from
    `axiom UserData : Type` to `abbrev UserData : Type := BitVec 512`.
    The DCAP quote's `report_data` is exactly 64 bytes / 512 bits;
    `BitVec 512` mirrors this exactly and provides automatic
    `Fintype`/`DecidableEq`/`Inhabited`. This is the highest-leverage
    carrier refinement in the queue because `UserData` is the
    codomain of both `commitHashE` and `commitHashBytesE`; with
    `Fintype UserData` available, the random-oracle birthday-bound
    discharge of those (d-pigeonhole-impossible) axioms becomes
    statable.

    **Cycle 6.22.d.3 (aggressive parameterisation, 2026-05-24)**:
    refined further from `BitVec 512` to `BitVec n` with `n` the
    security parameter. The production deployment instantiates at
    `n = 512` (the dstack quote's 64-byte `report_data` field); the
    cryptographic guarantees scale super-polynomially in `n` via the
    cycle-6.22.d.1 birthday bound. -/
abbrev UserData (n : Nat) : Type := BitVec n

/-- Abstract soundness predicate.

    `was_signed_by_dstack q` holds iff `q` was actually produced by
    a genuine dstack TEE running inside Intel TDX, with valid Intel
    PCK signatures up to the Intel SGX Root CA.

    This is the analog of `Axioms.Crypto.was_signed_by` from
    verified-cosmwasm — a propositional witness for off-chain reality
    that no Lean proof can construct, only consume. -/
axiom was_signed_by_dstack : TdxQuote → Prop

/-- **Bundled trust-boundary record**: the dstack TDX verifier
    packaged with its (classical-Prop) soundness and completeness
    claims.

    Bundling rationale: prior to Step 4 of the VCV-io refactor the
    verifier function and its two correctness claims were three
    independent axioms. Bundling them into a single record axiom
    (`tdxVerifier`) packages "there is a verifier" with "the
    verifier is sound" and "the verifier is complete" into one
    trust-boundary commitment. The three public names below
    (`verifyTdxQuote`, `verifyTdxQuote_sound`, `verifyTdxQuote_complete`)
    are recovered as projections so downstream files re-build
    unchanged.

    **Honesty caveat** (see file header): both `sound` and
    `complete` fields are classical-Prop statements that drop the
    "with negligible probability of forgery / under valid collateral"
    qualifiers cryptography actually provides. The truthful
    `OracleComp` formulation is sketched in `DstackVCVio.lean`. -/
structure TdxVerifier (n : Nat) where
  verify : TdxQuote → Option (MrEnclave × UserData n)
  sound (q : TdxQuote) (mr : MrEnclave) (ud : UserData n) :
    verify q = some (mr, ud) → was_signed_by_dstack q
  complete (q : TdxQuote) :
    was_signed_by_dstack q → ∃ mr ud, verify q = some (mr, ud)

/-- **Bundled trust-boundary axiom**: the canonical dstack TDX
    verifier exists.

    Replaces the previous trio (`verifyTdxQuote` axiom +
    `verifyTdxQuote_sound` axiom + `verifyTdxQuote_complete` axiom)
    with a single bundled record axiom. The three public names are
    recovered as projections immediately below.

    **Honesty caveat** carries over from the `TdxVerifier` structure
    docstring — the bundled record's `sound` / `complete` fields
    are classical-Prop implications that hide a probabilistic gap;
    the truthful formulation lives in `DstackVCVio.lean`. -/
axiom tdxVerifier (n : Nat) : TdxVerifier n

/-- Decode and verify a TDX quote.

    Operational mirror of the off-chain DCAP verification performed
    by zkdcap (and, eventually, the on-chain DCAP verifier hinted at
    in `attested.rs`).

    Returns `some (mr, user_data)` only on full success; `none` on
    any failure (malformed quote, expired collateral, bad signature,
    revoked PCK, etc.).

    Previously an axiom; now a derived definition. Marked
    `noncomputable` because `tdxVerifier` is an axiom. -/
noncomputable def verifyTdxQuote (n : Nat) (q : TdxQuote) :
    Option (MrEnclave × UserData n) :=
  (tdxVerifier n).verify q

/-- **Theorem (formerly an axiom): Soundness** of TDX quote
    verification — a quote that verifies must have been signed by
    dstack.

    Previously an independent axiom; now derived as a projection
    of the bundled `tdxVerifier` record.

    This is the analog of `Axioms.Crypto.secp256k1_verify_sound`.

    **Honesty caveat** (carries over from `tdxVerifier`): this is
    a classical-Prop implication. The cryptographic reality is
    that DCAP verification is *computationally* sound (forgery
    has negligible probability), not absolutely sound. Downstream
    consumers should eventually migrate to the
    `tdxVerifier_soundness_negl` shape sketched in
    `DstackVCVio.lean`. -/
theorem verifyTdxQuote_sound (n : Nat) (q : TdxQuote)
    (mr : MrEnclave) (ud : UserData n) :
    verifyTdxQuote n q = some (mr, ud) → was_signed_by_dstack q :=
  (tdxVerifier n).sound q mr ud

/-- **Theorem (formerly an axiom): Completeness** of TDX quote
    verification — a genuine dstack quote can be decoded to its
    measurement and user-data fields.

    Phrased existentially because the quote determines the fields,
    but we don't model the projection at this layer.

    Previously an independent axiom; now derived as a projection
    of the bundled `tdxVerifier` record.

    **Honesty caveat** (carries over from `tdxVerifier`): the
    real-world completeness claim is conditional on fresh
    Intel collateral and non-revocation of the PCK chain. The
    classical-Prop form drops those preconditions; the truthful
    formulation is in `DstackVCVio.lean`. -/
theorem verifyTdxQuote_complete (n : Nat) (q : TdxQuote) :
    was_signed_by_dstack q → ∃ mr ud, verifyTdxQuote n q = some (mr, ud) :=
  (tdxVerifier n).complete q

/-- Extract the user-data field from a successfully verified quote.

    Convenience wrapper used by composition theorems. -/
noncomputable def userDataOf (n : Nat) (q : TdxQuote) :
    Option (UserData n) :=
  (verifyTdxQuote n q).map Prod.snd

/-- Extract the measurement from a successfully verified quote. -/
noncomputable def mrEnclaveOf (n : Nat) (q : TdxQuote) :
    Option MrEnclave :=
  (verifyTdxQuote n q).map Prod.fst

/-- **Derived corollary**: if a quote verifies, both projections
    succeed. -/
theorem projections_some_of_verify
    (n : Nat) (q : TdxQuote) (mr : MrEnclave) (ud : UserData n)
    (h : verifyTdxQuote n q = some (mr, ud)) :
    mrEnclaveOf n q = some mr ∧ userDataOf n q = some ud := by
  refine ⟨?_, ?_⟩ <;> simp [mrEnclaveOf, userDataOf, h]

end Specs.Quartz.Attestation.Dstack
