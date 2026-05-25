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
  Cycle 4 (VCV-io migration) bundled the verifier + soundness +
  completeness into a single `axiom tdxVerifier : TdxVerifier`. Cycle
  7.5 (2026-05-25) demotes even that single bundled axiom to a
  derived definition.
  --------------------------------------------------------------------

  Refactor (VCV-io migration, 2026-05-13, Step 4):

  * `TdxQuote`, `MrEnclave`, `UserData` remain as opaque carrier
    abbrevs (later refined to concrete `BitVec` widths in cycles
    6.17-6.21 and parameterised by the security parameter in cycle
    6.22.d.3).
  * `was_signed_by_dstack` remains as the propositional witness for
    off-chain reality (a genuine dstack TEE produced the quote with
    valid Intel PCK signatures up to the SGX Root CA). This is the
    analog of `Axioms.Crypto.was_signed_by` from verified-cosmwasm
    — a witness no Lean proof can construct, only consume. Honest
    computational assumption.
  * `RtmrLog : Type` is **removed** as a dead axiom.
  * `verifyTdxQuote`, `verifyTdxQuote_sound`, `verifyTdxQuote_complete`
    are **bundled** into a single trust-boundary record axiom
    `tdxVerifier : TdxVerifier`.

  Net effect on Quartz's verified surface (Step 4): **8 axioms → 5
  axioms**.

  --------------------------------------------------------------------
  Cycle 7.5 (axiom demotion, 2026-05-25):
  --------------------------------------------------------------------

  The `axiom tdxVerifier (n : Nat) : TdxVerifier n` is now a derived
  definition:

      noncomputable def tdxVerifier (n : Nat) : TdxVerifier n :=
        DcapVerifier.dcapTdxVerifier n
          DcapVerifier.productionCollateral
          DcapVerifier.productionCollateral_fresh

  The bundled axiom is removed from the closure of every downstream
  theorem. In its place the closure inherits the three named
  (c)-bucket assumptions from `DcapVerifier.lean`:

    1. `pckLeafKey_signs_imply_signed_by_pck_holder` (ECDSA-P256
       EUF-CMA over Intel's PCK key population).
    2. `chain_verified_leafKey_is_legitimate` (Intel SGX Root CA
       chain trust).
    3. `verified_chain_implies_dstack_signed` (the final composition:
       chain + signatures + TCB/QE gates → `was_signed_by_dstack`).

  Plus three value-witness opaques:

    * `freshCollateral` predicate (opaque)
    * `productionCollateral : Collateral` (opaque)
    * `productionCollateral_fresh : freshCollateral productionCollateral`
      (opaque)

  Plus four substep opaques the DCAP verifier composes:

    * `parseDcapQuote` (RawBytes → Option DcapQuote)
    * `verifyX509Chain` (cert chain walk → leaf pubkey)
    * `verifyEcdsaP256` (raw ECDSA-P256 verify)
    * `verifyAttestationKeyBinding` (QE-report → attestation-key hash check)
    * `qeReportBytes` (BitVec → RawBytes serialisation)

  `dcapVerifier_complete` remains an axiom (cycle 7.3 honest gap —
  completeness has no in-fork decomposition into standard primitives
  because the precondition `was_signed_by_dstack` is itself opaque).

  **Net axiom change for cycle 7.5**: -1 bundled `tdxVerifier`
  axiom; +3 named (c)-bucket cryptographic axioms (already counted
  in the cycle 7.3.b closure of `dcapVerifier_sound_composed`);
  +3 value-witness opaques (`freshCollateral`, `productionCollateral`,
  `productionCollateral_fresh`); +5 substep opaques. The trade is
  intentional: the substantive cryptographic content is now exposed
  as named, narrow assumptions on standard primitives rather than
  bundled inside a single trust-boundary axiom. Auditing the verified
  surface now reads as "trust ECDSA-P256, trust the Intel CA chain,
  trust the named verifier algorithm matches the production wire
  format" — each line of trust is auditable independently.

  --------------------------------------------------------------------
  HONESTY-LENS FINDING (load-bearing — do not paper over):
  --------------------------------------------------------------------

  The derived `tdxVerifier` and its projections inherit the same
  classical-Prop shape as the original bundled axiom. The `sound`
  field is now backed by `dcapVerifier_sound_composed` (cycle 7.3.b
  derived theorem) plus the three named (c)-bucket assumptions; the
  `complete` field is still backed by the `dcapVerifier_complete`
  axiom because the precondition `was_signed_by_dstack` is opaque.

    1. `tdxVerifier.sound : verifyTdxQuote q = some (mr, ud) →
                            was_signed_by_dstack q`
       Now derived (cycle 7.5) from `dcapVerifier_sound`. The
       cryptographic-reality "with negligible probability of forgery"
       qualifier is still dropped at this layer — the truthful
       formulation appears in `DstackVCVio.lean` and `ProtocolVCVio.lean`.

    2. `tdxVerifier.complete : was_signed_by_dstack q →
                               ∃ mr ud, verifyTdxQuote q = some (mr, ud)`
       Now derived (cycle 7.5) from `dcapVerifier_complete`, which is
       itself still an axiom. The cryptographic-reality "fresh
       Intel collateral + non-revocation" precondition is captured at
       `dcapVerifier_complete` (via `freshCollateral`).

  The truthful VCV-io oracle-game shapes are sketched in
  `DstackVCVio.lean`.

  **Downstream theorems carrying Dstack-axiom closure** (verified
  via `lean_verify` post-cycle-7.5; each rides on the named
  cryptographic axioms plus the value-witness + substep opaques):

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

  Of these, theorems 2 and 7 ride on BOTH the (now-derived) Dstack
  shape AND the bundled `commitHashE` / `commitHashBytesE` axioms
  (Step 2 / Step 3 findings).
-/

-- NOTE: This module is intentionally kept free of `VCVio` imports.
-- Downstream files rely on instance synthesis that VCVio's
-- transitive closure slows past the default heartbeat budget.
-- The VCV-io integration (verification-oracle model + soundness/
-- completeness negligibility-bound sketch) lives in the sibling
-- module `Specs/Quartz/Attestation/DstackVCVio.lean`, imported only
-- where probabilistic refinements are needed.

import Specs.Quartz.Attestation.DstackCarriers
import Specs.Quartz.Attestation.DcapVerifier

namespace Specs.Quartz.Attestation.Dstack

open Specs.Quartz.Attestation.DcapVerifier (dcapTdxVerifier
  productionCollateral productionCollateral_fresh
  signed_quotes_anchor_to_production_collateral)

/-- **Derived trust-boundary value (cycle 7.5)**: the canonical
    dstack TDX verifier, constructed by instantiating the reference
    DCAP verifier `dcapTdxVerifier` at the deployment-side production
    collateral bundle.

    Previously an axiom (cycle 4: `axiom tdxVerifier (n) : TdxVerifier n`).
    Demoted to a derived definition in cycle 7.5: the cryptographic
    content is now exposed as the three named (c)-bucket assumptions
    in `DcapVerifier.lean` (PCK ECDSA-P256 unforgeability, Intel CA
    chain trust, the final chain-link composition) plus value-witness
    opaques (`productionCollateral`, `productionCollateral_fresh`) and
    substep opaques (`parseDcapQuote`, `verifyX509Chain`, etc.).

    The audit story is: trust the production wire-format substeps
    (cycle 7.2.c queued for substep implementations), trust ECDSA-P256
    EUF-CMA on Intel's PCK key population, trust the Intel SGX Root CA
    chain trust discipline, and trust that the deployer fetches a
    fresh `productionCollateral` within Intel's next-update window. -/
noncomputable def tdxVerifier (n : Nat) : TdxVerifier n :=
  dcapTdxVerifier n productionCollateral productionCollateral_fresh
    signed_quotes_anchor_to_production_collateral

/-- Decode and verify a TDX quote.

    Operational mirror of the off-chain DCAP verification performed
    by zkdcap (and, eventually, the on-chain DCAP verifier hinted at
    in `attested.rs`).

    Returns `some (mr, user_data)` only on full success; `none` on
    any failure (malformed quote, expired collateral, bad signature,
    revoked PCK, etc.).

    Marked `noncomputable` because `tdxVerifier` is derived from
    opaque production-collateral value-witnesses. -/
noncomputable def verifyTdxQuote (n : Nat) (q : TdxQuote) :
    Option (MrEnclave × UserData n) :=
  (tdxVerifier n).verify q

/-- **Theorem: Soundness** of TDX quote verification — a quote that
    verifies must have been signed by dstack.

    Derived as a projection of the now-derived `tdxVerifier`. After
    cycle 7.5, the closure of this theorem is the named DCAP
    (c)-bucket axioms, not a bundled `tdxVerifier` axiom.

    This is the analog of `Axioms.Crypto.secp256k1_verify_sound`.

    **Honesty caveat**: this is a classical-Prop implication. The
    cryptographic reality is that DCAP verification is *computationally*
    sound (forgery has negligible probability), not absolutely sound.
    Downstream consumers should eventually migrate to the
    `tdxVerifier_soundness_negl` shape sketched in
    `DstackVCVio.lean`. -/
theorem verifyTdxQuote_sound (n : Nat) (q : TdxQuote)
    (mr : MrEnclave) (ud : UserData n) :
    verifyTdxQuote n q = some (mr, ud) → was_signed_by_dstack q :=
  (tdxVerifier n).sound q mr ud

/-- **Theorem: Completeness** of TDX quote verification — a genuine
    dstack quote can be decoded to its measurement and user-data
    fields.

    Phrased existentially because the quote determines the fields,
    but we don't model the projection at this layer.

    Derived as a projection of the now-derived `tdxVerifier`. After
    cycle 7.5, the closure of this theorem includes the
    `dcapVerifier_complete` axiom (still in-fork irreducible — its
    precondition `was_signed_by_dstack` is opaque).

    **Honesty caveat**: the real-world completeness claim is
    conditional on fresh Intel collateral and non-revocation of the
    PCK chain. The classical-Prop form drops those preconditions; the
    truthful formulation is in `DstackVCVio.lean`. -/
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
