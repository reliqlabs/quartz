/-
  Trust-boundary carrier types for dstack TDX attestation.

  This module contains the bare wire-format carriers and the
  abstract `was_signed_by_dstack` witness — the minimum surface
  shared between `Dstack.lean` (which provides the canonical
  `tdxVerifier` derived from `DcapVerifier`) and `DcapVerifier.lean`
  (which provides the reference DCAP-quote verifier itself).

  --------------------------------------------------------------------
  History: this content was carved out of `Specs/Quartz/Attestation/
  Dstack.lean` in cycle 7.5 (2026-05-25). The split exists ONLY to
  break the file-dependency cycle that arises when `Dstack.lean`
  wants to define `tdxVerifier` in terms of `DcapVerifier`'s
  `dcapTdxVerifier`: `DcapVerifier.lean` needs `TdxVerifier` and
  the carriers; `Dstack.lean` needs `DcapVerifier`. Pulling the
  shared surface into a third file resolves the cycle without
  touching any consumer file (downstream files import `Dstack.lean`
  and that import re-exposes everything in the `Specs.Quartz.
  Attestation.Dstack` namespace via the carrier re-export chain).
  --------------------------------------------------------------------

  The split is purely structural; the carrier definitions and the
  `was_signed_by_dstack` axiom are byte-for-byte the same as their
  pre-split forms (cycles 6.17-6.21 + cycle 6.22.d.3 history applies).
-/

-- LAYER INVARIANT (cycle 7.7 review M2): this file must remain free
-- of any import of `DcapVerifier` or any `Specs.Quartz.Attestation.*`
-- module other than itself. It is the lowest layer in the attestation
-- file dependency graph; both `Dstack.lean` and `DcapVerifier.lean`
-- import it. Re-introducing an import from this file into
-- `DcapVerifier` would recreate the file-dependency cycle that cycle
-- 7.5 carved this module out to break.

namespace Specs.Quartz.Attestation.Dstack

/-- An abstract TDX quote. In wire format this is the
    DCAP-quote-v4 byte blob produced by dstack.

    **Cycle 6.21 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8` (variable-length byte sequence). Typical DCAP
    quote v4 blobs are ~5000 bytes but the exact length depends
    on the PCK certificate chain inlined in the quote. -/
abbrev TdxQuote : Type := List UInt8

/-- The measurement of the enclave image: a pair `(MRTD, RTMR3)`.
    Used in `state.rs::Config::mr_enclave` and the journal's
    `rtmr3` binding gate (`expected_rtmr3`).

    **Cycle 6.17 (carrier refinement, 2026-05-20)**: refined from
    `axiom MrEnclave : Type` to `abbrev MrEnclave : Type := BitVec 384`.
    Intel TDX's MRTD (build-time measurement) is a 48-byte / 384-bit
    SHA-384 digest.

    **Cycle 7.9 (extended carrier, 2026-05-25, addresses cycle-7.7
    review M3)**: refined further to `BitVec 384 × BitVec 384` —
    the pair `(MRTD, RTMR3)`. Production dstack binds enclave
    identity via BOTH the MRTD (build-time image digest) AND RTMR3
    (the `compose_hash` runtime measurement of the deployed image's
    docker-compose). The `DstackZkAttestation` handler in
    `crates/contracts/core/src/handler/execute/attested.rs` enforces
    `journal.rtmr3 == config.expected_rtmr3` precisely to bind the
    deployed image identity beyond MRTD alone.

    Prior to cycle 7.9 the spec modelled `MrEnclave := BitVec 384`
    (MRTD only), making the spec under-bind a degree of identity that
    production verifies. Cycle 7.9 closes that gap. -/
abbrev MrEnclave : Type := BitVec 384 × BitVec 384

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

/-- **Trust-boundary record**: the dstack TDX verifier packaged with
    its (classical-Prop) soundness and completeness claims.

    Bundling rationale: prior to Step 4 of the VCV-io refactor the
    verifier function and its two correctness claims were three
    independent axioms. Bundling them into a single record packages
    "there is a verifier" with "the verifier is sound" and "the
    verifier is complete" into one trust-boundary commitment.

    **Honesty caveat**: both `sound` and `complete` fields are
    classical-Prop statements that drop the "with negligible
    probability of forgery / under valid collateral" qualifiers
    cryptography actually provides. The truthful `OracleComp`
    formulation lives in `DstackVCVio.lean`; the cycle-7.x DCAP
    reference verifier in `DcapVerifier.lean` provides a concrete
    construction of a `TdxVerifier n` whose `sound`/`complete`
    fields decompose into named (c)-bucket assumptions on
    standard primitives.

    **Cycle 7.21 (rotation precondition)**: the `signedRecently`
    field carries the verifier's rotation-window predicate. The
    `complete` field takes `signedRecently q` as a precondition,
    so completeness only holds for quotes within the verifier's
    current rotation window. Addresses cycle-7.14-19.b review H2:
    the previous unconditional `complete` field silently
    strengthened classical-Prop completeness across collateral
    expiry (any genuinely-signed quote would decode regardless of
    rotation epoch). The new shape makes the rotation dependency
    visible at every consumer site. -/
structure TdxVerifier (n : Nat) where
  verify : TdxQuote → Option (MrEnclave × UserData n)
  sound (q : TdxQuote) (mr : MrEnclave) (ud : UserData n) :
    verify q = some (mr, ud) → was_signed_by_dstack q
  /-- Rotation-window predicate (cycle 7.21): a quote is
      `signedRecently` if it was signed under the PCK chain that
      anchors to the verifier's current collateral bundle. -/
  signedRecently : TdxQuote → Prop
  complete (q : TdxQuote) :
    signedRecently q → was_signed_by_dstack q →
    ∃ mr ud, verify q = some (mr, ud)

end Specs.Quartz.Attestation.Dstack
