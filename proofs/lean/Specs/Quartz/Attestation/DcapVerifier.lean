/-
Copyright (c) 2026 Quartz authors. All rights reserved.
Released under Apache 2.0 license.
-/

import Specs.Quartz.Attestation.DstackCarriers
import Specs.Quartz.Attestation.ByteUnpacking

/-!
# Reference DCAP verifier in Lean

This module formalises the Intel TDX DCAP (Data Center Attestation
Primitives) v4 quote verifier in Lean. The goal is to replace the
load-bearing `tdxVerifier (n) : TdxVerifier n` axiom in `Dstack.lean`
with a concrete reference implementation, demoting it from the trust
boundary to a derived definition (modulo PCK-signature unforgeability,
which remains an honest cryptographic assumption).

## Wire-format reference

The structural decoding matches the production zkdcap parser at
`zkdcap/circuits/dcap-gnark/witness/quote.go`. Bit-exact layout:

* Header (48 bytes): version, attestation key type, TEE type, QE SVN, PCE SVN.
* TDReport10 (584 bytes): TEE TCB SVN, MRTD, RTMR0-3, ReportData.
* AuthData (variable): ECDSA signature, attestation key, QE report,
  QE report signature, QE auth data, certificate chain.

Total signed region (header + TDReport10) = 632 bytes; remainder is
ECDSA-witness material verified against the embedded PCK chain.

## Verification flow

The verifier walks five proof obligations in order:

1. **Quote structural decode**: parse the byte blob into typed fields.
2. **Cert chain walk**: verify the PCK leaf certificate's chain up to
   the Intel SGX Root CA (hard-coded trusted public key).
3. **QE report signature**: verify the QE report's ECDSA signature
   under the PCK leaf certificate's public key.
4. **Attestation key binding**: verify the QE report's `report_data`
   contains the hash of the attestation key (binding QE → attestation key).
5. **Quote body signature**: verify the quote's signed region (header
   + TDReport10) under the attestation key.
6. **TCB / QE identity gates**: check the QE identity matches the
   collateral and the TCB level is at least the collateral threshold.

On full success, return `some (mrEnclave, reportData)` where:

* `mrEnclave` is the bundled MRTD + RTMR composition (per dstack convention).
* `reportData` is the 64-byte field at TDReport10 bytes [520..584).

This module provides the **structural** definitions and the verifier
algorithm skeleton. The cryptographic substeps (ECDSA verification,
X.509 chain walking) are themselves named definitions that downstream
cycles will either implement structurally or reduce to honest
cryptographic assumptions.

## Status

Cycle 7.1 (this commit): wire-format types + verifier signature +
top-level algorithm skeleton with substeps as named placeholders.

Cycle 7.2 (queued): substep implementations (ECDSA verification,
X.509 parsing, TCB level comparison, QE identity match).

Cycle 7.3 (queued): soundness reduction from `verifyDcap n q col = some _`
to PCK-signature unforgeability + collateral correctness.

Cycle 7.4 (queued): bridge to `TdxVerifier n` so the existing
`tdxVerifier n` axiom is demoted to a derived definition.
-/

namespace Specs.Quartz.Attestation.DcapVerifier

open Specs.Quartz.Attestation.Dstack
export Specs.Quartz.Attestation.ByteUnpacking (extractBitVec extractBitVec_take)

/-! ## Wire-format byte-level types -/

/-- A raw byte buffer of any length. Re-export of `List UInt8`. -/
abbrev RawBytes : Type := List UInt8

/-- The DCAP v4 quote header. 48 bytes total. -/
structure QuoteHeader where
  /-- Quote format version. Production: 4 or 5. -/
  version            : BitVec 16
  /-- Attestation key type. Production: ECDSA-256-with-P-256 (= 2). -/
  attestationKeyType : BitVec 16
  /-- TEE type. Production TDX: 0x00000081. -/
  teeType            : BitVec 32
  /-- Quoting Enclave SVN (Security Version Number). -/
  qeSvn              : BitVec 16
  /-- Provisioning Certification Enclave SVN. -/
  pceSvn             : BitVec 16
  /-- Remaining 20 bytes of vendor / reserved header fields. -/
  vendorBytes        : BitVec 160

/-- The TDReport10 body. 584 bytes total at offset 48 in the quote. -/
structure TdReport10 where
  /-- TEE TCB SVN. -/
  teeTcbSvn  : BitVec 128
  /-- MRTD (Measurement Register, TD): build-time digest of the dstack image. -/
  mrTd       : BitVec 384
  /-- Runtime Measurement Register 0 (firmware). -/
  rtmr0      : BitVec 384
  /-- Runtime Measurement Register 1 (kernel). -/
  rtmr1      : BitVec 384
  /-- Runtime Measurement Register 2 (initrd / boot binaries). -/
  rtmr2      : BitVec 384
  /-- Runtime Measurement Register 3 (application / compose_hash). -/
  rtmr3      : BitVec 384
  /-- User data slot (64 bytes / 512 bits). For dstack: the
      `user_data` field carrying the protocol commit. -/
  reportData : BitVec 512

/-- The AuthData portion (variable-length, parametrised by the cert
    chain and QE auth blob sizes). -/
structure AuthData where
  /-- ISV ECDSA signature over header || TDReport10. Raw `r || s`. -/
  ecdsaSignature    : BitVec 512
  /-- Attestation public key. Raw `x || y` over P-256. -/
  attestationKey    : BitVec 512
  /-- QE report (a fixed-size SGX-style report). -/
  qeReport          : BitVec (384 * 8)
  /-- QE report ECDSA signature under PCK leaf. -/
  qeReportSignature : BitVec 512
  /-- QE auth data (variable-length). -/
  qeAuthData        : RawBytes
  /-- Certificate chain (PEM-encoded; PCK leaf + intermediates). -/
  certificateData   : RawBytes

/-- The parsed DCAP v4 quote: header + body + auth. -/
structure DcapQuote where
  header   : QuoteHeader
  body     : TdReport10
  authData : AuthData
  /-- Raw signed region preserved for re-checking ECDSA. -/
  signedRegion : RawBytes

/-! ## Collateral types

Intel publishes signed collateral that the verifier consumes to check
TCB freshness and QE identity. -/

/-- An Intel TCB level entry. -/
structure TcbLevel where
  /-- TCB component SVNs (16 per CPU). -/
  svns     : RawBytes
  /-- TCB date (RFC 3339 string). -/
  date     : RawBytes
  /-- TCB status: UpToDate, OutOfDate, Revoked, etc. -/
  status   : RawBytes

/-- Signed TCB info from Intel. -/
structure TcbInfo where
  /-- TCB info version. Production: 3. -/
  version       : BitVec 32
  /-- Issue date. -/
  issueDate     : RawBytes
  /-- Next update date. -/
  nextUpdate    : RawBytes
  /-- FMSPC (Family-Model-Stepping-Platform-CustomSKU) identifier. -/
  fmspc         : BitVec 48
  /-- Per-platform TCB level list. -/
  tcbLevels     : List TcbLevel
  /-- Signature over the TCB info. -/
  signature     : BitVec 512

/-- QE identity collateral entry. -/
structure QeIdentity where
  /-- QE identity version. Production: 2. -/
  version    : BitVec 32
  /-- QE measurement (MRSIGNER + ISVPRODID + ISVSVN gating). -/
  mrsigner   : BitVec 256
  /-- QE ISV product ID. -/
  isvProdId  : BitVec 16
  /-- QE ISV SVN minimum. -/
  isvSvnMin  : BitVec 16
  /-- Issue date. -/
  issueDate  : RawBytes
  /-- Signature over the QE identity. -/
  signature  : BitVec 512

/-- The full DCAP collateral bundle. -/
structure Collateral where
  /-- Intel SGX Root CA certificate (the trust anchor). -/
  rootCaCert      : RawBytes
  /-- Intel TCB-signing intermediate certificate. -/
  tcbSigningCert  : RawBytes
  /-- TCB info bundle. -/
  tcbInfo         : TcbInfo
  /-- QE identity bundle. -/
  qeIdentity      : QeIdentity

/-! ## Verifier substep signatures

Each substep is a named definition. Cycle 7.1 leaves the bodies as
opaque hypotheses; cycle 7.2 will replace them with concrete
implementations or honest cryptographic assumptions. -/

/-- Parse a raw byte blob into a DcapQuote, or fail if structurally invalid.
    Production analog: `ParseTDXQuoteV4` in
    `zkdcap/circuits/dcap-gnark/witness/quote.go`. -/
opaque parseDcapQuote : RawBytes → Option DcapQuote

/-- **Structural invariant (cycle 7.6, addresses cycle-7.x adversarial
    finding #14 partially)**: a successful `parseDcapQuote raw = some q`
    sets the parsed quote's `signedRegion` to exactly the first 632
    bytes of the input — the concatenation of the header (48 bytes)
    and the `TDReport10` body (584 bytes).

    Without this axiom the parser is free to set `signedRegion` to any
    `RawBytes` value independent of `raw`. The production zkdcap parser
    at `zkdcap/circuits/dcap-gnark/witness/quote.go` always sets
    `signedRegion = raw[0..632]` bytewise; this axiom is the in-Lean
    structural commitment to that behavior.

    **Cycle 7.7 adversarial-review meta** (finding C1): this axiom is
    consumed by exactly one corollary
    (`verifyDcap_signedRegion_eq_input_prefix`) and no downstream
    `Protocol/*` or `Crypto/*` theorem cites it. It is *available* in
    the audit-closure of consumer-derived theorems if they choose to
    cite it; it is not yet load-bearing in any safety property. Cycle
    7.7 adds the parallel field-binding axioms (`mrTd_eq`,
    `reportData_eq`) which ARE load-bearing in the cycle 7.7
    `verifyDcap_output_bound_to_input` theorem, and are the right
    place for downstream protocol theorems to consume parser-output
    pinning — `signedRegion` linkage is a corollary of those field
    bindings via cryptographic chaining, not a primary surface. -/
axiom parseDcapQuote_signedRegion_eq_input_prefix
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q → q.signedRegion = raw.take 632

/-! ## Cycle 7.7 — parser field-binding axioms (addresses cycle-7.7-review C2/C3)

The cycle-7.7 adversarial review surfaced that pinning only
`signedRegion` to the input leaves `mrTd`, `reportData`,
`attestationKey`, `qeReport`, `certificateData` etc. fully unconstrained:
an adversarial parser can return a `DcapQuote` with attacker-chosen
`mrTd` (so `composeMrEnclave q.body = attacker_mr`) and attacker-chosen
`reportData` (so `projectUserData n q.body = attacker_ud`), while
still satisfying every other check including the cycle-7.6
`signedRegion` invariant. The returned `(mr, ud)` would then bear no
relation to the actual signed quote bytes, breaking measurement
binding silently at the protocol layer.

This section pins the *consumed-by-output* fields. The
cryptographically-load-bearing auth-data fields (attestationKey,
qeReport, certificateData) are pinned in cycle 7.8 (queued — they
require modelling the variable-length auth-data layout). -/

/-! ### Cycle 7.19.b — `extractBitVec` and `extractBitVec_take`

These were previously `opaque` and `axiom` in this module (cycles
7.7-7.18). Cycle 7.19.b moves them to a new module
`Specs.Quartz.Attestation.ByteUnpacking` where the proof of
`extractBitVec_take` can use Mathlib tactics without the cascade
through `Dstack.lean` / `DstackCarriers.lean`. The bare def +
theorem are re-exported via the `open` clause above.

Audit consequence: `extractBitVec` is no longer in the axiom closure
of any cycle 7.x theorem; `extractBitVec_take` is a derived theorem,
not an axiom. The cycle-7.13 binding theorem and its downstream
Protocol consumers (cycles 7.15-7.17) now lose two entries from
their closures.

Reference: `Specs/Quartz/Attestation/ByteUnpacking.lean` for the
def + theorem; this file consumes only the bare names. -/

/-- **Structural invariant (cycle 7.14, addresses review H4)**: a
    successful parse implies the wire-format header gates accepted by
    the production parser. Without this axiom an adversarial parser
    could return `some q` for an SGX (non-TDX) quote, a future
    `version=6` quote, or a non-ECDSA-P256 attestation-key-type
    quote — all of which the production parser at `quote.go:60-65`
    rejects but which the in-Lean spec would have permitted.

    Constrains:
    - `q.header.version ∈ {4, 5}` (the only versions production
      accepts: cycle-7.x targets v4 specifically)
    - `q.header.teeType = 0x00000081` (the TDX TEE type — SGX is
      0x00000000 and is rejected for this verifier)
    - `q.header.attestationKeyType = 2` (ECDSA-P256 with P-256;
      other key types do not match the cycle-7.11 attestationKey
      offset/width layout)

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:60-65`
    `if q.Version != 4 && q.Version != 5 { return nil, ... }`
    `if q.TeeType != 0x00000081 { return nil, ... }`. -/
axiom parseDcapQuote_header_validates
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    (q.header.version = 4 ∨ q.header.version = 5) ∧
    q.header.teeType = 0x00000081 ∧
    q.header.attestationKeyType = 2

/-- **Structural invariant (cycle 7.14, addresses review H5)**: a
    successful parse implies the outer CertificationData `cert_type`
    is 6 (the QEReportCertData wrapper required by DCAP v4 TDX).
    Conditions the cycle 7.12 axioms (`parseDcapQuote_qeReport_eq`,
    `parseDcapQuote_qeReportSignature_eq`) on the layout assumption
    they implicitly carried via docstring caveat. Without this axiom
    an adversarial parser could return a quote with cert_type=7
    (hypothetical future) where the QE report sits at a different
    offset; the cycle 7.12 axioms would be false in that model.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:98-108`
    `if certType == 6 { … } else { return nil, ... unexpected outer
    cert_type }`. -/
axiom parseDcapQuote_certType_eq_6
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    extractBitVec raw 764 16 = (6 : BitVec 16)

/-- **Structural invariant (cycle 7.7, corrected in cycle 7.10)**: a
    successful parse sets `q.body.mrTd` to the BitVec extracted from
    `raw` at the MRTD slot inside `TDReport10`.

    **Layout note (CORRECTED cycle 7.10)**: `TdReport10` is 584 bytes
    at quote-offset 48. Inside `TdReport10`, the MRTD field lives at
    TDReport10-offset **136** (not 16 as cycle 7.7 incorrectly said —
    the gap holds 120 bytes of TDX-specific fields: MrSeam,
    MrSignerSeam, SeamAttributes, TdAttributes, XFAM). Absolute offset
    in raw: `48 + 136 = 184`, width 48 bytes = 384 bits.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:70`
    `copy(q.MrTd[:], r[136:184])` where `r := raw[headerLen:]` so
    absolute offset is `48 + 136 = 184`. -/
axiom parseDcapQuote_mrTd_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.body.mrTd = extractBitVec raw 184 384

/-- **Structural invariant (cycle 7.11)**: a successful parse sets
    `q.authData.ecdsaSignature` to the BitVec extracted from `raw` at
    the AuthData ECDSA signature slot.

    **Layout note**: AuthData starts at absolute offset 632 (after
    header 48 + TDReport10 584). The first 4 bytes (632..636) are a
    little-endian `authSize` count. AuthDataV4 starts at absolute 636,
    with EcdsaSignature occupying its first 64 bytes (636..700).

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:78-94`
    `authOff := signedLen; authOff += 4` (skips size); then
    `copy(q.EcdsaSignature[:], auth[0:64])` where `auth :=
    raw[authOff:...]` so absolute = `signedLen + 4 + 0 = 636`,
    width 64 bytes = 512 bits. -/
axiom parseDcapQuote_ecdsaSignature_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.authData.ecdsaSignature = extractBitVec raw 636 512

/-- **Structural invariant (cycle 7.11)**: a successful parse sets
    `q.authData.attestationKey` to the BitVec extracted from `raw` at
    the AuthData attestation-key slot.

    **Layout note**: AuthDataV4 attestation key occupies auth[64..128]
    = raw[700..764]. Width 64 bytes = 512 bits.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:95`
    `copy(q.AttestationKey[:], auth[64:128])` where `auth :=
    raw[636:]` so absolute = 700, width = 512 bits.

    Closes part of the cycle-7.7-review finding C2 attack surface:
    an adversarial parser cannot substitute a different attestation
    key in the returned DcapQuote — the key's bytes are pinned to a
    specific window of the raw input. The QE report's signed binding
    `verifyAttestationKeyBinding qeReport attestationKey` therefore
    operates on a key the prover did not control. -/
axiom parseDcapQuote_attestationKey_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.authData.attestationKey = extractBitVec raw 700 512

/-- **Structural invariant (cycle 7.12)**: a successful parse sets
    `q.authData.qeReport` to the BitVec extracted from `raw` at the
    QE-report slot inside the AuthData outer CertificationData body.

    **Layout note (DCAP v4, cert_type=6)**: AuthData starts at 636.
    AttestationKey occupies 700..764. The outer CertificationData
    header (certType u16 + certBodySize u32) is at 764..770. The
    certBody (inner QEReportCertData) starts at 770. Inside certBody:
    QeReport occupies bytes 0..384 = raw[770..1154]. Width 384 bytes
    = 3072 bits = 384 * 8 (matching the `qeReport : BitVec (384*8)`
    field type).

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:98-104`
    `certType := binary.LittleEndian.Uint16(auth[128:130])` (cert_type
    must be 6 for QEReportCertificationData), `certBody := auth[134:
    134+certBodySize]`, then `parseQEReportCertData(certBody)` which
    starts with `copy(q.QeReport[:], data[0:384])`.

    **Caveat**: this axiom assumes the outer certType is 6 (the only
    valid type for DCAP v4 TDX). Production parser rejects other
    certType values, so the spec assumption is honest under the
    production-acceptance restriction. -/
axiom parseDcapQuote_qeReport_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.authData.qeReport = extractBitVec raw 770 (384 * 8)

/-! ### Cycle 7.18 — variable-offset cert-data field pinning

The cycle 7.7/7.9/7.11/7.12 axioms cover every fixed-offset field
consumed by `verifyDcap`'s substep chain. The remaining
parser-decoupling surface is the variable-length `qeAuthData` (whose
length is read from a 2-byte LE u16 at raw[1218..1220]) and
`certificateData` (which starts at offset `1226 + qeAuthLen`). Cycle
7.18 closes both via axioms that thread the parsed length value. -/

/-- **Structural invariant (cycle 7.20, addresses review H1)**:
    a successful parse implies the raw input has enough bytes for the
    full variable-length AuthData structure. Without this axiom the
    cycle 7.18 `parseDcapQuote_qeAuthData_eq` and
    `parseDcapQuote_certificateData_eq` axioms admit short-`raw`
    inputs the production parser at `quote.go:125, 138` would reject
    (silent List.take truncation rather than parser error).

    Specifically: the raw input must contain the full qeAuthData
    region (offset 1220 to 1220+qeAuthLen) AND the inner cert-data
    header (6 bytes after qeAuthData) AND the cert-data body
    (innerCertBodySize bytes after the header).

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:125`
    `if off+int(authLen) > len(data) { return ... "QE auth data
    exceeds bounds" }` and `:138` `if off+int(innerCertBodySize) >
    len(data) { return ... "inner cert data exceeds bounds" }`. -/
axiom parseDcapQuote_authData_length_valid
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    let qeAuthLen := (extractBitVec raw 1218 16).toNat
    let innerCertBodySize := (extractBitVec raw (1222 + qeAuthLen) 32).toNat
    1226 + qeAuthLen + innerCertBodySize ≤ raw.length

/-- **Structural invariant (cycle 7.18)**: the `qeAuthData` field is
    pinned to a raw byte slice starting at offset 1220, of length
    given by the LE u16 at raw[1218..1220].

    The slice length is expressed as `(extractBitVec raw 1218 16).toNat`
    so the axiom carries the parsed-length dependency explicitly.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:122-129`
    `authLen := binary.LittleEndian.Uint16(data[448:450])` where
    `data` is certBody starting at raw[770], so the length-prefix is
    at absolute raw[770+448:770+450] = raw[1218:1220]. The slice is
    `data[off:off+authLen]` for `off := 450` → absolute raw[1220:1220+authLen]. -/
axiom parseDcapQuote_qeAuthData_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.authData.qeAuthData =
      (raw.drop 1220).take (extractBitVec raw 1218 16).toNat

/-- **Structural invariant (cycle 7.18)**: the `certificateData` field
    is pinned to a raw byte slice starting at offset
    `1226 + qeAuthLen` (the 6-byte gap is the inner CertificationData
    header: 2-byte cert_type + 4-byte certBodySize). The length is
    the parsed `innerCertBodySize` value.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:132-141`
    `off += authLen; innerCertBodySize := binary.LittleEndian.Uint32(data[off+2:off+6]); q.CertificateData = data[off+6:off+6+innerCertBodySize]`.
    Absolute: cert-data offset = 770 + 450 + qeAuthLen + 6 = 1226 + qeAuthLen.
    Length = LE u32 at raw[1226 + qeAuthLen - 4 : 1226 + qeAuthLen] =
    raw[1222 + qeAuthLen : 1226 + qeAuthLen]. -/
axiom parseDcapQuote_certificateData_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    let qeAuthLen := (extractBitVec raw 1218 16).toNat
    q.authData.certificateData =
      (raw.drop (1226 + qeAuthLen)).take
        (extractBitVec raw (1222 + qeAuthLen) 32).toNat

/-- **Structural invariant (cycle 7.12)**: a successful parse sets
    `q.authData.qeReportSignature` to the BitVec extracted from `raw`
    at the QE report signature slot.

    **Layout note**: inside the certBody (starting at raw[770]),
    QeReportSignature is at offset 384..448. Absolute: raw[1154..1218].
    Width 64 bytes = 512 bits.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:120`
    `copy(q.QeReportSignature[:], data[384:448])`. -/
axiom parseDcapQuote_qeReportSignature_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.authData.qeReportSignature = extractBitVec raw 1154 512

/-- **Structural invariant (cycle 7.9, corrected in cycle 7.10)**: a
    successful parse sets `q.body.rtmr3` to the BitVec extracted from
    `raw` at the RTMR3 slot inside `TDReport10`.

    **Layout note (CORRECTED cycle 7.10)**: `TdReport10`'s `rtmr3`
    field is at TDReport10-offset **472** (not 208 as cycle 7.9
    incorrectly computed — the production layout has TDX-specific
    fields between TeeTcbSvn and MrTd, then MrTd at 136..184, then
    Rtmr0 at 328..376, Rtmr1 at 376..424, Rtmr2 at 424..472, Rtmr3
    at 472..520, ReportData at 520..584). Absolute offset in raw:
    `48 + 472 = 520`, width 48 bytes = 384 bits.

    Reference: `zkdcap/circuits/dcap-gnark/witness/quote.go:74`
    `copy(q.Rtmr3[:], r[472:520])` where `r := raw[headerLen:]`. -/
axiom parseDcapQuote_rtmr3_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.body.rtmr3 = extractBitVec raw 520 384

/-- **Structural invariant (cycle 7.7)**: a successful parse sets
    `q.body.reportData` to the BitVec extracted from `raw` at the
    `report_data` slot inside `TDReport10`.

    **Layout note**: `TdReport10`'s `report_data` field is the last
    64 bytes, at TDReport10-offset 520 (after teeTcbSvn 16 + mrTd 48
    + rtmr0..3 4×48 + reserved). Absolute offset: `48 + 520 = 568`,
    width 64 bytes = 512 bits. Reference: same as `mrTd_eq`. -/
axiom parseDcapQuote_reportData_eq
    (raw : RawBytes) (q : DcapQuote) :
    parseDcapQuote raw = some q →
    q.body.reportData = extractBitVec raw 568 512

-- The cycle 7.7 binding theorem `verifyDcap_output_bound_to_input`
-- lives after `verifyDcap` is defined (further down in the file).

/-- Verify an X.509 certificate chain rooted at the Intel SGX Root CA.
    Returns the leaf certificate's public key on success. -/
opaque verifyX509Chain : RawBytes → RawBytes → Option (BitVec 512)

/-- Verify an ECDSA-P256 signature over a message under a given public key.
    Production: gnark's `Verify(pk, msg, sig)` on the BN-254 / P-256 curve. -/
opaque verifyEcdsaP256 (pubKey : BitVec 512) (msg : RawBytes)
    (sig : BitVec 512) : Bool

/-- Check that the attestation key is bound by the QE report's
    `report_data` (typically `report_data[0..32] = sha256(attestationKey)`). -/
opaque verifyAttestationKeyBinding (qeReport : BitVec (384 * 8))
    (attestationKey : BitVec 512) : Bool

/-- **Bit-to-byte conversion** for the QE report. Converts the
    bit-packed `BitVec (384 * 8)` to its `RawBytes` representation
    consumed by `verifyEcdsaP256`. Opaque at this spec level — the
    production conversion is little-endian byte unpacking that
    downstream substeps depend on.

    Moved from cycle 7.3.b's bridging-axiom section to here so
    `verifyDcap` (below) can invoke it. -/
opaque qeReportBytes : BitVec (384 * 8) → RawBytes

/-- **Structural axiom (cycle 7.16, addresses review L1)**: the
    `qeReportBytes` conversion applied to a `BitVec` extracted from
    a specific window of `raw` equals the corresponding byte slice
    of `raw`. Without this axiom an adversarial `qeReportBytes` could
    ignore its `BitVec` input and return attacker-chosen bytes,
    defeating the cycle 7.12 `qeReport` pinning.

    Operationally: `qeReportBytes` is little-endian byte unpacking of
    a 384*8-bit vector into 384 bytes. When the input BitVec was
    little-endian-packed from `raw[offset..offset+384]` (via
    `extractBitVec`), the unpacking returns the original bytes.

    Concretely for the cycle 7.12 layout (`qeReport` at offset 770,
    width 384*8):
        qeReportBytes (extractBitVec raw 770 (384*8))
          = (raw.drop 770).take 384
    Connects the cycle-7.12 qeReport-binding to the bytes the
    `verifyEcdsaP256` substep in `verifyDcap` actually hashes. -/
axiom qeReportBytes_extractBitVec_eq
    (raw : RawBytes) (offset : Nat) :
    qeReportBytes (extractBitVec raw offset (384 * 8))
      = (raw.drop offset).take 384

/-- Check that the TCB level reported by the quote meets the
    collateral's TCB threshold.

    **Cycle 7.2.b implementation**: walks `info.tcbLevels` looking for a
    level entry whose `svns` field matches `q.body.teeTcbSvn` bytewise
    AND whose `status` is `UpToDate` (the deployed-policy threshold).

    The match predicate is "the quote's TCB SVN equals at least one
    `UpToDate` entry in the collateral's TCB info". Production zkdcap
    additionally accepts `SWHardeningNeeded` and `ConfigurationNeeded`;
    Quartz's stance is strict (`UpToDate` only) — auditable here.

    Note: this substep is *structural* — given a parsed quote and a
    parsed collateral bundle, it returns a Bool decision. It does NOT
    verify the collateral's signature (that's `verifyX509Chain` plus
    `verifyEcdsaP256` on the TCB-info signing key, a separate substep). -/
def checkTcbLevel (q : DcapQuote) (info : TcbInfo) : Bool :=
  -- **Endianness assumption (cycle 7.x adversarial finding #8)**:
  -- parseDcapQuote is opaque, so the wire-byte → BitVec 128 packing
  -- convention is not externally pinned. This function assumes
  -- *little-endian* byte packing: wire byte 0 of teeTcbSvn maps to
  -- the LOW 8 bits of the BitVec, and byte i = `(teeTcbSvn.toNat >>>
  -- (i*8)) &&& 0xff`. Production parseDcapQuote MUST match this
  -- convention; mismatch silently reverses the byte order and the
  -- comparison fails against the collateral.
  let quoteSvns : RawBytes :=
    (List.range 16).map (fun i => UInt8.ofNat ((q.body.teeTcbSvn.toNat >>> (i * 8)) &&& 0xff))
  info.tcbLevels.any (fun lvl =>
    lvl.svns = quoteSvns ∧ lvl.status = "UpToDate".toUTF8.toList)

/-- Check that the QE identity reported by the quote matches the
    collateral's QE identity (MRSIGNER + product ID + SVN min).

    **Cycle 7.2.b implementation**: extracts the QE report's MRSIGNER
    (SGX report offset 128..160), ISVPRODID (offset 256..258), ISVSVN
    (offset 258..260) from the 384-byte QE report blob and compares
    against the collateral's `qe.mrsigner`, `qe.isvProdId`, `qe.isvSvnMin`
    fields. The SVN check is `>=` against the minimum (production-aligned).

    Reference: Intel SGX Architectural Enclaves Service Manager spec,
    SGX_REPORT_BODY layout. -/
def checkQeIdentity (q : DcapQuote) (qe : QeIdentity) : Bool :=
  let report := q.authData.qeReport
  -- Extract MRSIGNER (32 bytes at offset 128..160 in SGX report body).
  let mrsigner : BitVec 256 :=
    BitVec.ofNat 256 ((report.toNat >>> (128 * 8)) &&& ((1 <<< 256) - 1))
  -- Extract ISVPRODID (2 bytes at offset 256..258, little-endian).
  let isvProdId : BitVec 16 :=
    BitVec.ofNat 16 ((report.toNat >>> (256 * 8)) &&& 0xffff)
  -- Extract ISVSVN (2 bytes at offset 258..260, little-endian).
  let isvSvn : BitVec 16 :=
    BitVec.ofNat 16 ((report.toNat >>> (258 * 8)) &&& 0xffff)
  decide (mrsigner = qe.mrsigner) &&
  decide (isvProdId = qe.isvProdId) &&
  decide (isvSvn.toNat ≥ qe.isvSvnMin.toNat)

/-! ## Reference verifier

Composes the substeps into a single verifier that returns the
deployed-format `(MrEnclave, UserData n)` pair on full success. -/

/-- The composed enclave identity: the pair `(MRTD, RTMR3)`.

    **Cycle 7.9 implementation (addresses prior cycle-7.x review
    finding M3)**: returns both `body.mrTd` (build-time image digest)
    and `body.rtmr3` (the runtime `compose_hash` measurement). Matches
    dstack's deployed binding discipline, which gates on both via
    `state.rs::Config::mr_enclave` and `expected_rtmr3` in
    `crates/contracts/core/src/handler/execute/attested.rs`.

    Prior cycle-7.2 implementation returned `body.mrTd` only, which
    misrepresented the deployed binding (RTMR3 was silently dropped).
    Cycle 7.9 closes that gap by extending `MrEnclave` to a pair
    `BitVec 384 × BitVec 384`. -/
def composeMrEnclave (body : TdReport10) : MrEnclave :=
  (body.mrTd, body.rtmr3)

/-- Project the user-data slot at the spec's `n` width.

    **Cycle 7.2 implementation**: deployed `n = 512` returns the raw
    64-byte `report_data` field directly (`Eq`-via-cast). For `n ≠ 512`
    `BitVec.ofNat n body.reportData.toNat` handles both truncation
    (`n < 512`: takes low `n` bits) and zero-extension (`n > 512`:
    high bits are zero by `BitVec.ofNat`'s `mod 2^n` semantics) in one
    operation.

    **Cycle 6.22.d.5 caveat (adversarial finding #6)**: when `n < 512`
    the projection is *silent low-bit truncation*. The dstack
    deployment uses `n = 512` so the truncation case is not exercised
    in production; the spec offers no precondition forbidding `n < 512`
    callers. If the high bits of `report_data` encode load-bearing
    content (e.g. attestation-key hash binding), `n < 512` callers
    would silently lose them. Documented; the safe-use convention
    `n = 512` matches deployment. -/
noncomputable def projectUserData (n : Nat) (body : TdReport10) : UserData n :=
  if h : n = 512 then h ▸ body.reportData
  else BitVec.ofNat n body.reportData.toNat

/-- **Reference DCAP verifier**: structural decoding + all five
    crypto substeps + collateral gates. Returns `some (mr, ud)` only
    on full success.

    Cycle 7.1 leaves the substeps opaque. Cycle 7.2 implements them.
    Cycle 7.3 proves soundness: any `verifyDcap n q col = some (mr, ud)`
    implies `was_signed_by_dstack q` under PCK-signature unforgeability +
    `Collateral` correctness. -/
noncomputable def verifyDcap (n : Nat) (rawQuote : RawBytes)
    (col : Collateral) : Option (MrEnclave × UserData n) :=
  match parseDcapQuote rawQuote with
  | none => none
  | some q =>
    match verifyX509Chain q.authData.certificateData col.rootCaCert with
    | none => none
    | some pckLeafPubKey =>
      if !verifyEcdsaP256 pckLeafPubKey (qeReportBytes q.authData.qeReport)
          q.authData.qeReportSignature
      then none
      else if !verifyAttestationKeyBinding q.authData.qeReport q.authData.attestationKey
      then none
      else if !verifyEcdsaP256 q.authData.attestationKey q.signedRegion q.authData.ecdsaSignature
      then none
      else if !checkTcbLevel q col.tcbInfo
      then none
      else if !checkQeIdentity q col.qeIdentity
      then none
      else some (composeMrEnclave q.body, projectUserData n q.body)

/-! ## Cycle 7.3 — intermediate cryptographic assumptions for the soundness reduction

`dcapVerifier_sound` is the substantive cryptographic claim. We
decompose its soundness into three honest cryptographic assumptions,
each tied to a standard primitive and corresponding to an
externally-deferred discharge target:

1. **PCK-signature unforgeability** (ECDSA-P256 on Intel's PCK keys):
   if `verifyEcdsaP256 pckKey msg sig = true` AND `pckKey` is a legitimate
   PCK leaf from a chain-verified collateral bundle, then a real signer
   (holder of the PCK private key, which Intel certifies to be running
   in genuine TDX) produced the signature on `msg`.

2. **X.509 chain trust**: if `verifyX509Chain leafCert rootCa = some pubKey`
   for the Intel SGX Root CA, then `pubKey` is the legitimate PCK leaf
   key and the chain is well-formed (Intel SGX Root CA signed the
   intermediate, which signed the leaf, recursively).

3. **Collateral correctness**: a fresh `Collateral` bundle correctly
   reflects Intel's current TCB info and QE identity (the
   `freshCollateral` predicate asserts the next-update window is alive
   and the issuer signatures chain).

These three replace the single bundled `tdxVerifier` trust assumption
with three narrower assumptions on standard primitives. Each is in the
(c) bucket (honest cryptographic assumption on a real-world primitive)
rather than (d) (impossibility / over-strength). -/

/-- Freshness predicate on collateral: the TCB info and QE identity
    are within their next-update window, and the issuer signatures
    chain to the Intel SGX Root CA. -/
opaque freshCollateral : Collateral → Prop

/-- **Abstract witness predicate**: `msg` was signed by the holder of
    the private key paired with `leafKey`. Externalises the "signature
    is real" property as a propositional witness, mirroring the shape
    of `was_signed_by_dstack` in `Dstack.lean`. -/
axiom signed_by_pck_holder : BitVec 512 → RawBytes → Prop

/-- **Abstract witness predicate**: `leafKey` is a legitimate Intel-
    certified PCK leaf key (issued by Intel for a TEE-resident
    Provisioning Certification Enclave). -/
axiom legitimate_pck_leaf : BitVec 512 → Prop

-- `pck_holder_is_dstack_tee` (cycle 7.3.a placeholder with `True`
-- body) was removed in cycle 7.3.b — its role is taken by
-- `verified_chain_implies_dstack_signed` (below), which carries the
-- full chain-to-quote-property connection with non-trivial type.

/-- **(c)-bucket assumption (ECDSA-P256 EUF-CMA over Intel's PCK key
    population)**: a legitimate PCK leaf key signature on a message
    is unforgeable by any party other than the holder of the
    corresponding private key.

    Concretely: `verifyEcdsaP256 leafKey msg sig = true` AND `leafKey`
    is a `legitimate_pck_leaf` implies the message was signed by the
    holder of `leafKey`'s private key. This is the standard ECDSA
    unforgeability assumption restricted to Intel's PCK key
    population.

    Now load-bearing (carries the `signed_by_pck_holder` witness in
    its conclusion). -/
axiom pckLeafKey_signs_imply_signed_by_pck_holder
    (leafKey : BitVec 512) (msg : RawBytes) (sig : BitVec 512) :
    legitimate_pck_leaf leafKey →
    verifyEcdsaP256 leafKey msg sig = true →
    signed_by_pck_holder leafKey msg

/-- **(c)-bucket assumption (X.509 chain trust to Intel SGX Root CA)**:
    a successful chain walk from a leaf certificate up to the Intel
    SGX Root CA implies the leaf's public key is a legitimate PCK leaf.

    Concretely: `verifyX509Chain certData rootCa = some leafKey`
    implies `legitimate_pck_leaf leafKey`. Captures Intel's CA trust
    discipline (the Root CA only signs intermediates that only sign
    PCK leaves issued for TEE-resident PCEs).

    Now load-bearing (carries the `legitimate_pck_leaf` witness in
    its conclusion). -/
axiom chain_verified_leafKey_is_legitimate
    (certData : RawBytes) (rootCa : RawBytes) (leafKey : BitVec 512) :
    verifyX509Chain certData rootCa = some leafKey →
    legitimate_pck_leaf leafKey

/-! ### Cycle 7.3.c — decompose the chain-link axiom (addresses review H2)

The original cycle-7.3.b axiom `verified_chain_implies_dstack_signed`
bundled the entire trust chain into a single 8-hypothesis assumption,
which review H2 critiqued as monolithic. Cycle 7.3.c (this section)
splits it into two narrower (c)-bucket assumptions tied to SGX-spec
content, with one intermediate witness predicate, and derives the
original monolith as a theorem.

The decomposition mirrors the production DCAP trust flow:

1. **First link (QE attestation chain)**: a legitimate PCK leaf
   signing the QE report, plus a verified attestation-key binding
   inside the QE report's `report_data`, implies the QE is a
   genuine Intel-attested QE that endorses the attestation key.

2. **Second link (TEE signing)**: a genuine QE endorsing an
   attestation key that signs the quote body, plus matching TCB
   and QE identity gates, implies the quote was produced by a TEE
   running attested code (i.e., dstack).

The intermediate `signed_by_qe` witness predicate makes the
hand-off between the two links explicit. -/

/-- **Abstract witness predicate (cycle 7.3.c)**: a parsed DCAP
    quote was signed by a genuine Intel-attested Quoting Enclave
    (the `parsed.authData.attestationKey` is the bound attestation
    key of a real QE, and `parsed.signedRegion` was signed by that
    key). Bridges between the PCK-attestation chain link (axiom A
    below) and the TEE-signing chain link (axiom B below).

    **Cycle 7.14 (addresses review C1)**: a constraining axiom
    `signed_by_qe_implies_pck_chain_witnesses` (below) excludes the
    trivial `signed_by_qe := fun _ => True` model — if `signed_by_qe
    parsed` holds, there must exist a legitimate PCK leaf that signed
    the QE report. Without this constraint, the cycle 7.3.c
    decomposition would have been vacuous (`signed_by_qe := True`
    satisfies both axioms A and B as stated). -/
axiom signed_by_qe : DcapQuote → Prop

/-- **(c)-bucket constraint (cycle 7.14, addresses review C1)**:
    `signed_by_qe parsed` implies the existence of a legitimate PCK
    leaf key whose holder signed the QE report. Excludes the trivial
    `signed_by_qe := fun _ => True` model that would make the cycle
    7.3.c decomposition vacuous.

    Acts as the dual of `qe_attestation_chain_implies_signed_by_qe`:
    that axiom says the forward direction (the chain implies the
    predicate); this axiom says the reverse-witness direction (the
    predicate implies some chain exists). Together they pin down
    `signed_by_qe` informationally — it carries the same content as
    the conjunction of the four cryptographic substep witnesses,
    not less. -/
axiom signed_by_qe_implies_pck_chain_witnesses
    (parsed : DcapQuote) :
    signed_by_qe parsed →
    ∃ pckLeafKey : BitVec 512,
      legitimate_pck_leaf pckLeafKey ∧
      signed_by_pck_holder pckLeafKey (qeReportBytes parsed.authData.qeReport) ∧
      verifyAttestationKeyBinding parsed.authData.qeReport
          parsed.authData.attestationKey = true ∧
      verifyEcdsaP256 parsed.authData.attestationKey parsed.signedRegion
          parsed.authData.ecdsaSignature = true

/-- **(c)-bucket assumption A (cycle 7.3.c — QE attestation chain)**:
    given a parsed quote whose `qeReport` was signed by the holder of
    a legitimate PCK leaf key (i.e., Intel certified the QE's signing
    chain), AND whose `attestationKey` is bound by the `qeReport`'s
    `report_data` slot (the SGX spec's attestation-key endorsement
    mechanism), the parsed quote `signed_by_qe` predicate holds.

    Concretely: the chain `Intel Root CA → PCK leaf → QE report
    endorses attestation key` is the SGX attestation-key endorsement
    discipline. This axiom encodes that following the chain to
    completion produces a genuine-QE-signed quote witness.

    This is narrower than the cycle-7.3.b monolith: it only assumes
    the QE attestation chain, not the TCB-current / QE-identity-match
    gates, and not the final dstack-image-attested step. -/
axiom qe_attestation_chain_implies_signed_by_qe
    (parsed : DcapQuote) (pckLeafKey : BitVec 512) :
    legitimate_pck_leaf pckLeafKey →
    signed_by_pck_holder pckLeafKey (qeReportBytes parsed.authData.qeReport) →
    verifyAttestationKeyBinding parsed.authData.qeReport
        parsed.authData.attestationKey = true →
    verifyEcdsaP256 parsed.authData.attestationKey parsed.signedRegion
        parsed.authData.ecdsaSignature = true →
    signed_by_qe parsed

/-- **(c)-bucket assumption B (cycle 7.3.c — TEE signing → dstack)**:
    given a parsed quote signed by a genuine QE, AND the TCB level
    matches the collateral threshold (TCB is current), AND the QE
    identity matches the collateral's QE identity, AND the collateral
    is fresh, AND the raw quote bytes parse to `parsed`, then the
    raw quote bytes were signed by a dstack TEE.

    This is the second SGX-spec link: a genuine QE will only sign
    `signedRegion` bytes that correspond to a quote produced by an
    attested TEE running the dstack image (the dstack image identity
    is encoded in the MRTD / RTMRs of `parsed.body`; the deployer's
    `Collateral` constrains which TCB levels and QE identities are
    accepted).

    Narrower than the monolith: this assumes the QE attestation
    chain has already been collapsed into the `signed_by_qe`
    witness, so it only encodes the TEE-attests-dstack-image step
    plus the freshness gates. -/
axiom qe_signed_tcb_match_implies_signed_by_dstack
    (n : Nat) (q : RawBytes) (col : Collateral) (parsed : DcapQuote) :
    freshCollateral col →
    parseDcapQuote q = some parsed →
    signed_by_qe parsed →
    checkTcbLevel parsed col.tcbInfo = true →
    checkQeIdentity parsed col.qeIdentity = true →
    was_signed_by_dstack q

/-- **Derived chain link (cycle 7.3.c, was an axiom in cycle 7.3.b)**:
    the original monolithic chain link is now derived from the two
    narrower (c)-bucket assumptions above (A: QE attestation chain;
    B: TEE signing → dstack) plus the intermediate `signed_by_qe`
    witness predicate.

    Provides backward-compatible API for `dcapVerifier_sound_composed`
    which was written against the bundled form. -/
theorem verified_chain_implies_dstack_signed
    (n : Nat) (q : RawBytes) (col : Collateral) (parsed : DcapQuote)
    (pckLeafKey : BitVec 512)
    (h_fresh : freshCollateral col)
    (h_parse : parseDcapQuote q = some parsed)
    (h_legit : legitimate_pck_leaf pckLeafKey)
    (h_qe_sig : signed_by_pck_holder pckLeafKey
        (qeReportBytes parsed.authData.qeReport))
    (h_keybind : verifyAttestationKeyBinding parsed.authData.qeReport
        parsed.authData.attestationKey = true)
    (h_body_sig : verifyEcdsaP256 parsed.authData.attestationKey
        parsed.signedRegion parsed.authData.ecdsaSignature = true)
    (h_tcb : checkTcbLevel parsed col.tcbInfo = true)
    (h_qe_id : checkQeIdentity parsed col.qeIdentity = true) :
    was_signed_by_dstack q :=
  qe_signed_tcb_match_implies_signed_by_dstack n q col parsed h_fresh h_parse
    (qe_attestation_chain_implies_signed_by_qe parsed pckLeafKey
      h_legit h_qe_sig h_keybind h_body_sig)
    h_tcb h_qe_id

/-- **Soundness composition (cycle 7.3.b, derived theorem)**: a
    successful end-to-end DCAP verification of a quote `q` under fresh
    collateral `col` implies the quote was produced by a real dstack TEE.

    Now a derived theorem (not an axiom) — derives from the chain of
    named (c)-bucket assumptions by unfolding `verifyDcap` and
    applying:

    - `chain_verified_leafKey_is_legitimate` for the PCK chain walk
    - `pckLeafKey_signs_imply_signed_by_pck_holder` for the QE report
      signature under the PCK leaf
    - `verified_chain_implies_dstack_signed` for the final composition
      (attestation-key binding + quote body signature + TCB/QE gates →
      `was_signed_by_dstack`).

    The named axioms are now **load-bearing**: `#print axioms
    dcapVerifier_sound_composed` reports them in the closure (verifiable
    via `lean_verify`). Cycle 7.3.a's documented-but-unused state is
    fixed. -/
theorem dcapVerifier_sound_composed (n : Nat) (q : RawBytes) (col : Collateral) :
    freshCollateral col →
    (∃ mr ud, verifyDcap n q col = some (mr, ud)) →
    was_signed_by_dstack q := by
  intro h_fresh ⟨mr, ud, h_acc⟩
  -- Unfold verifyDcap and split on each substep's result, forcing
  -- each to its non-`none` branch via the `h_acc` hypothesis.
  unfold verifyDcap at h_acc
  -- parseDcapQuote q must return some parsed
  match h_parse : parseDcapQuote q with
  | none => rw [h_parse] at h_acc; simp at h_acc
  | some parsed =>
    rw [h_parse] at h_acc
    simp only at h_acc
    -- verifyX509Chain must return some pckLeafKey
    match h_chain : verifyX509Chain parsed.authData.certificateData col.rootCaCert with
    | none => rw [h_chain] at h_acc; simp at h_acc
    | some pckLeafKey =>
      rw [h_chain] at h_acc
      simp only at h_acc
      -- Get legitimate_pck_leaf pckLeafKey from the named axiom.
      have h_legit : legitimate_pck_leaf pckLeafKey :=
        chain_verified_leafKey_is_legitimate _ _ _ h_chain
      -- QE report signature must verify (first if-then-else).
      by_cases h_qe_sig : verifyEcdsaP256 pckLeafKey
          (qeReportBytes parsed.authData.qeReport)
          parsed.authData.qeReportSignature = true
      · -- Get signed_by_pck_holder from the named axiom.
        have h_signed : signed_by_pck_holder pckLeafKey
            (qeReportBytes parsed.authData.qeReport) :=
          pckLeafKey_signs_imply_signed_by_pck_holder _ _ _ h_legit h_qe_sig
        simp [h_qe_sig] at h_acc
        by_cases h_keybind : verifyAttestationKeyBinding parsed.authData.qeReport
            parsed.authData.attestationKey = true
        · simp [h_keybind] at h_acc
          by_cases h_body_sig : verifyEcdsaP256 parsed.authData.attestationKey
              parsed.signedRegion parsed.authData.ecdsaSignature = true
          · simp [h_body_sig] at h_acc
            by_cases h_tcb : checkTcbLevel parsed col.tcbInfo = true
            · simp [h_tcb] at h_acc
              by_cases h_qe_id : checkQeIdentity parsed col.qeIdentity = true
              · -- All checks pass. Apply the final chain link.
                exact verified_chain_implies_dstack_signed n q col parsed pckLeafKey
                  h_fresh h_parse h_legit h_signed h_keybind h_body_sig h_tcb h_qe_id
              · simp [h_qe_id] at h_acc
            · simp [h_tcb] at h_acc
          · simp [h_body_sig] at h_acc
        · simp [h_keybind] at h_acc
      · simp [h_qe_sig] at h_acc

/-- **Derived theorem (cycle 7.7, closes review finding C2/C3)**:
    `verifyDcap`'s returned `(mr, ud)` are provably functions of the
    raw input bytes — `mr` is the extraction at offset 64 width 384
    bits (the MRTD slot of TDReport10), and `ud` is the extraction at
    offset 568 width 512 bits (the `report_data` slot of TDReport10).

    The chain of trust: ECDSA-signed `signedRegion = raw.take 632`
    (cycle 7.6) implies the signer committed to the prefix; the
    parser-field axioms (`parseDcapQuote_mrTd_eq`,
    `parseDcapQuote_reportData_eq`) say the extracted `mr` and `ud`
    are derivable from that same prefix; so `was_signed_by_dstack raw`
    combined with `verifyDcap n raw col = some (mr, ud)` provably
    binds the signer's intent to the returned measurement and
    user-data fields.

    Without this binding, the cycle-7.7-review finding C3 critique
    stands: `was_signed_by_dstack q` says nothing about `(mr, ud)` so
    an adversarial parser could decouple them. With this theorem, the
    decoupling is mechanically prevented at the spec layer.

    Load-bearing in the closure of any downstream protocol theorem
    that combines `verifyTdxQuote_sound` with this output-binding
    corollary to derive measurement / user-data fixedness. Cycle 7.8
    (queued) is the cascade to thread this binding through
    `Protocol/Handshake.lean`'s `handshake_sound` and downstream. -/
theorem verifyDcap_output_bound_to_input
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    mr = (extractBitVec raw 184 384, extractBitVec raw 520 384) ∧
    (if h : n = 512 then ud = h ▸ extractBitVec raw 568 512
     else ud = BitVec.ofNat n (extractBitVec raw 568 512).toNat) := by
  intro h_acc
  -- Extract `∃ q, parseDcapQuote raw = some q` from `h_acc`.
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  -- Extract mr = composeMrEnclave q.body and ud = projectUserData n q.body
  -- from the verifyDcap = some (mr, ud) branch.
  have h_mr_ud : mr = composeMrEnclave q.body ∧ ud = projectUserData n q.body := by
    unfold verifyDcap at h_acc
    rw [h_parse] at h_acc
    simp only at h_acc
    -- Walk each guard; only the all-pass branch yields some (mr, ud).
    cases h_chain : verifyX509Chain q.authData.certificateData col.rootCaCert with
    | none => rw [h_chain] at h_acc; simp at h_acc
    | some pck =>
      rw [h_chain] at h_acc
      simp only at h_acc
      by_cases h_qe_sig : verifyEcdsaP256 pck (qeReportBytes q.authData.qeReport)
          q.authData.qeReportSignature = true
      · simp [h_qe_sig] at h_acc
        by_cases h_keybind : verifyAttestationKeyBinding q.authData.qeReport
            q.authData.attestationKey = true
        · simp [h_keybind] at h_acc
          by_cases h_body_sig : verifyEcdsaP256 q.authData.attestationKey q.signedRegion
              q.authData.ecdsaSignature = true
          · simp [h_body_sig] at h_acc
            by_cases h_tcb : checkTcbLevel q col.tcbInfo = true
            · simp [h_tcb] at h_acc
              by_cases h_qe_id : checkQeIdentity q col.qeIdentity = true
              · simp [h_qe_id] at h_acc
                exact ⟨h_acc.1.symm, h_acc.2.symm⟩
              · simp [h_qe_id] at h_acc
            · simp [h_tcb] at h_acc
          · simp [h_body_sig] at h_acc
        · simp [h_keybind] at h_acc
      · simp [h_qe_sig] at h_acc
  -- Apply field-binding axioms.
  obtain ⟨h_mr, h_ud⟩ := h_mr_ud
  refine ⟨?_, ?_⟩
  · rw [h_mr]
    unfold composeMrEnclave
    rw [parseDcapQuote_mrTd_eq raw q h_parse,
        parseDcapQuote_rtmr3_eq raw q h_parse]
  · rw [h_ud]
    unfold projectUserData
    by_cases hn : n = 512
    · simp only [hn, dif_pos]
      rw [parseDcapQuote_reportData_eq raw q h_parse]
    · simp only [dif_neg hn]
      rw [parseDcapQuote_reportData_eq raw q h_parse]

/-- **Derived theorem (cycle 7.13)**: `verifyDcap`'s output `(mr, ud)`
    is uniquely a function of the ECDSA-signed prefix `raw.take 632`.
    Composes cycle 7.6 (`signedRegion = raw.take 632`) with cycles 7.7
    / 7.9 / 7.10 (field-binding axioms for `mrTd`, `rtmr3`, `reportData`
    — all at offsets ≤ 632) via `extractBitVec_take` to argue that the
    extractions in the cycle 7.7 binding theorem could equivalently be
    computed on the prefix.

    Audit consequence: if an adversary controls only `raw[632:]`
    (the post-signed-region bytes — including the entire AuthData /
    cert chain region), the verifier's returned `(mr, ud)` is
    invariant. The auth-data fields the adversary CAN influence are
    structurally bound by the cycle 7.11 / 7.12 axioms to specific
    raw bytes, so an attacker controlling auth-data must commit to
    those specific byte positions and then face the cryptographic
    chain (ECDSA forgery, X.509 chain trust, etc.) — they cannot
    decouple the returned `(mr, ud)` from `raw.take 632`. -/
theorem verifyDcap_output_committed_by_signed_region
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    mr = (extractBitVec (raw.take 632) 184 384,
          extractBitVec (raw.take 632) 520 384) ∧
    (if h : n = 512 then ud = h ▸ extractBitVec (raw.take 632) 568 512
     else ud = BitVec.ofNat n
       (extractBitVec (raw.take 632) 568 512).toNat) := by
  intro h_acc
  obtain ⟨h_mr, h_ud⟩ := verifyDcap_output_bound_to_input n raw col mr ud h_acc
  refine ⟨?_, ?_⟩
  · rw [h_mr]
    congr 1
    · exact extractBitVec_take raw 184 384 632 (by decide)
    · exact extractBitVec_take raw 520 384 632 (by decide)
  · by_cases hn : n = 512
    · simp only [hn, dif_pos] at h_ud ⊢
      rw [h_ud]
      congr 1
      exact extractBitVec_take raw 568 512 632 (by decide)
    · simp only [dif_neg hn] at h_ud ⊢
      rw [h_ud, extractBitVec_take raw 568 512 632 (by decide)]

/-- **Derived theorem (cycle 7.18)**: `verifyDcap`'s acceptance
    implies the parsed quote's variable-offset auth-data fields
    (`qeAuthData`, `certificateData`) are functions of raw input
    bytes, with offsets and lengths threaded through parsed length
    values at raw[1218..1220].

    Combined with the cycle 7.11/7.12 fixed-offset axioms, every
    parsed `DcapQuote` field is now provably a function of `raw`.
    The cycle-7.x parser-decoupling attack surface is fully closed
    at the field level: an adversarial `parseDcapQuote` cannot set
    any output field to a value independent of the input bytes. -/
theorem verifyDcap_authData_variable_fields_bound_to_input
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    ∃ q, parseDcapQuote raw = some q ∧
      q.authData.qeAuthData =
        (raw.drop 1220).take (extractBitVec raw 1218 16).toNat ∧
      q.authData.certificateData =
        (raw.drop (1226 + (extractBitVec raw 1218 16).toNat)).take
          (extractBitVec raw (1222 + (extractBitVec raw 1218 16).toNat) 32).toNat ∧
      -- Cycle 7.20 (review H1): raw is long enough that the
      -- variable-length region didn't silently truncate via List.take.
      1226 + (extractBitVec raw 1218 16).toNat +
        (extractBitVec raw (1222 + (extractBitVec raw 1218 16).toNat) 32).toNat
        ≤ raw.length := by
  intro h_acc
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  exact ⟨q, h_parse,
    parseDcapQuote_qeAuthData_eq raw q h_parse,
    parseDcapQuote_certificateData_eq raw q h_parse,
    parseDcapQuote_authData_length_valid raw q h_parse⟩

/-- **Derived theorem (cycle 7.16)**: a successful `verifyDcap`
    accepts only quotes whose QE-report bytes (as fed to ECDSA via
    `qeReportBytes`) equal the actual raw input byte slice. Composes
    cycle 7.12 (`parseDcapQuote_qeReport_eq`) with cycle 7.16
    (`qeReportBytes_extractBitVec_eq`) to close the audit gap that
    review L1 flagged: previously, an adversarial `qeReportBytes`
    could ignore its bit-vector input.

    Audit consequence: the bytes the production ECDSA call hashes
    when verifying `qeReportSignature` against the PCK leaf are
    provably the slice `raw[770..1154]` of the input quote — not
    parser-chosen, not key-conversion-adversary chosen. -/
theorem verifyDcap_qeReportBytes_eq_raw_slice
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    ∃ q, parseDcapQuote raw = some q ∧
      qeReportBytes q.authData.qeReport = (raw.drop 770).take 384 := by
  intro h_acc
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  refine ⟨q, h_parse, ?_⟩
  rw [parseDcapQuote_qeReport_eq raw q h_parse,
      qeReportBytes_extractBitVec_eq]

/-- **Derived theorem (cycle 7.14, makes header/certType axioms
    load-bearing)**: `verifyDcap`'s acceptance implies the parsed
    quote satisfies the production parser's header gates AND the
    outer cert_type is 6. Without this corollary, the cycle 7.14
    `parseDcapQuote_header_validates` and `parseDcapQuote_certType_eq_6`
    axioms would be unused infrastructure (same dead-weight pattern
    cycle 7.7-review C1 critiqued for cycle 7.6).

    Audit consequence: a successful `verifyDcap` provably accepts only
    DCAP v4/v5 TDX quotes with ECDSA-P256 attestation key type and
    cert_type=6 (QEReportCertData) outer wrapper. Eliminates the
    parser-accepts-wrong-quote-type attack surface raised by review
    H4/H5. -/
theorem verifyDcap_implies_header_validates
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    ∃ q, parseDcapQuote raw = some q ∧
      (q.header.version = 4 ∨ q.header.version = 5) ∧
      q.header.teeType = 0x00000081 ∧
      q.header.attestationKeyType = 2 ∧
      extractBitVec raw 764 16 = (6 : BitVec 16) := by
  intro h_acc
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  obtain ⟨h_ver, h_tee, h_kty⟩ := parseDcapQuote_header_validates raw q h_parse
  exact ⟨q, h_parse, h_ver, h_tee, h_kty,
    parseDcapQuote_certType_eq_6 raw q h_parse⟩

/-- **Derived theorem (cycle 7.12)**: `verifyDcap`'s acceptance
    implies the parsed quote's `qeReport` and `qeReportSignature`
    are functions of the raw input bytes (extractions at fixed
    offsets 770 and 1154 respectively, under the DCAP v4 cert_type=6
    layout). Makes the cycle 7.12 parser-pinning axioms load-bearing
    in the audit closure.

    Combined with the cycle 7.11 `verifyDcap_authData_bound_to_input`
    theorem, all four fixed-offset AuthData fields used by the
    cryptographic substep chain (`ecdsaSignature`, `attestationKey`,
    `qeReport`, `qeReportSignature`) are now provably functions of
    the raw input. The remaining surface is only `qeAuthData` and
    `certificateData`, both at variable offsets dependent on parsed
    length fields. -/
theorem verifyDcap_qeReport_bound_to_input
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    ∃ q, parseDcapQuote raw = some q ∧
      q.authData.qeReport = extractBitVec raw 770 (384 * 8) ∧
      q.authData.qeReportSignature = extractBitVec raw 1154 512 := by
  intro h_acc
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  exact ⟨q, h_parse,
    parseDcapQuote_qeReport_eq raw q h_parse,
    parseDcapQuote_qeReportSignature_eq raw q h_parse⟩

/-- **Derived theorem (cycle 7.11)**: `verifyDcap`'s acceptance
    implies the parsed quote's `ecdsaSignature` and `attestationKey`
    auth-data fields are functions of the raw input bytes (extractions
    at fixed offsets 636 and 700 respectively). Makes the cycle 7.11
    parser-pinning axioms load-bearing in the audit closure.

    Combined with the cycle 7.7 output-binding (`mrTd`, `reportData`)
    and cycle 7.9 (`rtmr3`) extensions, this closes the fixed-offset
    portion of cycle-7.7-review finding C2: every fixed-offset field
    consumed by `verifyDcap`'s cryptographic substeps is now provably
    a function of the raw input, not parser-controlled. The remaining
    surface is the variable-length cert-data fields (`qeReport`,
    `qeReportSignature`, `qeAuthData`, `certificateData`); cycle 7.12
    queued to model the AuthData inner CertificationData layout. -/
theorem verifyDcap_authData_bound_to_input
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    ∃ q, parseDcapQuote raw = some q ∧
      q.authData.ecdsaSignature = extractBitVec raw 636 512 ∧
      q.authData.attestationKey = extractBitVec raw 700 512 := by
  intro h_acc
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  exact ⟨q, h_parse,
    parseDcapQuote_ecdsaSignature_eq raw q h_parse,
    parseDcapQuote_attestationKey_eq raw q h_parse⟩

/-- **Audit corollary (cycle 7.6)**: a successful end-to-end
    `verifyDcap` accepts only quotes whose ECDSA-verified `signedRegion`
    is provably the first 632 bytes of the input. *Available* in the
    audit-closure of downstream consumers but no Protocol-layer theorem
    cites it as of cycle 7.7 — the cycle 7.7 output-binding theorem
    above is the load-bearing parser-pinning corollary.

    Concretely: if `verifyDcap n raw col = some (mr, ud)` then there
    exists a parsed quote `q` such that `parseDcapQuote raw = some q`
    AND `q.signedRegion = raw.take 632`. The downstream ECDSA check
    `verifyEcdsaP256 q.authData.attestationKey q.signedRegion
    q.authData.ecdsaSignature` is therefore verifying a signature
    over the actual input bytes — not over an attacker-chosen
    `signedRegion` field. -/
theorem verifyDcap_signedRegion_eq_input_prefix
    (n : Nat) (raw : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    verifyDcap n raw col = some (mr, ud) →
    ∃ q, parseDcapQuote raw = some q ∧ q.signedRegion = raw.take 632 := by
  intro h_acc
  -- Extract `∃ q, parseDcapQuote raw = some q` from `h_acc`.
  have h_parse_some : ∃ q, parseDcapQuote raw = some q := by
    cases hp : parseDcapQuote raw with
    | none =>
      unfold verifyDcap at h_acc
      rw [hp] at h_acc
      simp at h_acc
    | some q => exact ⟨q, rfl⟩
  obtain ⟨q, h_parse⟩ := h_parse_some
  exact ⟨q, h_parse,
    parseDcapQuote_signedRegion_eq_input_prefix raw q h_parse⟩

/-! ## Bridge to `TdxVerifier n`

The reference verifier above produces an `Option (MrEnclave × UserData n)`
which is exactly the type of `TdxVerifier.verify`. To package it as a
`TdxVerifier n` value we also need the `sound` and `complete` fields,
which assert the cryptographic correctness of the verifier.

Those are themselves substantive theorems. Cycle 7.3 (queued) will
prove them from PCK-signature unforgeability + cert chain trust +
collateral correctness. For now we expose them as opaque lemmas so
the bridge can be constructed and consumed downstream, with the
substantive proofs deferred. -/

/-- **Soundness of verifyDcap (cycle 7.3, derived from
    `dcapVerifier_sound_composed`)**: a quote that `verifyDcap`
    accepts under fresh collateral must have been signed by a real
    dstack TEE.

    Derived from the three named (c)-bucket assumptions
    (`pckLeafKey_signs_imply_signed_by_dstack`,
    `chain_verified_leafKey_is_legitimate`,
    `dcapVerifier_sound_composed`) — the closure is honest about which
    cryptographic primitives are being assumed.

    Pending cycle 7.3.b: refine the substep return types so this
    derivation discharges the named assumptions chain-by-chain rather
    than via the bundled `_composed` axiom. -/
theorem dcapVerifier_sound (n : Nat) (q : RawBytes) (col : Collateral)
    (mr : MrEnclave) (ud : UserData n) :
    freshCollateral col →
    verifyDcap n q col = some (mr, ud) →
    was_signed_by_dstack q :=
  fun h_fresh h_acc =>
    dcapVerifier_sound_composed n q col h_fresh ⟨mr, ud, h_acc⟩

/-- **Witness predicate (cycle 7.8, addresses review H3)**: the PCK
    chain in `q` anchors to the trust roots in `col`. Operationally:
    the cert chain inside `q.authData.certificateData` walks up to
    `col.rootCaCert`, and the TCB/QE collateral in `col` corresponds
    to the FMSPC / QE identity that signed `q`. Without this
    precondition, the original cycle-7.3 `dcapVerifier_complete` axiom
    asserted "any fresh col decodes any genuine quote", which is
    cryptographically false — a quote signed against Intel's CA-A
    cannot decode against a (still fresh) collateral bundle from a
    different Intel sub-CA, FMSPC, or post-revocation chain. -/
axiom chain_anchors_to_collateral : RawBytes → Collateral → Prop

/-- **Completeness of verifyDcap (cycle 7.8, addresses review H3)**:
    a genuinely signed dstack quote whose PCK chain anchors to a fresh
    collateral bundle decodes successfully.

    The added `chain_anchors_to_collateral q col` precondition closes
    the over-strength gap raised by cycle-7.7 review H3: the previous
    `freshCollateral col → was_signed_by_dstack q → ∃ mr ud, verify ...`
    form asserted completeness against *any* fresh collateral,
    including ones whose trust roots are incompatible with the quote's
    signer chain. The corrected form binds completeness to collateral
    that actually matches the quote's anchor. -/
axiom dcapVerifier_complete (n : Nat) (q : RawBytes) (col : Collateral) :
    freshCollateral col →
    chain_anchors_to_collateral q col →
    was_signed_by_dstack q →
    ∃ mr ud, verifyDcap n q col = some (mr, ud)

-- The deployment-side anchoring axiom
-- `signed_quotes_anchor_to_production_collateral` is declared
-- below, after `productionCollateral` is in scope.

/-- **The reference DCAP-based `TdxVerifier`**: a concrete
    `TdxVerifier n` value built from `verifyDcap` plus a fresh
    collateral bundle. Replaces the bundled `axiom tdxVerifier`
    with a structurally-defined verifier modulo the cycle-7.3
    opaque soundness/completeness lemmas.

    The opaque lemmas remain the trust boundary — but they reduce
    to standard cryptographic assumptions (PCK-signature
    unforgeability, X.509 chain trust, collateral freshness)
    rather than a single bundled tdxVerifier axiom that hid all
    of them in one place.

    **Cycle 7.x adversarial finding #15 caveat**: this bridge closes
    over `h_fresh : freshCollateral col` at construction time and
    invokes it inside the `complete` field. But the consumer interface
    `TdxVerifier.complete : was_signed_by_dstack q → ∃ mr ud, ...` has
    no temporal precondition, so a caller could invoke
    `(dcapTdxVerifier n col h_fresh).complete` long after `col`
    expired. The bridge silently strengthens classical-Prop completeness
    to "fresh-at-construction implies always-complete", which is
    over-strong against cryptographic reality (TCB info has a finite
    next-update window). Documented; the dstack production flow
    rotates collateral within the next-update window, but the spec
    does not enforce that. -/
noncomputable def dcapTdxVerifier (n : Nat) (col : Collateral)
    (h_fresh : freshCollateral col)
    (h_anchors : ∀ q, was_signed_by_dstack q → chain_anchors_to_collateral q col) :
    TdxVerifier n where
  verify q := verifyDcap n q col
  sound q mr ud h_acc := dcapVerifier_sound n q col mr ud h_fresh h_acc
  complete q h_signed := dcapVerifier_complete n q col h_fresh
    (h_anchors q h_signed) h_signed

/-! ## Production-deployment value witnesses (cycle 7.5)

To allow `Dstack.lean` to derive `tdxVerifier` from `dcapTdxVerifier`
we need a canonical collateral value and a freshness witness for it.
These are exposed as opaques so the in-fork audit story is honest:
no in-Lean derivation produces a concrete Intel-issued collateral
bundle, and no in-Lean derivation can verify the next-update window
is alive at run-time. -/

/-- **Production-deployment opaque (cycle 7.5)**: a concrete
    Intel-issued collateral bundle. This is a *value-witness*
    representing the deployer's responsibility to fetch real Intel
    TCB info + QE identity at deployment time. No in-Lean reduction
    produces this value; it is a (c)-bucket assumption about a
    deployment-side artifact.

    **Adversarial finding #16 caveat**: keeping this opaque rather
    than parameterising every downstream theorem by an explicit
    `(col : Collateral)` is a tradeoff. The parameterised form
    would surface the collateral dependency at every call site
    (audit transparency win) but would require threading `col`
    through every protocol-layer theorem (substantial cascade).
    The current opaque form keeps the cascade trivial; cycle 7.6
    is queued as a candidate for parameterisation if the audit
    surface ever needs the explicit dependency. -/
axiom productionCollateral : Collateral

/-- **Production-deployment opaque (cycle 7.5)**: a freshness
    witness for `productionCollateral`. The deployer's runtime
    obligation is to rotate `productionCollateral` within the
    Intel-published next-update window so this witness remains
    truthful in real-world operation.

    Same audit caveat as `productionCollateral`: this is a
    value-witness, not a verified-by-Lean derivation. The
    cryptographic discharge target is "TCB info collateral with
    valid Intel signatures still inside its next-update window
    and no PCK revocation events since last refresh". -/
axiom productionCollateral_fresh : freshCollateral productionCollateral

/-- **Witness predicate (cycle 7.14, addresses review C2)**: the
    quote `q` was signed under the PCK chain that is currently
    anchored by `col` — i.e., the chain rotation epoch matches.
    Captures the rotation-window dependency that the cycle 7.8
    universal-anchoring axiom previously elided.

    Operationally: the Intel PCK chain rotates on FMSPC and CA-rotation
    events; a quote signed last quarter under a PCK leaf may not
    anchor to a collateral bundle fetched this quarter (post-rotation).
    `recently_signed_under_current_chain q col` asserts that the
    rotation epochs match. -/
axiom recently_signed_under_current_chain :
    RawBytes → Collateral → Prop

/-- **(c)-bucket assumption (cycle 7.8 — deployment-side anchoring,
    weakened cycle 7.14 per review C2)**: in the deployed flow,
    every quote that (i) was produced by a dstack TEE AND (ii) was
    signed under the PCK chain currently anchored by
    `productionCollateral` anchors its PCK chain to
    `productionCollateral`.

    The cycle 7.14 weakening adds the
    `recently_signed_under_current_chain` precondition that the
    cycle-7.8 universal-anchoring claim was missing. The cycle 7.8
    form asserted ALL dstack-signed quotes anchor to
    `productionCollateral`, which collapses across PCK rotation
    epochs — a quote signed last quarter against a rotated-out PCK
    chain would not anchor to this quarter's collateral. The
    weakened form is honest about the rotation dependency.

    Captures the deployment-side discipline: the deployer fetches
    collateral matching the FMSPC / Intel sub-CA the dstack image's
    TEE is currently provisioned under, and rotates it within the
    next-update window so the chain-anchoring holds for *currently
    being produced* quotes. -/
axiom signed_quotes_anchor_to_production_collateral
    (q : RawBytes) :
    was_signed_by_dstack q →
    recently_signed_under_current_chain q productionCollateral →
    chain_anchors_to_collateral q productionCollateral

/-- **Deployment-side commitment (cycle 7.14)**: the deployer takes
    responsibility for rotating `productionCollateral` such that every
    currently-signed dstack quote is `recently_signed_under_current_chain`
    against it.

    **Cycle 7.20 retraction (review H2)**: combining this axiom with
    `signed_quotes_anchor_to_production_collateral` (cycle 7.14)
    derives `∀ q, was_signed_by_dstack q → chain_anchors_to_collateral q
    productionCollateral`, which is the original cycle 7.8 axiom
    being claimed as "weakened". The cycle 7.14 framing of "two
    named commitments, not one bundled" was rhetorical; the axiom
    *closure* sums the same content. The decomposition is structural
    naming (the deployer-rotation step is visible as a named axiom
    rather than buried), not semantic narrowing.

    The honest fix (option b from the review) is to make the rotation
    invariant a hypothesis on `dcapTdxVerifier` rather than a free
    axiom, so that the deployer commitment becomes a Lean-tracked
    obligation passed into the verifier — but that requires
    restructuring `TdxVerifier.complete`'s signature to take a
    `recently_signed` precondition, which cascades through every
    downstream consumer of `verifyTdxQuote_complete`. Queued as cycle
    7.21. The current axiom-level shape is accurate-but-not-narrowing;
    auditors should read the two cycle 7.14 axioms as a single
    deployment-side trust assumption with two named components. -/
axiom productionCollateral_rotation_invariant :
    ∀ q : RawBytes,
      was_signed_by_dstack q →
      recently_signed_under_current_chain q productionCollateral

end Specs.Quartz.Attestation.DcapVerifier
