//! Canonical Noir/UltraHonk TDX attestation verification primitives.
//!
//! This crate owns everything application-INDEPENDENT about consuming a
//! dcap-noir UltraHonk proof on-chain:
//!
//! - the packed 672-byte / 21-field `public_inputs` layout and its decoders
//!   ([`layout`]): `extract_report_data`, `extract_measurements`,
//!   `extract_cert_serial`, `extract_fmspc`, `extract_timestamp`,
//!   `extract_tcb_eval_num`, `extract_qe_eval_num`, `extract_valid_from`,
//!   `extract_valid_until`, `measurement_digest`, `build_public_inputs`,
//!   `split_attestation`/`frame_attestation`, `unix_to_packed_datetime`;
//! - the [`ProofBackend`] seam and the generic [`verify_quote`] primitive that
//!   decodes, range-checks recency/validity + independent TCB-Info and
//!   QE-Identity floors, and verifies
//!   the proof;
//! - the CosmWasm [`xion`] backend (feature `xion-backend`) that calls
//!   `/xion.zk.v1.Query/ProofVerifyUltraHonk`.
//!
//! What is NOT here, because it is inherently per-application: what the 64-byte
//! `report_data` must equal (each consumer recomputes its own domain binding),
//! and which measurements are expected (the consumer's image registry). Callers
//! compare [`DecodedQuote::report_data`] / [`DecodedQuote::measurements`]
//! against their own recomputed values.
//!
//! Shared by `quartz-contract-core`, `dossier`, and `verified-rcv` so a circuit
//! layout change or a new check is a one-place edit.
//!
//! # What a verified proof does and does not establish
//!
//! Scope id `zkdcap-tdx-v4-tdreport10-21`. A successful [`verify_quote`] means the
//! decoded values came from a v4 `TDREPORT10` quote body whose ISV signature
//! verifies under an attestation key; a QE report committing to that key, itself
//! signed by a PCK key; a certificate chain for that PCK key reaching the pinned
//! Intel SGX Root CA; Intel-signed TCB Info and QE Identity FMSPC-matched to the
//! PCK leaf; Intel-signed PCK and Root CRLs not listing the relevant serials; and
//! every certificate and collateral validity window containing the proven
//! timestamp.
//!
//! Four limits are inherent and a caller MUST NOT paper over them:
//!
//! 1. **[`extract_cert_serial`] names the certificate the proof reasoned
//!    about, not provably the one the platform presented.** The PCK chain is a
//!    prover-supplied witness bound to the platform through its KEY only; the
//!    quote's embedded chain sits outside the signed body and the QE report's
//!    `report_data` covers only the attestation key and QE auth data. Comparing
//!    this serial against a chain parsed from a caller-supplied quote proves
//!    nothing, because the same party supplies both. Measurements, FMSPC and TCB
//!    status are unaffected: Intel derives the PCK per (device, CPUSVN, PCESVN), so
//!    any substitute certifies the same key and hence the same platform and TCB
//!    level.
//! 2. **A clean CRL result is not Intel's verdict on the platform.** Intel does not
//!    usually revoke platforms merely for running unmitigated firmware, and signals
//!    TCB currency through status and evaluation numbers instead.
//!    [`extract_tcb_status`] and the two evaluation numbers carry that
//!    judgement; treat the revocation result as the narrow check it is.
//! 3. **[`extract_timestamp`] is not a hardware clock.** It is
//!    prover-selected inside the proven interval, which is why callers range-check
//!    chain time against
//!    [`extract_valid_from`]/[`extract_valid_until`] instead.
//! 4. **No advisory identity is published**, so accepting a status above
//!    `UP_TO_DATE` cannot be justified from the receipt alone.
//!
//! A `Revoked` converged status never receipts, so a caller cannot distinguish a
//! revoked platform from a failure to attest.
//!
//! # Relation hardening, distinct from the limits above
//!
//! The limits above are inherent. The relation also had four defects that were
//! not, and as of zkdcap `e7002e4` all four are closed:
//!
//! - the signed quote header's version, attestation-key type, TEE type,
//!   reserved fields and Intel QE vendor ID are asserted against the ISV-signed
//!   span, before body parsing (`2c416e5`);
//! - Intel's TDX component skip at `tee_tcb_svn[1] != 0` is applied, so level
//!   selection matches Intel QVL rather than dcap-qvl on the live path
//!   (`2c416e5`);
//! - the signed platform and QE tables must be strictly descending under QVL's
//!   comparator, so "first satisfiable" means the same on both sides
//!   (`97f6746`);
//! - TDX module identity is appraised and converged into the published verdict
//!   in QVL's order, platform with module first and then with QE, with
//!   MRSIGNERSEAM and SEAMATTRIBUTES bound against the selected identity out of
//!   the ISV-signed span (`8b33992`, `eabe577`, `e7002e4`).
//!
//! [`extract_tcb_status`] is therefore now a module-aware verdict. Callers that
//! disclaimed the missing module appraisal should drop that disclaimer.
//!
//! This does not make a key production-ready: the differential corpus, the
//! content-addressed release bundle, the release-day live proof, and the
//! production registration are all still ahead. See
//! `.colosseum/boundaries/zkdcap--quartz.md`.
//!
//! Separately, quote v5 and body types other than `TDREPORT10` are rejected.
//! That matches this scope id, but the body version is chosen by the TD Quoting
//! Enclave and changes after a TD-preserving TDX module update, so a platform
//! patched that way stops attesting until a successor profile exists.

#![forbid(unsafe_code)]

/// 32-byte hash (SHA-256 digest / measurement register low half, etc.).
pub type Hash32 = [u8; 32];

pub mod eventlog;
mod layout;
mod trust;
mod verifier;

pub use layout::*;
pub use trust::VkeyTrust;
pub use verifier::*;

#[cfg(feature = "xion-backend")]
pub mod xion;
#[cfg(feature = "xion-backend")]
pub use xion::XionUltraHonkBackend;

#[cfg(test)]
mod tests;
