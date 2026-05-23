# Parallel tracks A / B / C — single-session results

- Date: 2026-05-21 (UTC)
- Tracks: A (RO migration cycle 6.22), B (Aeneas extraction experiment), C (Verus production migration — Critical 4 hook)

## Track B (Aeneas extraction experiment): conclusive negative

Ran Aeneas + Charon on two candidate crates:

**`crates/enclave/core` (failed at Charon stage)**: Hax (Charon's Rust frontend) panics on every `async fn` trait method. Affected traits include `Enclave`, `Backup`, `Export`, `Import`, `Handler`, `KeyManager`, `Store`, `GasProvider`, plus the `tonic`-generated `quartz_proto::quartz::core_server::Core`. Each panic surfaces as `region parameter 'life0/#1 out of range when instantiating args=...` in `Charon__Substitute.shift_subst`. After dozens of these panics the rustc subprocess stack-overflows and exits with SIGABRT.

**`crates/contracts/core` (Charon ✓, Aeneas ✗)**: Charon successfully translates the crate to LLBC (16 MB output, 1335 prepasses applied, 104 globals, 743 opaque functions, 522 transparent functions). Aeneas crashes during the transparent-functions translation phase at function 514 of 522, with `Uncaught exception: Not_found` in `Charon__Substitute.compose` at `charon-ml/src/Substitute.ml:12`. The trace points to a `dyn` trait reference (`TDynTrait`) substitution bug.

**Conclusion**: Aeneas as it currently stands cannot extract Quartz's Rust to Lean without upstream work in two places: (1) Hax must handle async trait methods, which is a known limitation tracked upstream and unlikely to land soon; (2) the contracts-side `Not_found` is a bug we'd need to file. Neither is actionable here. Aeneas is not a viable near-term path; Track B is closed without progress.

## Track C (Verus production migration — Critical 4 hook): partial closure landed

Round D Critical 4's production-side hook was queued in the ledger as: "decode `zkdcap_public_inputs` or `zkdcap_journal` and verify-equal the encoded `report_data` and `compose_hash` against `self.user_data` and `self.compose_hash` before returning Ok." Investigation surfaced that the journal format (`zkdcap_core::DcapJournal` at `/Users/mvid/Development/reliq/zkdcap/core/src/lib.rs:7`) exposes `report_data` directly (hex-encoded 64-byte string) but does NOT expose `compose_hash` — only `rtmr3` (48-byte SHA-384 measurement register, into which `compose_hash` is extended at dstack-vm boot).

**Landed (`crates/contracts/core/src/handler/execute/attested.rs`)**: a `verify_journal_binds_report_data` helper that JSON-decodes `self.zkdcap_journal` into a minimal `JournalReportData` struct, hex-decodes the `report_data` field, length-checks (64 bytes), and asserts byte-equality against `self.user_data`. Called immediately after the `verify_resp.verified` check in the non-mock `DstackZkAttestation::Handler` impl. Errors surface via `Error::ZkdcapVerificationFailed` with descriptive context.

Builds cleanly under:
- `cargo check -p quartz-contract-core` (default features)
- `cargo check -p quartz-contract-core --target wasm32-unknown-unknown` (wasm)
- `cargo check -p quartz-contract-core --features mock`

The full struct is not imported (would require depending on `zkdcap-core`); only the field we need is declared inline as `JournalReportData`.

**Not landed (deferred)**: the `compose_hash` ↔ `self.compose_hash` binding. This requires either:
1. A zkdcap-side change: add `compose_hash: [u8; 32]` to `DcapJournal` (clean fix, requires PR to the zkdcap repo, recompile of provers).
2. An on-chain RTMR3 extension verifier: derive expected RTMR3 from a known initial-RTMR-3 state and `self.compose_hash`, compare to `journal.rtmr3`. Expensive (SHA-384 per call), requires the initial state to be encoded in `Config`.

Either is a follow-on PR. The report_data binding alone closes the more dangerous half of Critical 4 — without it the verifier confirms an arbitrary proof, with no statement about *which* `user_data` was attested. The compose_hash binding only matters once the contract is hardened against an attacker who controls dstack image selection, which is a later threat-model layer.

## Track A (RO migration cycle 6.22.a scaffolding): documentation only, infrastructure work surfaced

Attempted to land the random-oracle simulator scaffolding alongside the existing `protocolSpecHonestSim`. Two infrastructure blockers surfaced:

1. **DecidableEq scoping**: the cycle-6.14.a `instDecidableEqUserDataCommit` `local instance` sits ~200 lines after the natural spot for RO scaffolding in `ProtocolVCVio.lean`. Lean resolves `local instance` linearly in file order, so the RO definitions can't see the DecidableEq instance.
2. **SampleableType import**: `randomOracle` requires `SampleableType (BitVec 512)`. This instance ships with VCVio via `VCVio.OracleComp.Constructions.BitVec`, which `ProtocolVCVio.lean` doesn't currently import.

Both are mechanical to resolve, but the cleanest path is a new file `Specs/Quartz/Protocol/ProtocolVCVioROModel.lean` that imports `ProtocolVCVio.lean` plus the extra VCVio deps and hosts the RO simulator + downstream theorems. That's the next concrete step but does not produce verifiable content without also landing cycle 6.22.b (the birthday-bound theorem).

**Landed in this cycle**: a documentation-only block in `ProtocolVCVio.lean` describing the cycle 6.22.a/b/c plan, the infrastructure prerequisites surfaced by the attempt, and what each sub-cycle's deliverable looks like. The block sits where the scaffolding would have lived. Future cycles can lift the documentation into actual code.

## Summary

| Track | Outcome | Artifact |
|---|---|---|
| A (RO migration) | Plan documented in-file; no scaffolding landed | `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean` (documentation block) |
| B (Aeneas) | Negative finding; not viable today | This change record |
| C (Verus C4 hook) | Partial closure (report_data binding); compose_hash binding deferred | `crates/contracts/core/src/handler/execute/attested.rs` (helper + call site) |

Net: Track C is real product progress (a security-critical missing check that the gnark verifier alone did not catch is now enforced). Track A is a design document. Track B closes an avenue cleanly.
