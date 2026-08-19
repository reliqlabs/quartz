# Change record: zkdcap relation-hardening completion, boundary v1.3.0

- Date: 2026-08-19
- Classification: implementation-only
- Intent revision: none

## Description

zkdcap `e7002e4` closed the fourth and last step-5 relation defect by appraising TDX module identity and converging the module verdict into the published status in QVL's order. The three earlier defects closed in `2c416e5` (quote-header profile assertions, Intel's TDX component skip) and `97f6746` (descending order on the signed platform and QE tables). Quartz's consumed statement is unchanged at 21 fields / 672 bytes, so no decoder, layout, handler, or policy code changes. This change refreshes Quartz's supplier pin and retires documentation that still described the module-appraisal defect as open.

## Affected verification surface

- [x] Boundary — `.colosseum/boundaries/zkdcap--quartz.md` at v1.3.0 pins `e7002e4`, records the closed defect, and keeps production registration blocked. Landed in `7199420`.
- [x] Consumer claim text — `crates/zkdcap/src/lib.rs` replaces the "current implementation gaps" section with a relation-hardening section listing all four closed defects and their commits, and states that `extract_tcb_status` is now a module-aware verdict. Landed in `7199420`.
- [x] Agent notes — `CLAUDE.md` tracks the hardening state and names the chain blocker. Landed in `7199420`.
- [x] Changelog — `CHANGELOG.md` describes the hardening as closed rather than outstanding.
- [x] Compose — `.colosseum/ledger.md` carries the dated entry. No theorem, axiom, or coverage-count change.
- [x] Quint — NA. No invariant references the supplier pin or the appraisal gap.
- [x] Lean — NA. `Attestation/Zkdcap.lean` models the verifier abstractly and asserts nothing the boundary denies; no theorem statement or proof depends on the removed text.
- [x] Verus — NA. No annotation references the gap.
- [x] Kani — NA. `crates/zkdcap` carries a `#[cfg(kani)]` lint allowlist only, no harness.
- [x] Tests — NA. No test predicate asserts the gap. `cargo test -p quartz-zkdcap` green at 22 tests after the doc edits.

## Adversarial review

N/A — implementation-only change, no intent/spec diff. Nothing executable, no protocol model, theorem, or annotation changed.

## Ledger delta

No composition theorem added or removed. No axiom added or removed. No coverage shift. The ledger gains one dated supplier-boundary entry.

## Outstanding follow-ups

Supplier, ahead of any production key:

- dual-oracle differential corpus with a real rejection set; `zkdcap/test/qvl-differential/MANIFEST.json` still scopes itself to a single accepted vector and is not hermetic;
- content-addressed release bundle binding source, tools, ACIR, vkey bytes, raw-vkey SHA-256, field count, capacity vector and scope id;
- release-day live proof and production key registration, never reusing the `dcap-ultrahonk-v1` name or id.

Customer:

- re-pin `expected_zkdcap_vkey_sha256` from a digest read back from the target chain, then seed the per-FMSPC TCB floors and the QE floor from release-day signed collateral and rehearse on a disposable instance. Blocked on the production registration above; the scratch key on xion-testnet-2 is not an admissible pin source;
- migration versus fresh instantiation still needs an operator ruling; there is no `migrate` entry point in this tree;
- requirement 7's domain separation remains open and is a wire-format decision, not a policy toggle.
