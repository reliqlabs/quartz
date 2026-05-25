# Quartz

Fork of informalsystems/cycles-quartz, modernized for dstack TDX + zkdcap + Xion.

## Two-agent split

This repo is worked by two agents that do not run in parallel:

- **Colosseum agent** — methodology, verification, adversarial review. Owns `.colosseum/`, `proofs/lean/`, `specs/` (the verification surface).
- **Quartz agent** — product engineering. Owns `crates/`, `examples/`, `tests/`, application logic.

The integration ledger `.colosseum/ledger.md` is the contract between them. Each agent reads its own priority section below and treats the other's as background.

## Current verification priority (Colosseum agent)

**Status: Steps 1-7 + cycles 6.4-6.22.d.4 + cycles 7.1-7.7 complete. Cycle 7.5 (2026-05-25) demotes the bundled `axiom tdxVerifier (n : Nat) : TdxVerifier n` to a derived definition `noncomputable def tdxVerifier (n) := dcapTdxVerifier n productionCollateral productionCollateral_fresh`. Required carving shared surface (carrier types + `was_signed_by_dstack` + `TdxVerifier` struct) into new file `DstackCarriers.lean` to resolve file-dependency cycle; no downstream consumer required edits (shared namespace). `tdxVerifier` is now fully eliminated from every downstream theorem's `#print axioms` closure, replaced by the three named cryptographic (c)-bucket axioms (PCK leaf legitimacy via X.509 chain trust, ECDSA-P256 EUF-CMA on Intel's PCK key population, verified-chain → dstack-signed) plus two new deployment-side value-witnesses (`productionCollateral`, `productionCollateral_fresh`). The audit story now reads per-line: trust ECDSA-P256, trust Intel CA chain, trust the algorithm matches production wire format, trust the deployer rotates collateral. Build green at 2677 jobs (+1 for DstackCarriers); 0 new `sorry`.**

VCV-io OracleComp refactor done. Cumulative: **40 → 10 axioms (-30, -75%)**; 8 of 8 protocol theorems lifted into probabilistic `_negl` forms with zero `sorry`, parametric over hardness hypotheses. All 14 abstract carrier types refined to concrete Lean types via cycles 6.16-6.21. `IsPPT_proper` substantive PPT predicate landed (cycle 6.14.a) with per-reduction preservation lemmas (cycle 6.14.b) and parallel `_AGAINST_PPT_ADVERSARIES` packagings (cycle 6.14.c). Build at 2670 jobs, green.

- **Ledger**: `.colosseum/ledger.md` (audit-ready paragraph at the top; refreshed 10-axiom 4-bucket classification with original-26 inventory cross-reference; 8-theorem lift index; cross-bundle composition map; updated carrier refinement table)
- **Plan archive**: `.colosseum/refactor-plan-vcvio.md` (executed)
- **Change records**: `.colosseum/changes/2026-05-{13..21}T*.md` (19+ records spanning Steps 1-7 + cycles 6.4-6.21)
- **What's open**:
  - ~~**Cycle 7.5** (queued, multi-file)~~ **landed 2026-05-25**: `axiom tdxVerifier` demoted to `noncomputable def tdxVerifier := dcapTdxVerifier n productionCollateral productionCollateral_fresh`. File-dependency cycle resolved by carving `DstackCarriers.lean` out as a new third file (carriers + structure shared by both Dstack and DcapVerifier). No downstream consumer edits needed (shared namespace). Change record: `.colosseum/changes/2026-05-25T00-00-00Z-cycle-7.5-tdxverifier-demotion.md`.
  - ~~**Cycle 7.6** (queued, candidate)~~ **landed 2026-05-25**: `parseDcapQuote_signedRegion_eq_input_prefix` axiom + auxiliary corollary. Cycle 7.7 review (immediately after) found this was insufficient — only one field was pinned. Cycle 7.7 added the load-bearing field axioms.
  - ~~**Cycle 7.7** (immediate follow-up)~~ **landed 2026-05-25**: field-binding axioms for `q.body.mrTd` (extractBitVec raw 64 384) and `q.body.reportData` (extractBitVec raw 568 512), plus derived theorem `verifyDcap_output_bound_to_input` binding the returned `(mr, ud)` to functions of raw input bytes. Closes critical review findings C2/C3. Change record: `.colosseum/changes/2026-05-25T01-00-00Z-cycle-7.6-7.7-parser-field-binding.md`.
  - **Cycle 7.8** (queued): pin the auth-data fields (`attestationKey`, `qeReport`, `qeReportSignature`, `certificateData`) via additional `parseDcapQuote_*_eq` axioms. Variable-length auth-data layout requires more careful offset modelling than the fixed-offset TDReport10 fields. Closes the remainder of finding #17.
  - **Cycle 7.9** (queued): extend `MrEnclave` from `BitVec 384` (MRTD only) to a pair `(BitVec 384 × BitVec 384)` (MRTD + RTMR3) so the spec-layer `MrEnclave` matches the dstack production binding via `expected_rtmr3`. Addresses cycle-7.7 review finding M3.
  - **Cycle 7.2.c** (queued, separate libraries needed): substep implementations for ECDSA-P256, X.509 chain walking, SHA-256 attestation key binding. Require in-Lean cryptographic primitives that don't currently exist in Mathlib at sufficient detail. Could be sourced from ArkLib (P-256) once available, or implemented separately.
  - **Cycle 7.3.b** (queued): refine substep return types to carry semantic witnesses so `dcapVerifier_sound` derives chain-by-chain from the three named assumptions rather than via the bundled `_composed` axiom. Increases audit transparency without changing the closure size.
  - **ArkLib Groth16 KS reduction** (upstream-paced): cross-repo Lattice/SNARK ecosystem development for the (d)-bucket `groth16Verifier` axiom discharge. Out of in-fork control.
  - External discharge of remaining (d)-bucket axioms: ArkLib Groth16-KS reduction, reference DCAP verifier in Lean. All upstream-blocked or substantial separate work.
  - Re-adversarial review of cycles 6.13-6.21 against external voices (v0.4 Ask R recommends after canonical revisions touching load-bearing predicates).
  - This fork is the canonical destination for the verification surface. The original informalsystems/cycles-quartz upstream is unmaintained and does not carry the dstack TDX / zkdcap / Xion changes that motivate the refactor. Work lands here; no upstream contribution is planned.
- **Background**: `.colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/synthesis.md` — Quint adversarial review (closed loop, action-tag rewrite landed pre-VCVio)

### Methodology updates from verified-rcv Round 3a (2026-05-20)

Three things the Colosseum agent here may not be aware of yet. If a fresh spec-authoring or adversarial cycle starts (new spec, IsPPT hardening, axiom (a)-bucket demotion that requires a re-verify pass), prefer these patterns over the pre-Round-3a single-shot flow.

- **v0.4 methodology asks O–T** at `/Users/mvid/Development/reliq/colosseum/methodology-v0.4-candidates.md`: cross-critique as standard post-fan-out step (Ask O), defense round with defend/concede/third-option protocol (Ask P), intent-tightening on encoding-discipline as the convergence lever (Ask Q), re-cross-critique after any canonical revision touching load-bearing predicates (Ask R), ghost-variable plus state-invariant encoding for action-guard-only safety properties (Ask S), `--variant high` reasoning-effort flag as the default for spec-class adversarial dispatch (Ask T). All have direct Round 3a dogfood evidence; SKILL codification pending.
- **Dispatch infrastructure**: agents distribute as canonical-body plus per-harness wrappers. `colosseum/agents/{spec-adversary,quint-spec-generator}-body.md` is the single source of truth; per-harness wrappers live in `colosseum/agents/` (Claude Code) and `colosseum/agents/opencode/` (OpenCode); rebuild via `colosseum/scripts/install-agents.py build`. Multi-voice fan-out via opencode is the standard shape for spec-class adversarial work. Reference dispatch scripts at `verified-rcv/.colosseum/scripts/*_dispatch.py` cover fan-out, cross-critique, defense, and re-cross-critique on both Quint and Lean layers.
- **Intent-first patches**: when a finding could be fixed at intent OR spec level, patch the intent first. Downstream specs derive from it; spec-only patches let the intent rot.

## Current product priority (Quartz agent)

**Open product blockers (in approximate order of urgency):**

- **zkdcap verifier migration**: circom `ProofVerify` → gnark `ProofVerifyGnark` endpoint. Live blocker for testnet flow. See `crates/cli/src/handler/zkdcap.rs` + `tests/integration/src/zk_mock.rs` (both endpoints already mocked).
- **Register zkdcap gnark vkey on testnet**: keygen tool at `zkdcap/circuits/dcap-gnark/cmd/keygen/`.
- **Set `config.expected_rtmr3` on new deployments**: as of 2026-05-21 the `DstackZkAttestation` handler enforces `journal.rtmr3 == config.expected_rtmr3` when the field is populated. Without it, the contract is vulnerable to a "wrong-image-attestation" substitution (attacker submits a valid proof for image Y with `self.compose_hash` of image X). Compute `expected_rtmr3` once from a known-good quote of the intended dstack image and set it on instantiate. Existing deployments keep working without the field (binding skipped); new deployments should always populate it.
- **Anti-sniping for BidBoard auction contract** (separate repo at `/Users/mvid/Development/reliq/bidboard`, but the integration touches Quartz).
- **IBE-based key management**: commonware `feat/threshold-ibe` branch. Blocked on chain signature support in xiond.

The verification surface (Colosseum side) is currently quiescent — product changes that don't touch `crates/enclave/core/src/encryption.rs`, the attestor, or the key manager will not invalidate any ledger entries. Changes that do touch those should be flagged for a Colosseum-side re-verify pass.

## Build

```bash
cargo check                                          # workspace
cargo check -p quartz-contract-core --features mock   # mock mode
cargo check -p quartz-contract-core --target wasm32-unknown-unknown  # wasm

# examples (excluded from workspace)
cargo check --manifest-path examples/pingpong/enclave/Cargo.toml --features mock

# integration tests (excluded from workspace)
cd tests/integration && cargo test
cd tests/integration && cargo test testnet -- --ignored  # live testnet
```

## Architecture

- **TEE**: dstack CVM (Intel TDX). No SGX, no Gramine.
- **Attestation**: DstackAttestor → TDX quote → zkdcap Groth16 proof → Xion ZK module (`/xion.zk.v1.Query/ProofVerify` via `query_grpc()`)
- **Chain**: Xion (xiond v28+, uxion, CosmWasm 3)
- **Config**: `zkdcap_vkey` field in Config — name of the verification key registered in Xion's ZK module
- **Key management**: DstackKeyManager (dstack KMS) is default. DstackAttestor for TEE quotes.
- **Encryption**: ECIES in `quartz-enclave-core::encryption`
- **Mock mode**: `--mock` CLI flag, `mock` feature flag. Swaps DstackAttestor→MockAttestor, DstackAttestation→MockAttestation, skips ZK verification.
- **Prover**: gnark Groth16 via Unix socket (GNARK_SOCKET env var)

## Key files

- `crates/contracts/core/src/handler/execute/attested.rs` — DstackAttestation handler, ZK module query
- `crates/contracts/core/src/state.rs` — Config with zkdcap_vkey
- `crates/enclave/core/src/attestor.rs` — DstackAttestor + MockAttestor
- `crates/enclave/core/src/key_manager/dstack.rs` — DstackKeyManager
- `crates/enclave/core/src/encryption.rs` — ECIES helpers
- `crates/cli/src/handler/zkdcap.rs` — gnark prover integration
- `specs/handshake.qnt` — Quint formal spec (11 invariants)
- `tests/integration/src/zk_mock.rs` — ZK module mock (both ProofVerify and ProofVerifyGnark)

## Related repos

- `/Users/mvid/Development/reliq/zkdcap` — ZK proof compression for TDX attestation
- `/Users/mvid/Development/reliq/oauth3` — OAuth2 proxy with dstack attestation
- `/Users/mvid/Development/reliq/bidboard` — Sponsorship auction contract
- `/Users/mvid/Development/burnt/commonware` — IBE module on feat/threshold-ibe branch
- `/Users/mvid/Development/burnt/xion` — Xion chain (release/v29 has gnark ZK support)
