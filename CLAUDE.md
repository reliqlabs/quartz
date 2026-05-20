# Quartz

Fork of informalsystems/cycles-quartz, modernized for dstack TDX + zkdcap + Xion.

## Two-agent split

This repo is worked by two agents that do not run in parallel:

- **Colosseum agent** — methodology, verification, adversarial review. Owns `.colosseum/`, `proofs/lean/`, `specs/` (the verification surface).
- **Quartz agent** — product engineering. Owns `crates/`, `examples/`, `tests/`, application logic.

The integration ledger `.colosseum/ledger.md` is the contract between them. Each agent reads its own priority section below and treats the other's as background.

## Current verification priority (Colosseum agent)

**Status: Steps 1-7 complete. Audit-ready ledger in place; awaiting external discharge paths.**

VCV-io OracleComp refactor done. Cumulative: **40 → 26 axioms (-14, ~35%)**; 8 of 8 protocol theorems lifted into probabilistic `_negl` forms with zero `sorry`, parametric over hardness hypotheses. Build at 2667 jobs, green.

- **Ledger**: `.colosseum/ledger.md` (audit-ready paragraph at the top; 26-axiom 4-bucket classification; 8-theorem lift index; cross-bundle composition map)
- **Plan archive**: `.colosseum/refactor-plan-vcvio.md` (executed)
- **Change records**: `.colosseum/changes/2026-05-13T*.md` (10 records spanning Steps 1-7)
- **What's open**:
  - External discharge of (d)-bucket axioms: ArkLib Groth16-KS reduction, reference DCAP verifier in Lean, concrete bytes/userdata hash specs. All upstream-blocked or substantial separate work.
  - 3 (a)-bucket named-constant axioms could be demoted to `def` after carrier refinement (one of the few near-term Quartz-side wins).
  - `IsPPT` predicate is currently `True`-placeholder; hardening required if/when adversaries gain oracle access.
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
