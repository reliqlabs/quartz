# Quartz

Fork of informalsystems/cycles-quartz, modernized for dstack TDX + zkdcap + Xion.

## Current priority

Refactoring `proofs/lean/Specs/Quartz/Crypto/*` and `Specs/Quartz/Attestation/*` axioms onto VCVio's `OracleComp` framework. Goal: shrink the cryptographic trust boundary from 40 axioms to ~11 (per-module breakdown in the plan).

- **Plan**: `.colosseum/refactor-plan-vcvio.md` (read this first)
- **Methodology**: run one `colosseum-change` cycle per module, sequenced Ecies → UserDataCommit → RawMessages → Dstack → Zkdcap, then re-prove the protocol layer on the new substrate
- **Stop condition**: each module is independently shippable. Stop after each module re-proves cleanly so the human can review before moving to the next.
- **First step**: add VCV-io to `proofs/lean/lakefile.lean`, run `lake update && lake build`, confirm the dependency resolves before any theorem changes
- **Background**: see `.colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/synthesis.md` for the most recent adversarial review of the Quint spec layer (separate work; not blocked by this refactor)

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

## Pending work

- zkdcap verifier needs to migrate from circom ProofVerify to gnark ProofVerifyGnark endpoint
- Anti-sniping for BidBoard auction contract
- Register zkdcap gnark vkey on testnet (keygen tool at zkdcap/circuits/dcap-gnark/cmd/keygen/)
- IBE-based key management (commonware feat/threshold-ibe branch) — needs chain signature support in xiond

## Related repos

- `/Users/mvid/Development/reliq/zkdcap` — ZK proof compression for TDX attestation
- `/Users/mvid/Development/reliq/oauth3` — OAuth2 proxy with dstack attestation
- `/Users/mvid/Development/reliq/bidboard` — Sponsorship auction contract
- `/Users/mvid/Development/burnt/commonware` — IBE module on feat/threshold-ibe branch
- `/Users/mvid/Development/burnt/xion` — Xion chain (release/v29 has gnark ZK support)
