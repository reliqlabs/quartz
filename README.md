# Quartz

> Fork of [informalsystems/cycles-quartz](https://github.com/informalsystems/cycles-quartz), modernized for dstack TDX and zkdcap (Noir/UltraHonk).

Quartz is a framework for privacy-preserving computation via Trusted Execution
Environments (TEEs) organized and secured by smart contracts on Xion.

Encrypted data lives on-chain in CosmWasm contracts. Computation happens
privately off-chain in a dstack CVM (TDX-based confidential VM). A light-client
handshake protocol gives the contract control over enclave execution,
preventing grinding and replay attacks.

Source: [github.com/reliqlabs/quartz](https://github.com/reliqlabs/quartz)

---

WARNING: Quartz is under heavy development and not ready for production use.

---

## Architecture

- **TEE**: dstack CVM (Intel TDX). Enclaves run as standard Docker containers.
- **Attestation**: TDX quotes verified on-chain via zkdcap Noir/UltraHonk proofs through Xion's native ZK module (`ProofVerifyUltraHonk`).
- **Chain**: Xion (`xiond`, `uxion`, CosmWasm 3).
- **Prover**: Noir/bb UltraHonk via Unix socket (`zkdcap/noir-prove-server`).
- **Key management**: dstack KMS deterministic key derivation.
- **Encryption**: ECIES (secp256k1) for user-to-enclave privacy.

## Crates

- **`quartz-zkdcap`** -- Canonical UltraHonk attestation primitives: the packed `public_inputs` layout + decoders, the recency/validity + tcb-eval checks, and the Xion `ProofVerifyUltraHonk` backend. Application-independent; shared so the proof checks live in one place (also consumed by dossier and verified-rcv).
- **`quartz-contract-core`** -- CosmWasm contract library. Session management, `DstackZkAttestation` verification (built on `quartz-zkdcap`), `zkdcap_vkey` config.
- **`quartz-enclave-core`** -- Enclave-side library. `DstackAttestor`, `DstackKeyManager`, ECIES encryption, light-client proof verification.
- **`quartz` (CLI)** -- Build, deploy, handshake. Integrates `xiond` and the Noir prover.

## Specs and Tests

- Quint formal spec for the handshake protocol: [`specs/handshake.qnt`](specs/handshake.qnt)
- Integration tests with ZK module mock (cw_multi_test): [`tests/integration/`](tests/integration/)

## Docs

- [How it Works](docs/how_it_works.md) -- Handshake protocol and execution model
- [Building Applications](docs/building_apps.md) -- App development guide
- [TEE Security](docs/tees.md) -- TEE security background

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
