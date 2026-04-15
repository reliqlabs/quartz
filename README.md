# Quartz

> Fork of [informalsystems/cycles-quartz](https://github.com/informalsystems/cycles-quartz), modernized for dstack TDX and zkdcap.

Quartz is a framework for privacy-preserving computation via Trusted Execution
Environments (TEEs) organized and secured by smart contracts.

Encrypted data lives on-chain in CosmWasm contracts. Computation happens
privately off-chain in a dstack CVM (TDX-based confidential VM). A light-client
handshake protocol gives the contract control over enclave execution,
preventing grinding and replay attacks.

Source: [github.com/reliqlabs/quartz](https://github.com/reliqlabs/quartz)

---

WARNING: Quartz is under heavy development and not ready for production use.

---

## Architecture

| Component | Old (SGX) | New (dstack/TDX) |
|---|---|---|
| TEE | Intel SGX enclave | dstack CVM (Intel TDX) |
| Enclave wrapper | Gramine | Standard Docker container |
| Attestation | DCAP on-chain (5M gas, 2 contracts) | zkdcap Groth16 via Xion ZK module (1M gas, gRPC query) |
| Chain | Neutron (`neutrond`, `untrn`) | Xion (`xiond`, `uxion`) |
| CosmWasm | 2.1 | 3 |
| SGX libs | MobileCoin | Removed |
| Attestor | `DcapAttestor` (Intel SGX DCAP) | `DstackAttestor` (dstack guest agent socket API) |
| Key management | Random generation | `DstackKeyManager` (dstack KMS deterministic derivation) |
| Encryption | Example-only ECIES | Core framework ECIES module |
| Prover | N/A | gnark Groth16 (~5s CPU, <1s GPU) via Unix socket |

## Crates

- **`quartz-contract-core`** -- CosmWasm contract library. Session management, `DstackAttestation` verification via Xion ZK module, `zkdcap_vkey` config.
- **`quartz-enclave-core`** -- Enclave-side library. `DstackAttestor`, `DstackKeyManager`, ECIES encryption, light-client proof verification.
- **`quartz` (CLI)** -- Build, deploy, handshake. Integrates `xiond` and gnark prover.

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
