# Quartz: Getting Started Guide

> **Note**: This guide is being updated for the dstack/TDX architecture.
> The previous SGX/Gramine/Neutron instructions below are outdated.
> The new setup uses dstack CVM (TDX), Xion chain (`xiond`), and zkdcap
> attestation verification.

## What Changed

- **No SGX hardware required.** Enclaves run as Docker containers on dstack CVMs (Intel TDX).
- **No Gramine.** No manifest files, no SGX signing, no AESM service.
- **No FMSPC/TCBInfo/DCAP contracts.** Attestation is verified via zkdcap Groth16 proofs through the Xion ZK module.
- **Xion chain** replaces Neutron. Use `xiond` and `uxion` denom.
- **gnark prover** generates Groth16 proofs for attestation verification.

## Quick Start

1. Install dependencies (Rust, Docker)
2. Clone the repository: `git clone https://github.com/reliqlabs/quartz`
3. Install Quartz: `cargo install --path crates/cli`
4. Start a local Xion node (or use testnet)
5. Run: `quartz dev` from your app directory

## Application Structure

Every Quartz application has three components:

1. **Frontend** -- User interface (e.g. Next.js)
2. **Contracts** -- CosmWasm 3 smart contract on Xion
3. **Enclave** -- Code executing privately in a dstack CVM

## Installation

### Rust

```bash
rustup target add wasm32-unknown-unknown
```

### Quartz

```bash
git clone https://github.com/reliqlabs/quartz
cd quartz
cargo install --path crates/cli
quartz --help
```

### Xion

Install `xiond` for chain interaction and key management. See Xion
documentation for setup instructions.

## Deployment

From your app directory (e.g. `examples/transfers`):

```bash
# Build and start the enclave (runs in Docker on dstack CVM)
quartz enclave build
quartz enclave start

# Build and deploy the contract
quartz contract build --contract-manifest "contracts/Cargo.toml"
quartz contract deploy --contract-manifest "contracts/Cargo.toml" --init-msg '{"denom":"uxion"}'

export CONTRACT_ADDRESS=<CONTRACT_ADDRESS>

# Establish secure session
quartz handshake --contract $CONTRACT_ADDRESS
```

## Mock Mode

For local development without TDX hardware, use the `--mock-sgx` flag
(named for historical reasons — it disables all TEE attestation):

```bash
quartz --mock-sgx enclave build
quartz --mock-sgx enclave start
quartz --mock-sgx contract deploy --contract-manifest "contracts/Cargo.toml" --init-msg '{"denom":"uxion"}'
quartz --mock-sgx handshake --contract $CONTRACT_ADDRESS
```

## Further Reading

- [How it Works](/docs/how_it_works.md)
- [Building Applications](/docs/building_apps.md)
- [Handshake spec](/specs/handshake.qnt)
- [Integration tests](/tests/integration/)
