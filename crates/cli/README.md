# quartz CLI

CLI tool for managing Quartz applications. Handles enclave lifecycle, contract deployment, and the handshake protocol.

## Installation

```shell
cargo install --path crates/cli
```

## Commands

```
quartz [SUBCOMMAND]

SUBCOMMANDS:
    init        Create base Quartz app directory from template
    build       Build the contract and enclave binaries
    enclave     Build and start the enclave (Docker container on dstack CVM)
    contract    Build and deploy the WASM binary to Xion
    handshake   Run the handshake between the contract and enclave
    dev         Build, deploy, and handshake in one step
```

## Key Changes from Upstream

- **Chain binary**: `neutrond` replaced with `xiond` (Xion chain, `uxion` denom).
- **gnark prover**: Groth16 proof generation integrated via Unix socket (~5s CPU, <1s GPU).
- **Removed**: `print-fmspc` command (SGX-specific, not needed for TDX).
- **Removed**: Gramine enclave subcommands (`configure`, `sign`). Enclaves run as standard Docker containers.
- **Removed**: `--fmspc`, `--tcbinfo-contract`, `--dcap-verifier-contract` flags.

## App Structure

```
myapp/
├── contracts/
├── enclave/
├── frontend/
└── README.md
```

## Usage

See [Getting Started](../../docs/getting_started.md).
