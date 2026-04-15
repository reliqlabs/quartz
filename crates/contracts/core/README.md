# quartz-contract-core

CosmWasm contract library for building attestation-aware smart contracts with Quartz.

## Features

- **`Attested<M, A>`** -- Wrapper for a message and its attestation.
- **`DstackAttestation`** -- TDX attestation type verified via the Xion ZK module. Replaces on-chain DCAP verification (no separate verifier/tcbinfo contracts needed).
- **`MockAttestation`** -- For development/testing without real TDX hardware.
- **Session management** -- Secure session between contract and enclave (see [`specs/handshake.qnt`](../../../specs/handshake.qnt)).
- **`zkdcap_vkey` config** -- Stores the Groth16 verification key for zkdcap proof verification.
- **ZK module query** -- Attestation verification via direct gRPC query to Xion's ZK module (~1M gas, down from ~5M with on-chain DCAP).

## Key Differences from Upstream

| Before | After |
|---|---|
| `DcapAttestation` calling `dcap-verifier` + `tcbinfo` contracts | `DstackAttestation` via Xion ZK module gRPC query |
| MobileCoin SGX verification libs | Removed |
| CosmWasm 2.1 | CosmWasm 3 |
| Neutron (`untrn`) | Xion (`uxion`) |

## Installation

```toml
[dependencies]
quartz-contract-core = { path = "path/to/crates/contracts/core" }
```

## Testing

Integration tests with ZK module mock via `cw_multi_test`: [`tests/integration/`](../../../tests/integration/).

```sh
cargo test
```
