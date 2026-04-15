# quartz-enclave-core

Enclave-side library for Quartz applications. Mirrors `quartz-contract-core` --
this crate handles session management, attestation production, and blockchain
state verification from within the dstack CVM.

## Key Components

- **`DstackAttestor`** -- Produces TDX attestations via the dstack guest agent Unix socket API. Replaces the old SGX/Gramine DCAP attestor.
- **`DstackKeyManager`** -- Deterministic key derivation via dstack KMS. Replaces random key generation. Keys are reproducible across CVM restarts.
- **ECIES encryption module** -- Integrated encryption/decryption for enclave-contract communication. Promoted from examples to core framework.
- **Light client verification** -- Verifies Merkle and light client proofs of CosmWasm contract state, ensuring the enclave only processes authorized data.
- **Session management** -- Enclave side of the handshake protocol (see [`specs/handshake.qnt`](../../../specs/handshake.qnt)).

## Usage

```bash
cargo build --release
```

The enclave binary runs inside a standard Docker container on a dstack CVM.
No Gramine manifest or SGX signing required.
