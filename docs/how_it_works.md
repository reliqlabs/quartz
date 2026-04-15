# How It Works

Quartz establishes a secure light-client based session between a smart
contract and a TEE via a handshake protocol. This registers the TEE with the
contract and the contract with the TEE. Data is encrypted to the TEE and
submitted to the contract, and the contract controls when the TEE runs and on
what data. All communication with the TEE is done via a light-client based
round-trip with the blockchain.

The main goal is to prevent grinding or replay attacks on the TEE. All execution
on the TEE is gated by verifying light client proofs from the blockchain that
give the enclave permission to execute.

A formal specification of the handshake protocol is available in Quint:
[`specs/handshake.qnt`](/specs/handshake.qnt).

## Basic Concepts

In dstack/TDX, the enclave runs as a full confidential VM (CVM). The
measurement of the VM image serves the same role as `mr_enclave` in SGX --
it identifies the code running in the TEE.

Verifying that specific code executed on a TDX device is called remote
attestation (RA). Quartz uses **zkdcap**: the TDX attestation quote is verified
via a Groth16 zero-knowledge proof, checked on-chain through Xion's ZK module
as a direct gRPC query (~1M gas). This replaces the previous approach of
on-chain DCAP verification via two separate contracts (~5M gas).

The gnark prover generates the Groth16 proof (~5s CPU, <1s GPU), communicating
with the enclave via Unix socket.

## Handshake

The goal of the handshake is to establish:

- specific code is running on the TEE (given by a VM measurement)
- a specific TEE instance is running (given by a `nonce`)
- the TEE has a specific decryption key (given by a `pubkey`)

This is done in three steps:

1. **Instantiate** -- The contract is configured with the expected VM measurement
   and light client parameters. Requires off-chain social consensus on valid code
   (reproducible builds) and legitimate LC initialization. The `zkdcap_vkey`
   (Groth16 verification key) is also stored.

2. **SessionCreate** -- The TEE generates a nonce and produces a TDX attestation
   via `DstackAttestor` (dstack guest agent socket API). The contract verifies
   the zkdcap proof via the Xion ZK module and stores the nonce.

3. **SessionSetPubKey** -- The TEE verifies a light client proof that the nonce
   was stored, derives a key pair via `DstackKeyManager` (dstack KMS
   deterministic derivation), and attests to the nonce and pubkey. The contract
   verifies and stores the pubkey.

The TEE is now ready to process requests encrypted to the pubkey (via the ECIES
module in `quartz-enclave-core`).

## Execution

After the handshake, encrypted requests are submitted to the smart contract.
At whatever cadence defined by the contract, the TEE fetches the encrypted
requests, verifies light client proofs of the requests and the contract's
authorization, decrypts using the ECIES module, and performs computation.

The TEE attests to the results via a zkdcap proof, and optionally produces a
ZKP of the execution itself. The contract verifies both via the Xion ZK module.
