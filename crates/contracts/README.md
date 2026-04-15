# Quartz CosmWasm Packages

CosmWasm packages for building Quartz apps with TEE attestation support.

The main interface for CosmWasm developers is `quartz-contract-core`.

## Active Packages

- `quartz-contract-core` — Framework for building attestation-aware smart contracts. Wraps CosmWasm messages in `Attested<M>` with DstackAttestation (TDX quotes verified via Xion ZK module) or MockAttestation (testing).

## Legacy Packages (excluded from workspace)

The following packages were part of the original SGX architecture and are no longer compiled:

- `quartz-dcap-verifier` — Replaced by direct Xion ZK module queries
- `quartz-tee-ra` — SGX attestation types, replaced by DstackAttestation
- `quartz-tcbinfo` — TCB registry, replaced by zkdcap circuit
