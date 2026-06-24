# Changelog

## Unreleased: zkdcap Noir/UltraHonk migration

Migrates on-chain attestation from gnark Groth16 to Noir/UltraHonk and extracts
the shared `quartz-zkdcap` crate so the proof checks live in one place.

### Breaking Changes

- **gnark Groth16 replaced with Noir/UltraHonk.** Attestation is verified via
  `/xion.zk.v1.Query/ProofVerifyUltraHonk`. `DstackZkAttestation` drops the
  `zkdcap_journal` field — the packed 640-byte / 20-field `public_inputs` ARE
  the journal. The CLI prover socket env is `ZKDCAP_PROVER_SOCKET` (legacy
  `GNARK_SOCKET` still read as a fallback).
- **New mandatory recency/validity checks.** The `DstackZkAttestation` handler
  now range-checks chain time against the proof's proven `[valid_from,
  valid_until]` window and rejects `tcb_eval_num` below `Config.min_tcb_eval_num`
  (new config field; defaults to 0 = no floor). The circuit has no clock/counter,
  so this is the consumer's decision.

### Features

- **`quartz-zkdcap` crate** -- canonical UltraHonk attestation primitives (packed
  `public_inputs` layout + decoders, `verify_quote`/`verify_quote_parts` with the
  recency/validity + tcb-eval checks, the Xion `ProofVerifyUltraHonk` backend).
  Application-independent; shared by `quartz-contract-core`, dossier, and
  verified-rcv so circuit/layout changes are a one-place edit.
- Noir/bb UltraHonk prover integration (`zkdcap/noir-prove-server`) via Unix socket
- Verus prototype + Quint spec updated to the UltraHonk proof shape, incl. the
  recency/eval-floor gate (Verus: 15 verified/0 errors; Quint: typecheck + run +
  Apalache verify clean)

## Earlier: dstack/TDX Modernization

Fork of [informalsystems/cycles-quartz](https://github.com/informalsystems/cycles-quartz) by Reliq Labs.

### Breaking Changes

- **Intel SGX replaced with dstack TDX.** Enclaves now run as standard Docker containers on dstack confidential VMs (Intel TDX). Gramine, SGX signing, AESM, and all MobileCoin SGX libs removed.
- **On-chain DCAP verification replaced with zkdcap.** Attestation verified via zero-knowledge proofs through the Xion ZK module (direct gRPC query). The `dcap-verifier` and `tcbinfo` contracts are no longer needed.
- **Neutron replaced with Xion.** Chain binary is now `xiond`, denom is `uxion`.
- **CosmWasm 2.1 upgraded to CosmWasm 3.**

### Features

- `DstackAttestor` -- TDX attestation via dstack guest agent socket API
- `DstackKeyManager` -- Deterministic key derivation via dstack KMS
- ECIES encryption promoted from examples to core framework module
- `zkdcap_vkey` config for ZK verification key storage
- `DstackAttestation` type with direct ZK module query verification
- Quint formal spec for handshake protocol (`specs/handshake.qnt`)
- Integration tests with ZK module mock via `cw_multi_test` (`tests/integration/`)

### Removed

- `quartz-dcap-verifier` contract
- `quartz-tcbinfo` contract
- `quartz-tee-ra` crate (MobileCoin SGX libs)
- `print-fmspc` CLI command
- Gramine enclave subcommands (configure, sign)
- `--fmspc`, `--tcbinfo-contract`, `--dcap-verifier-contract` CLI flags

---

## Release: v0.2.0

This release features a complete redesign of the enclave API (AKA Host-enclave separation) that -

- clearly separates the trusted/untrusted components of the app enclave code
- extracts more reusable code into the core enclave
- provides cleaner and more expressive abstractions

This means app devs now write up to ~20% less code.

The release also includes a new example app (called pingpong), numerous bug-fixes, API improvements, and better crate
documentation.

**Note:** this release contains multiple breaking changes.

### Features

- feat(enclave): API improvements to Store and KeyManager ([#299](https://github.com/informalsystems/quartz/pull/299))
- feat(enclave): allow app devs to define the pk type ([#297](https://github.com/informalsystems/quartz/pull/297))
- feat(enclave): add sequence number for replay protection ([#252](https://github.com/informalsystems/quartz/pull/252))
- feat(cw-client): add pay amount field to tx_execute ([#275](https://github.com/informalsystems/quartz/pull/275))
- feat(contract): Impl #[derive(UserData)] and improve
  naming ([#284](https://github.com/informalsystems/quartz/pull/284))
- feat(enclave): Host-enclave separation & redesign ([#283](https://github.com/informalsystems/quartz/pull/283))
- feat(examples): new template app ([#271](https://github.com/informalsystems/quartz/pull/271))

### Bug fixes

- fix(contract): UserData derive macro to avoid having users reimport
  stuff ([#303](https://github.com/informalsystems/quartz/pull/303))
- fix: add check for matching proof key ([#251](https://github.com/informalsystems/quartz/pull/251))
- fix(enclave): core include paths ([#257](https://github.com/informalsystems/quartz/pull/257))
- fix(enclave): proto build ([#256](https://github.com/informalsystems/quartz/pull/256))
- fix(cli): Update paths to public repo ([#258](https://github.com/informalsystems/quartz/pull/258))

### Refactor

- refactor: Remove all epoch related code ([#285](https://github.com/informalsystems/quartz/pull/285))
- refactor(enclave): remove core build.rs and copy data
  files ([#259](https://github.com/informalsystems/quartz/pull/259))

### Docs

- docs: Add comprehensive doc comments for core enclave traits, fns and
  types ([#302](https://github.com/informalsystems/quartz/pull/302))
- docs fixes ([#260](https://github.com/informalsystems/quartz/pull/260))
- Update docs ([#262](https://github.com/informalsystems/quartz/pull/262))
- Fix: Update on getting_started / tcbinfo ([#278](https://github.com/informalsystems/quartz/pull/278))
- fix(docs): checkout release version in getting_started.md ([#276](https://github.com/informalsystems/quartz/pull/276))
- fix(docs): getting started for docker and neutrond ([#264](https://github.com/informalsystems/quartz/pull/264))

### Build & CI

- build: add unsafe-trust-latest and contract-manifest
  defaults ([#292](https://github.com/informalsystems/quartz/pull/292))
- Add block pruning to neutrond docker ([#288](https://github.com/informalsystems/quartz/pull/288))
- fix: Use docker default networking
- Update docker to work on macs, update quick start ([#263](https://github.com/informalsystems/quartz/pull/263))

### Misc

- Adding props.onClose() on transfer, deposit, withdraw
  modals ([#270](https://github.com/informalsystems/quartz/pull/270))

---

## Release: v0.1.0

This is the initial release of the quartz framework and CLI.
