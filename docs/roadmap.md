# Roadmap

Quartz is a fork of [informalsystems/cycles-quartz](https://github.com/informalsystems/cycles-quartz),
modernized for dstack TDX and zkdcap by [Reliq Labs](https://github.com/reliqlabs/quartz).

## Completed

- Intel SGX + Gramine replaced with dstack CVM (Intel TDX)
- On-chain DCAP verification replaced with zkdcap Groth16 via Xion ZK module
- Neutron chain support replaced with Xion (`xiond`, `uxion`)
- CosmWasm 2.1 upgraded to CosmWasm 3
- MobileCoin SGX libs removed
- `DstackAttestor` and `DstackKeyManager` implemented
- ECIES encryption promoted to core framework module
- gnark prover integration (Groth16, ~5s CPU, <1s GPU)
- Quint formal spec for handshake protocol (`specs/handshake.qnt`)
- Integration tests with ZK module mock (`tests/integration/`)

## Future Work

- ORAM
- Forward Secrecy (Key Rotation)
- Multi-Solvers
- Solver Decentralization and Fault Tolerance
- Multi-Verifiers of TEEs and ZKPs (defense-in-depth)
