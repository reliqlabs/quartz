# quartz-contract-core

CosmWasm contract library for building attestation-aware smart contracts with Quartz.

## Features

- **`Attested<M, A>`** -- Wrapper for a message and its attestation.
- **`DstackAttestation`** -- TDX attestation type verified via the Xion ZK module. Replaces on-chain DCAP verification (no separate verifier/tcbinfo contracts needed).
- **`MockAttestation`** -- For development/testing without real TDX hardware.
- **Session management** -- Secure session between contract and enclave (see [`specs/handshake.qnt`](../../../specs/handshake.qnt)).
- **Pinned UltraHonk config** -- `zkdcap_vkey` selects the Xion-stored key and `expected_zkdcap_vkey_sha256` pins its exact bytes. A non-mock attestation fails closed if either is absent.
- **ZK module query** -- Attestation verification via direct gRPC query to Xion's ZK module. Quartz sends the expected key digest and requires the response digest to match, including across server downgrade attempts. The target chain must deploy those additive query fields before this path can succeed live.

## Attestation policy surface

A verified zkdcap proof is one input to policy, not the authorization result.
zkdcap states nine consumer requirements (`zkdcap/README.md`, "Consumer
requirements"); for scope `zkdcap-tdx-v4-tdreport10-21` they map onto this crate
as follows.

| Requirement | Status here |
|---|---|
| 1. Bind a versioned statement schema and the exact program identity | `Config::zkdcap_vkey` selects the Xion-stored key, `expected_zkdcap_vkey_sha256` pins its exact bytes, and both are mandatory for a non-mock attestation. v1 publishes no profile id, so the schema is bound by the `quartz-zkdcap` revision rather than by a proven field. |
| 2. Verify the proof and the canonical 21-field encoding | `quartz_zkdcap::verify_quote_parts`. |
| 3. Compare trusted block time with `[ValidFrom, ValidUntil]` | The handler passes `env.block.time`. The proof's prover-selected `Timestamp` is decoded and never used for policy. |
| 4. Enforce the TCB-Info and QE-Identity floors independently | Per-FMSPC `TCB_FLOORS` plus a contract-wide QE floor, never merged into a `min()`. Both are governed and monotonic; see below. |
| 5. Enforce every policy the selected statement supports | `Config::max_tcb_status` over the merged status, default `UpToDate` only. v1 publishes no advisory IDs and no per-component platform/module/QE statuses, so a deployment that needs advisory or per-component policy cannot get it from v1 and must wait for a successor statement. |
| 6. Pin the required workload measurements | `expected_mrtd`, `expected_rtmr0` through `expected_rtmr3`, and `expected_compose_hash` (RTMR3 event-log replay against the proof-bound register). `allow_any_image` disables image pinning and must not be set in production. |
| 7. Interpret `ReportData` through a domain-separated protocol binding | **Partial.** The handler verify-equals the proof's `report_data` against the wrapper's `user_data`, so an attacker cannot substitute the attested payload. But `user_data` is `SHA256(serde_json(message))` in the low 32 bytes: `SessionCreate` covers the contract address and nonce, while `SessionSetPubKey` covers only nonce and public key. Neither carries a chain id, an action tag, or a version, so the preimage is not domain-separated in the sense the requirement asks for. |
| 8. Choose current-state or historical-receipt semantics explicitly | Current-state only: chain time must fall inside the proven interval, so a stored receipt cannot be replayed later and no separate historical revocation policy is needed. |
| 9. Distinguish "valid at receipt time" from "secure now" | Follows from 8. The recency floors and the status ceiling are the only "secure now" levers v1 offers. |

### Governed policy messages

All three are authorized by `Config::admin`, fail closed when no admin is
configured, and refuse the loosening direction so an admin key cannot weaken
the deployment by accident.

| Message | Effect | Direction |
|---|---|---|
| `SetTcbEvalFloor` | per-FMSPC TCB-Info `tcbEvaluationDataNumber` floor in `TCB_FLOORS` | raise-only against the effective floor, so a per-FMSPC entry can never sit below the global default |
| `SetQeEvalFloor` | contract-wide QE-Identity floor on the stored config | raise-only; legacy state with no QE field is checked against the inherited TCB floor, not against zero |
| `SetFmspcPolicy` | require every attesting platform to have a registered TCB floor | tighten-only; widen the platform set with `SetTcbEvalFloor` instead |

### Platform authorization

What happens when the proof-bound FMSPC has no registered floor is an
authorization decision, not a recency one, because Intel advances
`tcbEvaluationDataNumber` fleet-wide: an unregistered platform would otherwise be
measured against the same number a registered one carries. With
`require_registered_fmspc` set, an unregistered FMSPC is rejected before the
proof is verified. Without it, the legacy global-default floor applies, which
preserves state instantiated before the map existed.

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
