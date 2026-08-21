# Change record: testnet rehearsal, and the digest echo that does not exist

- Date: 2026-08-21
- Classification: implementation-only
- Intent revision: none

## Description

Registered a reproducible zkdcap vkey on `xion-testnet-2` and drove the Quartz consumer path against it, to rehearse the non-mock attestation route before any production key exists. The chain half works and is discriminating. The consumer half rejects everything, because `XionUltraHonkBackend` depends on a request/response digest echo that no released Xion server implements. The boundary already predicted this from a local checkout; this run confirms it against the deployed chain and pins it with regression tests.

## What was exercised

Supplier, at zkdcap `e7002e4` under the chain-pinned pair (nargo `1.0.0-beta.19`, bb `4.0.4`):

- reproducible build: ACIR 56,395,307 B; vk 3,680 B, `sha256 a9a9b7c7f4bf555623adeeabb1ace8c0becc1715a50ee53ed78fb710ddb8dbc6`, identical to the digest `e7002e4` reported, so the key is deterministic from source;
- `bb_vk_hash 17aa121b1a7439a078b9fe75390859ffcda48dedd95d0878c4e8a035cf871cc6`, a different object, confirming the substitution hazard empirically;
- registered as `zkdcap-tdx-v4-tdreport10-21-rehearsal-e7002e4`, id **26**, tx `28E4611BAD73F7EE9A16EC5AD5AEE79362C1F06D674E835AF64430A03D7520DF`, height 17667261, gas 2,068,531;
- `release_build.sh --chain-verify` recorded `"chain_verified": true`, closing the gap where the earlier scratch verify was prose the release record did not capture.

Chain behaviour, all four cases as expected:

| case | result |
|---|---|
| id 26, honest proof | `verified: true` |
| `dcap-ultrahonk-v1` (id 15, different ACIR) | `verified: false` |
| one flipped proof byte | `verified: false` |
| one flipped public-input byte | `verified: false` |

Consumer, on the real 672-byte statement (`crates/zkdcap/examples/rehearsal_decode.rs`): 21/21 fields satisfy the `pack_be` high-byte invariant; FMSPC `20a06f000000`; `tcb_status 0` (UpToDate); both evaluation numbers 18; window `20260228014618 .. 20260330004912`; the two collateral floors reject independently when either is raised one above its proven value; the status ceiling and the inclusive freshness boundaries behave.

## The finding

`XionUltraHonkBackend` sends `expected_vkey_sha256` at request tag 5 and requires the response to echo `vkey_sha256` at tag 2. `xion-testnet-2` reports `app_version: 30.0.0`, and the released `xiond-30.0.0.tar.gz` has `QueryVerifyUltraHonkRequest` stopping at tag 4 and `ProofVerifyResponse` carrying only `verified`. Neither field exists in any release; the binding lives on an unmerged branch.

Consequence: tag 5 is discarded as unknown, tag 2 returns absent, prost decodes it empty, and the accept conjunction can never hold. With a vkey configured the non-mock path rejects every proof the chain accepts. Fail-closed, so not exploitable, but a liveness failure rather than a caveat. The pre-existing unit test passes only because its mock echoes the digest.

Secondary finding: `x/zk` vkey registration is permissionless. `MsgAddVKey` has no authority check and stores the caller as the key's owner; only `UpdateParams` checks. The CLI says so: "Any account can add verification keys." This strengthens the case for pinning bytes rather than names, since a name carries no authority at all.

## Affected verification surface

- [x] Boundary — section 1 pins row now names id 26 as rehearsal-only; section 4 records the registration, the negative controls, the permissionless-registration finding, the empirical v30.0.0 confirmation, and three named ways forward.
- [x] Consumer code — two regression tests in `crates/zkdcap/src/xion.rs` pin the live-chain shape. One decodes the exact `08 01` a successful verify returns and asserts the backend's conjunction is false; it flips to failing when Xion ships verify-by-hash, which is the signal to re-enable the comparison. The other asserts tag 5 is on the wire.
- [x] Rehearsal harness — `crates/zkdcap/examples/rehearsal_decode.rs`, gated on the `accepting` feature so default `--all-targets` still builds.
- [x] Supplier tooling — zkdcap `ca90006` fixes `release_build.sh`, which had been dead since the fixture refresh (hardcoded `-timestamp 1751624163` against collateral whose `not_before` moved to 2026-02-28, dying at `der.nr:72`). Without it there was no release-day proof to verify against any key.
- [x] Quint — NA, no invariant models the chain query.
- [x] Lean — NA, `Attestation/Zkdcap.lean` models the verifier abstractly and asserts nothing about wire tags.
- [x] Verus — NA.
- [x] Kani — NA.
- [x] Tests — 28 pass in `quartz-zkdcap` across default, `xion-backend`, and `--all-features`.

## Adversarial review

N/A — implementation-only. No intent, protocol model, theorem, or annotation changed; the code change is two tests and an example.

## Ledger delta

No composition theorem, axiom, or coverage-count change. One boundary revision and one dated ledger entry.

## Outstanding follow-ups

- Decide among the three options in boundary section 4. Option 1 (ship verify-by-hash in `x/zk`) is the only one that delivers the atomic guarantee; option 2 (separate `vkey-by-name` query) is exercisable today but leaves a repoint window that must be documented where it is enforced.
- A full D1 with a real attestation is still hardware-blocked independently of the above: this rehearsal's `report_data` is an `oauth3` app's, so no dossier or Quartz binding matches it. That needs a TDX enclave producing a quote bound to a consumer tuple.
- dossier inherits the defect verbatim through its pin at Quartz `681acd3`; its `docs/status.md` remaining-work list describes the real-attestation path as hardware-blocked only, which is now incomplete.
- Release evidence still owed before any production key: rejection corpus, content-addressed release bundle, Gate B evidence record.
