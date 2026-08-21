# Change record: digest echo proposed upstream; mainnet pin decision

- Date: 2026-08-21
- Classification: implementation-only
- Intent revision: none

## Description

Two things this records. The branch the boundary cited as holding the verify-by-hash fix does not exist, so that work was unstarted rather than queued; it is now implemented and proposed as `burnt-labs/xion` PR #597. And the operator decision to pin by vkey name or id on mainnet, which is sound but for a narrower reason than it first appears, with the consumer-side readback held in reserve.

## The phantom branch

Boundary section 4 said the request/response digest binding "lives only on branch `zk-ultrahonk-vkey-hash` (`e14a4ba`, 2026-07-17), contained in no tag." It does not exist. After fetching all three xion remotes (`burnt-labs/xion`, `01builders/xion`, `burnt-labs/xion-commonware`):

- no ref matches `vkey` / `ultrahonk` / `verify-by-hash`
- `e14a4ba` is not a valid object
- `git log --all -S expected_vkey_sha256` and `-S vkey_sha256` return nothing
- code search: 0 hits in all three repos, 0 across every `.proto` on GitHub
- `release/v31` does not add the fields either

So Quartz's accept condition was written against an interface that had never existed in any repository, and "waiting for Xion" was never a plan.

## What was built

`burnt-labs/xion` PR #597, draft, base `release/v31`, branch `zk/ultrahonk-vkey-digest-echo`. Response `vkey_sha256` (tag 2) always populated on success; request `expected_vkey_sha256` (tag 5) enforced when set, with a mismatch returning `verified=false` rather than an error and a wrong length returning an error. The gate runs before any Barretenberg work. Green locally and on CI.

Scoped deliberately to exactly the two fields Quartz already expects, so landing it needs no Quartz change beyond deleting the fail-closed workaround. Two reviewer decisions are open and either would move the consumer contract: bare-blob digest versus a canonical `(id, name, proof_system, key_bytes)` tuple, and whether to echo the vendored Aztec tag. Do not re-pin until they settle.

## The mainnet decision

**Pin by name or id on mainnet; hold the readback in reserve.**

Sound, because `UpdateVKey` and `RemoveVKey` gate on the key's stored authority (`x/zk/keeper/keeper.go:346`, `:406`), and mainnet's single registered vkey (id 1, `Zk Email`, Groth16) carries authority `xion10d07y265gmmuvt4z0w9aw880jnsr700jctf8qc`, verifiably the gov module account per `query auth module-account gov`. Changing it needs a passed proposal.

**The condition that makes it hold:** this is a property of that key's registration, not of the chain. `AddVKey` is permissionless on mainnet too and stores the caller as the key's authority. A zkdcap production key registered from an ordinary account is owner-mutable, and the pin buys nothing. To inherit governance control the production key must itself be added through a governance proposal, so the signer, and therefore the stored authority, is the gov module account. `xiond tx zk add-vkey --from <key>` does not do this. Deployment requirement, not a default.

**Testnet transfers nothing.** Rehearsal key id 26's authority is `xion1uk6g4hjtf477zf8arl6qrq4v29k89xkjuftql3`, an ordinary account, so its bytes are owner-mutable at will.

**Still not a no-op in code.** The backend fails closed on the absent echo today, so taking this option means removing the echo comparison from the accept condition. Until that or #597 lands, the non-mock path verifies nothing.

## Correction carried forward

An earlier record called the readback non-atomic and warned of a repoint window between the readback and the verify. That is wrong for a contract consumer: a CosmWasm execution is a single atomic state transition and every query inside it reads one consistent state view, so no transaction can interleave. The readback is equivalent in strength for a contract, and weaker only for an off-chain caller issuing two independent queries.

## Affected verification surface

- [x] Boundary section 4 — the phantom-branch correction, option 1 repointed at PR #597, the recorded decision with its condition, and the readback correction.
- [x] Ledger — dated entry.
- [x] dossier `docs/status.md` — inherits the same condition, since it is the other consumer of this backend.
- [x] Quint / Lean / Verus / Kani / tests — NA. No executable Quartz behaviour changed here; the two regression tests pinning the live-chain shape landed in `21b0d000`.

## Adversarial review

N/A — implementation-only. Documentation and an upstream proposal; no intent, model, theorem, or annotation moved.

## Ledger delta

No composition theorem, axiom, or coverage change.

## Outstanding follow-ups

- Watch PR #597's two design decisions before any re-pin.
- If #597 stalls, implement the readback; it is unblocked and needs no chain change.
- The production key must be registered via governance proposal, or the mainnet name/id pin is void.
- Independent of all of the above: v31 moves Barretenberg to v5.2.0, which invalidates keys minted under bb 4.0.4, including rehearsal id 26. No upgrade height is scheduled on `xion-testnet-2` yet.
