# Boundary: zkdcap <-> Quartz

Colosseum boundary document, Quartz side. Records what Quartz consumes from
zkdcap, what zkdcap guarantees today, and which obligations sit on which side.

**Boundary version: 1.3.0.** Written 2026-08-17, revised 2026-08-18 for upstream
`e7002e4`, which completes all four step-5 relation defects and adds a live
scratch registration. Earlier revisions tracked `f51b9eb`, `1280a96`, `2c416e5`
and `97f6746`. Replaces zkdcap's deleted
`.colosseum/boundaries/zkdcap--quartz.md` (v0.3.2), which pinned an intent
lineage that no longer exists. The upstream copy and the upstream
compose-ledger were both removed when the v0.4.0 through v0.8.10 intent lineage
was scrapped on 2026-08-06, so this file is now the only recorded form of the
contract. It lives on the Quartz side because Quartz is the party that fails if
the pin drifts.

DDD relationship pattern: **Customer / Supplier.** Quartz (customer) consumes a
versioned zkdcap statement and owns every relying-party policy and state
transition around it. zkdcap (supplier) owns the relation and the key.

## 1. Pins

| Pin | Value | Source |
|---|---|---|
| zkdcap revision evaluated | `e7002e4` (2026-08-18) | `zkdcap` git HEAD |
| Quartz revision evaluated | `9172b74` plus this working tree | this tree |
| Upstream intent | `.colosseum/intent.md` v1.0.4-draft | states "authorizes no release" |
| Upstream canonical plan | `.colosseum/panels/2026-08-13T00-37-17-project-plan/final.md` | panel-synthesized, Path A |
| Consumed relation | monolithic `circuits/dcap-noir/crates/dcap` | `main.nr:135` returns `[Field; 21]` |
| Consumed statement | 21 fields, 672 bytes, 31-byte big-endian packing | `crates/zkdcap/src/layout.rs:36-38` |
| Release scope id | `zkdcap-tdx-v4-tdreport10-21` | `zkdcap/README.md:98`, `main.nr:3` |
| Canonical claim text | upstream README scope section + circuit header | `1280a96`; its gap list is now empty, see section 3 |
| Consumer requirements | nine, upstream README "Consumer requirements" | mapped in `crates/contracts/core/README.md` |
| Verification key | rehearsal only: id 26 `zkdcap-tdx-v4-tdreport10-21-rehearsal-e7002e4` | see section 4; still not a production pin |

## 2. What the chosen architecture means for Quartz

zkdcap chose **Path A** on 2026-08-13: keep the monolithic `dcap_full` relation
and its 21-field ABI, harden the private relation, then register a new
versioned key. Path B (the 74-field frozen statement that lived in
`docs/spec/`) was rejected in part because it "forces a Quartz decoder and
contract migration".

Consequences Quartz can rely on:

- **No decoder or ABI migration.** `crates/zkdcap/src/layout.rs` stays as is.
  The recursive candidate crates and the 63-field `crates/projection-abi` codec
  remain non-gating reference material, and the 74-field statement layer was
  scrapped outright in `f51b9eb`: `docs/spec/` and the 2026-07 basis documents
  are gone (17,797 lines), leaving only `docs/prior-art.md`. Any earlier
  Quartz-side plan to migrate to a 65-field or 74-field projection is
  superseded, and the layer that would have required it no longer exists.
- **The canonical claim text is now published upstream** on three surfaces: the
  circuit header, the README scope section, and the consumer crate's module
  docs. Quartz's copy of the third lives in `crates/zkdcap/src/lib.rs`.

Consequences Quartz must absorb:

- **The vkey changed four times in five days.** Capacity resize (`aa8b2f9`),
  header assertions plus component skip (`2c416e5`), ordering asserts
  (`97f6746`), module appraisal (`e7002e4`, ACIR 41.8 MB to 56.4 MB). Each
  changed the ACIR and therefore the key, while the proof stayed 16,000 bytes and
  the statement stayed 21 fields, so nothing downstream shifted. Nothing Quartz
  pins should be derived from this tree; section 4 admits only a chain-read
  digest from the production registration.
- **The prover is pinned backward to the chain's verifier, not forward.**
  `release_build.sh` builds with nargo 1.0.0-beta.19 and bb 4.0.4 because the
  chain runs `burnt-labs/barretenberg-go` at aztec_tag v4.0.4 (xiond 29.x/30.x).
  This retires the plan's top risk, that the chain would reject bb 5.0.0-era
  bytes: the build targets what the chain runs, and the live scratch verify
  confirms the format is accepted.
- **`dcap-ultrahonk-v1` is legacy.** Plan step 11 forbids reusing that name or
  id. Quartz points at a new versioned name after step 11 registers it.

## 3. Present supplier guarantee (21-field relation, as of `e7002e4`)

What a verified receipt establishes:

- The published measurements, `report_data`, FMSPC, PCK serial, merged TCB
  status, both Intel evaluation numbers, and the validity interval came from
  one quote and its Intel-signed collateral.
- Certificate and collateral signatures chain to the compile-time pinned Intel
  SGX Root CA. Certificate, collateral and CRL validity windows are checked.
  CRL non-membership is checked.
- `[valid_from, valid_until]` is the intersection of every signed validity
  window, computed in-circuit.
- **New in `2c416e5`:** the quote's profile is authenticated, not assumed. The
  header's `version`, `attestation_key_type`, `tee_type`, reserved-byte content
  and Intel `qe_vendor_id` are asserted against the ISV-signed span, before body
  parsing. An SGX or v5 quote can no longer reach TDX body parsing.
- **New in `2c416e5`:** TCB level selection applies Intel QVL's component skip
  when `tee_tcb_svn[1] != 0`, so the selected level is the one Intel would
  select rather than dcap-qvl's. Both real captures carry `tee_tcb_svn[1] == 1`,
  so this was the live path; both still publish `UpToDate`, meaning the closed
  divergence was latent on current collateral rather than active.
- **New in `97f6746`:** the signed platform and QE tables must be strictly
  descending under QVL's own comparator, so "first satisfiable" means the same
  thing on both sides. Verified against all 44 platform levels across the 16
  captured FMSPCs before asserting: zero violations, so the assert cannot reject
  a platform that works today.
- **New in `8b33992`, `eabe577` and `e7002e4`:** TDX module identity is
  appraised. A nonzero `tee_tcb_svn[1]` selects identity `TDX_` plus its
  uppercase hex, first match wins, the level is the first with
  `module_isvsvn >= level.isvsvn`, and a missing identity or level rejects.
  MRSIGNERSEAM and SEAMATTRIBUTES are bound against the selected identity from
  the ISV-signed span. The module status converges into the verdict in QVL's
  order, platform with module first and then with QE, including the
  fall-through that leaves an already-worse platform status unchanged rather
  than taking the worse of the two. Every proof before this omitted a check that
  applied, since both real captures carry `tee_tcb_svn[1] == 1`; both still
  publish `UpToDate`, so what it closes was a latent over-favourable path.

What it does **not** establish, and which Quartz therefore must not claim. All
four of step 5's implementation defects are now closed, so every item below is
inherent to DCAP or to this ABI and no implementation work removes it:

1. **PCK identity is by key, not by bytes.** The quote's embedded certification
   data sits outside the signed body and is private to the prover. The relation
   proves non-revocation of a supplied Intel-issued certificate whose key
   verifies the QE report. It does **not** prove byte identity with the
   certificate the machine actually emitted. The canonical plan narrows the
   claim rather than closing it, and retains dissent on that call. A consumer
   that treats the published serial as necessarily belonging to the quote's own
   chain exceeds the verified relation.
2. **No freshness.** The receipt carries no trusted clock. Freshness is
   entirely Quartz's decision against `[valid_from, valid_until]` and chain
   time.
3. **No advisory data.** The 21-field statement exposes no advisory IDs, which
   is why `max_tcb_status` is a product risk decision rather than a formality.
4. **Merged status only.** Per-component platform, module and QE statuses are
   not published separately. The merged value is now module-aware, but a
   consumer still cannot tell which component drove it, so `max_tcb_status` is
   the only status lever.
5. **A clean CRL result is not Intel's verdict.** Use of Intel's newest CRL is
   not proven and `crlNumber` monotonicity is not published. Intel states it
   "does not usually revoke platforms running software and firmware not
   mitigated against disclosed vulnerabilities" and signals TCB currency
   through status and evaluation numbers instead, so the recency floors and the
   status ceiling carry that judgement, not the revocation result. Upstream's
   source-cited basis: `zkdcap/.colosseum/research/intel-pck-revocation-scope-2026-08-13.md`.
6. **`Revoked` never receipts.** It is rejected in-circuit, so Quartz cannot
   distinguish a revoked platform from a failure to attest, and
   `verify_quote_parts`'s status ceiling only ever sees severities 0 through 5.
   Any successor relation that publishes `Revoked` instead of rejecting it
   invalidates that assumption and its comment in `crates/zkdcap/src/verifier.rs`.

Upstream deliberately separates inherent limits from implementation gaps on all
three claim surfaces. The gap list is now empty; Quartz's copies say so rather
than keeping stale disclaimers.

## 4. Key and registration state

Upstream retired its consumer re-pin instruction on 2026-08-03 and recorded
that it was also wrong in kind: it named the circuit's native `Field` `vk_hash`
where Quartz reads SHA-256 over the stored verification key's bytes
(`git show 936f102`). Upstream's standing position: "No replacement pin is
published here, and none is publishable yet... Consumer re-pinning is not an
available action."

Quartz's pin is configuration, not a compiled constant
(`RawConfig::expected_zkdcap_vkey_sha256`), so re-pinning is a deployment
action. Any future re-pin instruction must name the pin's kind explicitly:
zkdcap holds at least four substitutable key-adjacent identities (stored-vkey
byte SHA-256, native `vk_hash`, schema id, release-binding digest).

Quartz keeps the digest mandatory. The handler fails closed when `zkdcap_vkey`
is configured and `expected_zkdcap_vkey_sha256` is absent, and the Xion backend
rejects a missing or mismatched digest echo.

**A rehearsal key now exists with a machine-checked chain verify, and it still
is not Quartz's pin.** `e7002e4` reported vkey
`a9a9b7c7f4bf555623adeeabb1ace8c0becc1715a50ee53ed78fb710ddb8dbc6` registered as
scratch on `xion-testnet-2`, but its release record said
`"chain_verified": "not-attempted"`, so the verify was prose only. That gap is
now closed from the other direction. A reproducible run at `e7002e4` under the
pinned pair rebuilt the identical digest, it was registered under the fresh name
`zkdcap-tdx-v4-tdreport10-21-rehearsal-e7002e4` (id **26**, tx
`28E4611BAD73F7EE9A16EC5AD5AEE79362C1F06D674E835AF64430A03D7520DF`, height
17667261), and `release_build.sh --chain-verify` recorded
`"chain_verified": true` in
`circuits/dcap-noir/target/release-2026-08-20T22-03-26Z/release-record.json`.
The digest read back from chain state matches the local build byte for byte.

Negative controls from the same session, all `{"verified":false}`: the legacy
`dcap-ultrahonk-v1` (id 15, different ACIR), a one-byte flip in the proof, and a
one-byte flip in the public inputs. So the chain's acceptance is discriminating,
not vacuous.

What that buys is bounded: the chain's verifier accepts this proof format, this
vkey encoding, and 672-byte public inputs, and the digest is reproducible from
source. It is a rehearsal name chosen to be unmistakable, not the versioned
production registration, and it does not touch the release evidence still owed
(rejection corpus, content-addressed bundle, Gate B record).

Registration itself turned out to need no authority at all. `x/zk`'s
`MsgAddVKey` has no authority check in the msg server, and `AddVKey` simply
stores the caller as the key's owner; only `UpdateParams` checks. `xiond tx zk
add-vkey --help` states it outright: "Any account can add verification keys."
The proto comment calling `authority` "the address that controls the module
(governance)" is misleading. This is the strongest argument for pinning bytes
rather than names: anyone can claim any unused name, so a name carries no
authority whatsoever, and section 4's insistence on the digest is doing the
entire job.

**Do not pin from a commit message or a build artifact.** As of `e7002e4` this
tree offers five different 32-byte values that all look like the pin:
`a9a9b7c7…` (current `vk_sha256`, prose-verified on chain as scratch);
`17aa121b1a7439a078b9fe75390859ffcda48dedd95d0878c4e8a035cf871cc6` (the same
build's `bb_vk_hash`, a different kind of object, which `release_build.sh:256-257`
labels "what bb reports" against "what Quartz pins");
`1135db10af0fa91f4cd1b2d1f892855df8a2e290172da6a93985b4452b4f684a` (`2c416e5`'s
message, superseded by the next commit); `774ae43ce498…` (the pre-hardening key,
the only one with `chain_verified: true` in a record, now three circuit changes
stale); and `5ebac8eb1c6a486bff7de5270f6e4677bc6e00b37a3e6e38e1558c6c759e34a4`
(SHA-256 of the stale `target/dcap_full.vk` from a 2026-08-13 build). The only
admissible pin is the digest of the bytes registered under the production name,
read back from the chain.

**The chain-side prerequisite does not exist in any release, so Quartz cannot
use any pin yet.** Quartz sends `expected_vkey_sha256` at request tag 5 and
requires the response to echo `vkey_sha256` at tag 2, failing closed otherwise.
Confirmed empirically 2026-08-20 rather than inferred: `xion-testnet-2` reports
`app_version: 30.0.0`, and the released `xiond-30.0.0.tar.gz` source has
`QueryVerifyUltraHonkRequest` stopping at tag 4 (`vkey_id`) with
`ProofVerifyResponse` carrying only `verified`. Neither field exists, and
`release/v31` does not add them either.

**Correction, 2026-08-21.** An earlier revision of this section said the
binding "lives only on branch `zk-ultrahonk-vkey-hash` (`e14a4ba`,
2026-07-17), contained in no tag." That branch does not exist. After fetching
all three xion remotes (`burnt-labs/xion`, `01builders/xion`,
`burnt-labs/xion-commonware`): no ref matches `vkey`/`ultrahonk`/`verify-by-hash`,
`e14a4ba` is not a valid object, `git log --all -S expected_vkey_sha256` and
`-S vkey_sha256` return nothing, and a code search finds zero hits in all three
repos and zero across every `.proto` on GitHub. The work was never pushed
anywhere, so Quartz was written against an interface that had never existed in
any repository. Cite PR #597 below, not a branch.

So tag 5 leaves as an unknown field a conformant server discards, tag 2 comes
back absent, prost decodes it as an empty `Vec`, and
`r.vkey_sha256 == expected_vkey_sha256` can never hold. With a vkey configured,
the non-mock path rejects every proof the chain accepts. Fail-closed, so not
exploitable, but a total liveness failure rather than a compatibility caveat.
The pre-existing unit test passes only because its mock echoes the digest, which
is the one behaviour no deployed server exhibits; two regression tests in
`crates/zkdcap/src/xion.rs` now pin the real shape and flip to failing the day
Xion ships verify-by-hash.

Three ways out. Option 1 is no longer hypothetical:

1. **Ship verify-by-hash in `x/zk`.** Request tag 5, response tag 2 echoing
   SHA-256 of the stored bytes. The only option that delivers the atomic
   guarantee this section claims, and it makes the consumer correct as written.
   **Now proposed: `burnt-labs/xion` PR #597** (draft, `release/v31`, branch
   `zk/ultrahonk-vkey-digest-echo`), implemented with tests, CI green. It
   deliberately implements exactly the two fields Quartz already expects, so
   landing it requires no Quartz change beyond deleting the workaround. Two
   reviewer decisions are open there: whether to digest the bare blob or a
   canonical `(id, name, proof_system, key_bytes)` tuple, and whether to also
   echo the vendored Aztec tag. Either would change the consumer contract, so
   watch that PR before re-pinning.
2. **Decouple the check.** Keep the config field, drop the echo from the accept
   condition, and re-derive the digest with a separate `VKey` or `VKeyByName`
   query. **Correction, 2026-08-21: this does NOT work against today's chain
   from a contract, and an earlier revision of this section wrongly said it
   did.** Xion gates contract-originated queries through a whitelist
   (`wasmbindings/stargate_whitelist.go`), and on the deployed `v30.0.0` tag
   only `/xion.zk.v1.Query/ProofVerify`, `ProofVerifyUltraHonk` and
   `ProofVerifyGnark` are whitelisted for `xion.zk.v1`. `Query/VKey` and
   `Query/VKeyByName` are absent, so a contract calling either gets "path is
   not allowed from the contract". Enabling this needs one
   `setWhitelistedQuery` line upstream, which is trivially bundleable into
   PR #597.

   The atomicity reasoning stands and is worth keeping separate from the
   availability problem: a CosmWasm execution is a single atomic state
   transition and every query inside it reads one consistent state view, so
   there is no repoint window between a readback and the verify. The readback
   is equivalent in strength to the echo for a contract, once it is reachable
   at all. An off-chain caller issuing two independent queries gets no such
   guarantee.
3. **Accept name-or-id trust,** with key identity enforced out of band at
   deploy time. See the decision below, which takes this option for mainnet.
   Against today's chain this is the ONLY model a contract can enforce, which
   is worth stating plainly rather than presenting it as the weakest of three
   live options.

**All three are now selectable in config, and the choice is no longer this
section's to make.** `quartz_zkdcap::VkeyTrust` names them and
`Config::vkey_trust` selects one, replacing what had been a single hard-coded
policy: the digest was an `Option` field that the handler nonetheless required,
refusing with "refusing mutable-name-only verification" when it was absent.

Three properties worth citing when reading the code rather than rediscovering:

- **Secure by default, including for state that predates the enum.** Absent
  `vkey_trust` deserializes to `Bytes` and keeps the existing digest, so an
  upgrade cannot silently loosen a deployment that never opted in.
  `legacy_state_without_the_mode_field_stays_on_bytes` pins it.
- **No silent downgrade.** A mode whose pin is missing is a refusal, not a
  fallback to whatever weaker check happens to be reachable. Likewise in the
  backend: `Bytes` accepts either the response echo or a registry readback and
  refuses when neither is available, and `Authority` refuses outright without
  the registry query.
- **The capability matrix is executable.** `VkeyTrust::is_enforceable_today`
  is parameterised on whether the chain echoes the digest and whether
  `Query/VKey` is whitelisted for contracts, so the availability facts in this
  section cannot rot into stale prose.

`NameOnly`'s builder is `with_unchecked_vkey_name_only`, named so the decision
is visible at each call site, matching the `allow_any_image` hatch beside it.

PR #597 carries both halves of what the other two modes need: the digest echo,
and a `wasmbindings` entry whitelisting `Query/VKey` and `Query/VKeyByName` for
contract queries. Until it lands and the network upgrades, `NameOnly` is the
only variant a deployed contract can actually enforce.

**Decision, 2026-08-21: pin by name or id on mainnet, with the readback held in
reserve.** Recorded because it rests on a fact about one key rather than a
property of the chain, and the distinction is load-bearing.

`UpdateVKey` and `RemoveVKey` gate on the key's STORED authority
(`x/zk/keeper/keeper.go:346` and `:406`), falling back to the gov module
address only when that field is empty. Mainnet's single registered vkey (id 1,
`Zk Email`, Groth16) has authority `xion10d07y265gmmuvt4z0w9aw880jnsr700jctf8qc`,
which is exactly the gov module account as returned by
`query auth module-account gov`. So changing that key does require a passed
proposal, and a name or id pin against it is sound.

**The condition:** that is a property of how that key was registered, not of
mainnet. `AddVKey` is permissionless on mainnet too and stores the CALLER as
the key's authority. A zkdcap production key registered from an ordinary
account would be owner-mutable, and the pin would buy nothing. To inherit
governance control the production key must itself be added via a governance
proposal, so that the message signer, and therefore the stored authority, is
the gov module account. `xiond tx zk add-vkey --from <key>` does NOT give this.
Treat it as a deployment requirement, not a default.

**Testnet does not transfer.** Rehearsal key id 26's authority is
`xion1uk6g4hjtf477zf8arl6qrq4v29k89xkjuftql3`, an ordinary account, so on
testnet the bytes under that name and id are owner-mutable at will. Rehearsal
results say nothing about the strength of a mainnet name pin.

**This is not a no-op in code.** The backend today fails closed on the absent
echo, so taking option 3 still means removing the echo comparison from the
accept condition. Until that lands or #597 does, the non-mock path verifies
nothing.

## 5. Obligations by side

Supplier (zkdcap), plan steps 1 through 6 and 9 through 11:

- **[DONE]** deterministic release runner, drift gate, and a toolchain pinned to
  the chain's verifier rather than to the newest local tools;
- **[DONE]** capacity vector that fits live Intel collateral, with boundary
  pairs;
- **[DONE `e7002e4`]** all four step-5 relation defects: header profile,
  component skip, table ordering, module appraisal with convergence;
- **[DONE, scratch only]** registration compatibility: the current key verified
  live on `xion-testnet-2` by name. Production registration under the versioned
  name is still ahead, and section 4 records why the recorded evidence is weaker
  than the commit prose;
- **[OPEN]** dual-oracle differential corpus with a real rejection set (step 6);
- **[OPEN]** content-addressed release bundle binding source, tools, ACIR, vkey
  bytes, raw-vkey SHA-256, field count, capacity vector and scope id (step 9),
  and the release-day live proof (step 10);
- **[OPEN]** production key registration, never reusing the legacy name or id
  (step 11).

Third party (Xion chain), not tracked by the plan:

- **[OPEN, blocks Quartz]** merge and release the `expected_vkey_sha256` /
  `vkey_sha256` binding, then upgrade the target network. Section 4 has the
  evidence. Nothing on either side of this boundary can substitute for it.

Customer (Quartz), plan steps 7, 8, 12 and 13:

- **[DONE 2026-08-17]** governed raise-only QE-Identity floor
  (`SetQeEvalFloor`), independent of the per-FMSPC TCB floor map;
- **[DONE 2026-08-17]** explicit platform-authorization policy.
  `SetFmspcPolicy` sets `require_registered_fmspc`, which rejects an
  unregistered FMSPC before proof verification; tighten-only, since turning it
  off would silently re-admit every unenumerated platform. Left off, the legacy
  governed global default applies. Both branches of the upstream reviewers'
  split are therefore available and tested, and the deployment picks one;
- **[DONE 2026-08-17]** claim text carries the scope id and separates inherent
  limits from current relation gaps: `crates/zkdcap/src/lib.rs` (module docs,
  the third of upstream's three surfaces) and `crates/contracts/core/README.md`
  (the nine consumer requirements mapped onto this crate, with requirement 7
  marked partial);
- **[OPEN, needs operator ruling]** migration versus fresh instantiation. There
  is no `migrate` entry point in this tree, so every successor profile requires
  a fresh instantiation or a Quartz change that adds a mutable binding set. The
  panel records this as an unresolved decision;
- **[OPEN]** requirement 7's domain separation. `user_data` is
  `SHA256(serde_json(message))`: `SessionCreate` covers the contract address
  and nonce, `SessionSetPubKey` covers only nonce and public key, and neither
  carries a chain id, action tag, or version. Closing it changes the attested
  message envelope, so it is a wire-format decision, not a policy toggle;
- **[DONE 2026-08-18]** claim surfaces track the relation. All four step-5
  defects closed across `2c416e5`, `97f6746` and `e7002e4`, so
  `crates/zkdcap/src/lib.rs` now states that the gap list is empty, lists what
  closed with commits, and tells callers who disclaimed the missing module
  appraisal to drop that disclaimer. Section 3's remaining items are inherent
  only;
- **[OPEN, blocked on step 11 and on the Xion merge]** re-pin the vkey name and
  32-byte digest, seed per-FMSPC TCB floors and the QE floor from the exact
  release-day signed collateral, then rehearse on a disposable instance before
  activation. Blocked twice over: no production key exists, and the chain cannot
  honour a digest pin yet.

The Lean surface (`proofs/lean/Specs/Quartz/Attestation/Zkdcap.lean`) models the
verifier abstractly and asserts nothing section 3 denies, but its header did
claim `dcap-ultrahonk-v1` was "the live supplier artifact", which section 4
contradicts. Corrected 2026-08-17 to name the scope id and no live key, with the
dangling boundary citations repointed at section 8. Comment text only; no
definition, axiom, or theorem changed.

## 6. Open questions upstream is waiting on Quartz to answer

These were posed in `docs/spec/80-integration.md`, which `f51b9eb` deleted along
with the rest of that layer. They are recorded here because the questions
outlived their document. Recoverable at
`zkdcap/_scrapped-spec-layer-2026-08-13.tar.gz`, which holds all ten
`docs/spec/` chapters; the durable answers below come from the upstream README
and the panel record. Both scrap archives are untracked in zkdcap, so treat the
quoted material here as the durable copy, not the tarballs.
1. **Open.** Will Quartz support a mutable set of `(profile id, vkey hash,
   schema)` bindings, or does every successor profile require re-instantiation
   or migration? v1 publishes no profile id at all, so today the question
   reduces to the migration ruling in section 5. The panel carries it as an
   unresolved decision.
2. **Answered for this profile: not applicable.** A `Revoked` converged status
   is rejected in-circuit and never receipts, which upstream now states in the
   README scope section. Quartz's status ceiling therefore only ever sees
   severities 0 through 5, and `verify_quote_parts`'s comment holds. The
   question reopens only for a successor relation that publishes `Revoked`
   instead of rejecting it, which would make the ceiling the sole gate.
3. **Answered: no.** Quartz performs no SVN-level appraisal. It consumes the
   merged status plus the two evaluation numbers, so the platform SVN fields
   stay private and no further platform facts are needed from the statement.

Plus the product rulings upstream lists as unresolved and Quartz-facing:
production `max_tcb_status`, workload authorization policy (measurement pins
versus compose-hash/event-log binding), authorized-platform set, and contract
migration versus new instance.

## 7. Re-verification triggers

Re-read this boundary and re-run the affected gates when any of these move:

- the field count or byte length of the consumed statement;
- the set of in-circuit assertions listed in section 3, since Quartz's claim text
  mirrors it and callers disclaim against it;
- the registered vkey name, id, or digest;
- the capacity vector, since a capacity change is a vkey change;
- upstream's choice of Path A, which would reopen the decoder question;
- the target chain's `x/zk` gaining the `expected_vkey_sha256` request field and
  the `vkey_sha256` response echo, which is what currently blocks any live
  non-mock attestation.

## 8. Identifiers the Quartz tree cites

Quartz source cites boundary identifiers that had no surviving definition after
`f51b9eb`. Recovered verbatim from the scrapped upstream boundary
(`zkdcap/_scrapped-spec-layer-2026-08-06.tar.gz`,
`.colosseum/boundaries/zkdcap--quartz.md`, version v0.8.10-aligned) and pinned
here so the citations resolve.

Inherited supplier assumptions:

- **K1 UltraHonk soundness.** "The release-pinned Barretenberg verifier accepts
  only proofs of the compiled Noir relation." Owned upstream by
  Barretenberg; inherited and open. Cited by
  `Attestation/Zkdcap.lean`, `Attestation/ZkdcapVCVio.lean`,
  `Attestation/DcapVerifier.lean`, `Protocol/ProtocolVCVioQuad.lean`.
- **K2 root-pin correctness.** "The circuit constant is the intended Intel SGX
  Root CA public key." A zkdcap build and audit fact, not something Quartz can
  check.
- **K8 target-relation refinement.** "The frozen circuit, witness construction,
  and ABI implement semantic R_target." Corpus evidence is scoped testing, not
  a proof. This is what `CircuitEqAdv` is indexed by, currently `R_v1`.

Quartz-side obligations. The recovered v0.8.10 list is O1 program, schema, and
manifest identity; O2 trusted-time validity and capability lifecycle; O3
independent collateral floors; O4 CRL recency and rollback; O5 relying-party
policy; O6 profile, cutover, and effect semantics. Every row was marked OPEN
there, because it described a future frozen profile that does not exist. Only two
are cited in this tree:

- **O3 independent collateral floors.** Tagged on the floor handlers, the
  `TCB_FLOORS` map, and the FMSPC policy. Satisfied in the v1 shape: two typed
  floors, governed, never merged.
- **O4 CRL recency and rollback.** Tagged in `crates/zkdcap/src/verifier.rs`.
  The v1 statement publishes no CRL identity or recency field, so the stance is
  to bound CRL lag by the authenticated `valid_until` rather than invent a
  field. Upstream's newest-CRL and `crlNumber` monotonicity limits (section 3
  item 6) are what make this a stance rather than a check.

The v0.8.10 O1 through O6 wording is not reproduced here: it is written against
that scrapped profile machinery (`ProfileTuple`, `VerifierModuleCodeIdentity`,
`FloorSourceProtocol`) which no implementation ever had, and quoting it would
re-import vocabulary the intent rewrite deliberately dropped. The short names
above are enough to resolve a citation; the recovered file is the source if more
is ever needed.

**The O-numbering is not stable across upstream lineages, and two Quartz
commits prove it.** Under the recovered v0.8.10 list, O5 is "relying-party
policy" and O6 is "profile, cutover, and effect semantics". Under the v0.3.x
list the Quartz tree was written against, `10bbfb1` closes "consumer obligation
O5 replay-rollback" and `474040d` closes "consumer obligation O6 formal-model
neutrality". Both numbers mean something else upstream now, so a reader who
resolves them against the recovered file draws the wrong conclusion twice. Cite
these by name, not by number. This is the same substitution hazard upstream
recorded for vkey pins: several similar-looking identifiers, trivially swapped
in prose.
