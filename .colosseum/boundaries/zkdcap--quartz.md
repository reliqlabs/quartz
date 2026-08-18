# Boundary: zkdcap <-> Quartz

Colosseum boundary document, Quartz side. Records what Quartz consumes from
zkdcap, what zkdcap guarantees today, and which obligations sit on which side.

**Boundary version: 1.2.0.** Written 2026-08-17, revised 2026-08-18 for upstream
`2c416e5` and `97f6746`, which close three of the four step-5 relation defects.
Earlier revisions tracked `f51b9eb` and `1280a96`. Replaces zkdcap's deleted
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
| zkdcap revision evaluated | `97f6746` (2026-08-18) | `zkdcap` git HEAD |
| Quartz revision evaluated | `9172b74` plus this working tree | this tree |
| Upstream intent | `.colosseum/intent.md` v1.0.4-draft | states "authorizes no release" |
| Upstream canonical plan | `.colosseum/panels/2026-08-13T00-37-17-project-plan/final.md` | panel-synthesized, Path A |
| Consumed relation | monolithic `circuits/dcap-noir/crates/dcap` | `main.nr:135` returns `[Field; 21]` |
| Consumed statement | 21 fields, 672 bytes, 31-byte big-endian packing | `crates/zkdcap/src/layout.rs:36-38` |
| Release scope id | `zkdcap-tdx-v4-tdreport10-21` | `zkdcap/README.md:98`, `main.nr:3` |
| Canonical claim text | upstream README scope section + circuit header | `1280a96`, gaps list since narrowed by `97f6746` |
| Consumer requirements | nine, upstream README "Consumer requirements" | mapped in `crates/contracts/core/README.md` |
| Verification key | **none registrable yet** | see section 4 |

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

- **The vkey has changed three times in five days and changes at least once
  more.** The capacity resize (`aa8b2f9`, `TCB_INFO_CAP` 3,072 to 16,384), the
  header assertions plus component skip (`2c416e5`), and the ordering asserts
  (`97f6746`) each changed the ACIR and therefore the key; TDX-module appraisal
  is still to come. Nothing Quartz pins should be derived from this tree until
  step 11 registers a key on-chain, which is why section 4 admits only a
  chain-read digest.
- **`dcap-ultrahonk-v1` is legacy.** Plan step 11 forbids reusing that name or
  id. Quartz points at a new versioned name after step 11 registers it.

## 3. Present supplier guarantee (21-field relation, as of `97f6746`)

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

What it does **not** establish today, and which Quartz therefore must not claim:

1. **No TDX-module appraisal.** `tdxModuleIdentities` is still not parsed, so
   the merged status carries no module-level verdict of its own and the module
   table's canonical ordering is unasserted. This is the last of step 5's four
   defects; the other three closed in `2c416e5` and `97f6746`.
2. **PCK identity is by key, not by bytes.** The quote's embedded certification
   data sits outside the signed body and is private to the prover. The relation
   proves non-revocation of a supplied Intel-issued certificate whose key
   verifies the QE report. It does **not** prove byte identity with the
   certificate the machine actually emitted. The canonical plan narrows the
   claim rather than closing it, and retains dissent on that call. A consumer
   that treats the published serial as necessarily belonging to the quote's own
   chain exceeds the verified relation.
3. **No freshness.** The receipt carries no trusted clock. Freshness is
   entirely Quartz's decision against `[valid_from, valid_until]` and chain
   time.
4. **No advisory data.** The 21-field statement exposes no advisory IDs, which
   is why `max_tcb_status` is a product risk decision rather than a formality.
5. **Merged status only.** Per-component platform, module and QE statuses are
   not published separately, so `max_tcb_status` is the only status lever.
6. **A clean CRL result is not Intel's verdict.** Use of Intel's newest CRL is
   not proven and `crlNumber` monotonicity is not published. Intel states it
   "does not usually revoke platforms running software and firmware not
   mitigated against disclosed vulnerabilities" and signals TCB currency
   through status and evaluation numbers instead, so the recency floors and the
   status ceiling carry that judgement, not the revocation result. Upstream's
   source-cited basis: `zkdcap/.colosseum/research/intel-pck-revocation-scope-2026-08-13.md`.
7. **`Revoked` never receipts.** It is rejected in-circuit, so Quartz cannot
   distinguish a revoked platform from a failure to attest, and
   `verify_quote_parts`'s status ceiling only ever sees severities 0 through 5.
   Any successor relation that publishes `Revoked` instead of rejecting it
   invalidates that assumption and its comment in `crates/zkdcap/src/verifier.rs`.

Item 1 is the one remaining current implementation gap; the rest are inherent
and no implementation work removes them. Upstream deliberately separates the two
on all three claim surfaces, and Quartz's copies do the same.

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

**Do not pin from a commit message or a build artifact.** As of `97f6746` this
tree can produce three different 32-byte values that all look like the pin:
`1135db10af0fa91f4cd1b2d1f892855df8a2e290172da6a93985b4452b4f684a`, recorded in
`2c416e5`'s message and already superseded by the next commit's circuit change;
`5ebac8eb1c6a486bff7de5270f6e4677bc6e00b37a3e6e38e1558c6c759e34a4`, the SHA-256
of the stale `circuits/dcap-noir/target/dcap_full.vk` left over from a 2026-08-13
build, five days older than the current source; and the native `vk_hash` in the
sibling `.vk_hash` file, which is a different kind of object entirely. The only
admissible pin is the digest of the bytes actually registered on the target
chain, read back from the chain after step 11's registration.

## 5. Obligations by side

Supplier (zkdcap), plan steps 1 through 6 and 9 through 11:

- deterministic current-tool release runner and drift gate;
- capacity vector that fits live Intel collateral, with boundary pairs;
- quote-header assertions and TDX-module appraisal (step 5, vkey-changing);
- dual-oracle differential corpus with a real rejection set;
- content-addressed release bundle binding source, tools, ACIR, vkey bytes,
  raw-vkey SHA-256, field count, capacity vector and scope id;
- scratch-then-production key registration on the target chain, never reusing
  the legacy name or id.

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
- **[DONE 2026-08-18, partial]** the quote-profile and selection-conformance
  gaps left section 3 as `2c416e5` and `97f6746` landed; the crate docs in
  `crates/zkdcap/src/lib.rs` now name only TDX-module appraisal and record what
  closed. One more pass is due when that last defect lands, at which point the
  gap section disappears rather than becoming a permanent disclaimer;
- **[OPEN, blocked on step 11]** re-pin the vkey name and 32-byte digest, seed
  per-FMSPC TCB floors and the QE floor from the exact release-day signed
  collateral, then rehearse on a disposable instance before activation.

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
- the set of in-circuit assertions listed in section 3, since each one Quartz
  currently compensates for or disclaims;
- the registered vkey name, id, or digest;
- the capacity vector, since a capacity change is a vkey change;
- upstream's choice of Path A, which would reopen the decoder question.

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
