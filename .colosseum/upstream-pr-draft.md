# Upstream PR draft: VCV-io OracleComp refactor + Verus prototype hardening

Target: `informalsystems/cycles-quartz`
Author: reliqlabs/quartz (forked + modernized for dstack TDX + zkdcap + Xion)
Date drafted: 2026-05-20
Status: ready for review

## Summary

This PR lands a multi-week verification refactor across the Lean and Verus surfaces of cycles-quartz. The Lean tree migrates the eight protocol-layer theorems from classical-Prop forms (carrying four bundled cryptographic axioms with over-strength shapes) into probabilistic `_negl` forms parametric over hardness hypotheses, dropping the axiom count from 40 to 26 (-35 percent) while introducing zero `sorry`s. The Verus prototype tree under `crates/{contracts,enclave}/core/verus-prototype/` is hardened against five critical findings surfaced by a 7-voice multi-model adversarial review (Round D, 2026-05-14/15) and a follow-up 6-voice cross-critique pass (2026-05-20). Build remains green: `lake build` at 2667 jobs, `verus` at 46 verified 0 errors across the prototype tree, all CI workflows passing.

Two follow-up scopes are explicitly called out in the "Known follow-up work" section below rather than blocking this PR. Both have concrete implementation paths recorded in the ledger; neither affects the trust claims of the surface this PR ships.

## What changed

### Lean (VCV-io OracleComp refactor)

The pre-refactor trust boundary carried 40 axioms across five carrier modules (`Ecies`, `UserDataCommit`, `RawMessages`, `Dstack`, `Zkdcap`) and the protocol layer. The eight protocol theorems (`handshake_sound`, `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`, `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`, `cross_component_session_bind`, `verifyGroth16_yields_decoded`) carried classical-Prop conclusions resting on four bundled `(d)`-bucket cryptographic axioms with over-strength shapes (deterministic-injectivity claims on fixed-width hashes that pigeonhole forbids, classical-Prop verifier-soundness implications dropping computational-soundness qualifiers).

The refactor proceeds in seven steps:

Steps 1-5 (form-phase axiom reduction): re-bucket each axiom into one of four classifications (demotable-to-def-or-dead / demotable-to-derived-theorem / honest-computational-assumption / impossibility-or-over-strength), then discharge the demotable ones. Net reduction is 40 to 26 axioms, with three `(a)`-bucket named constants remaining as the only near-term Quartz-side win pending carrier refinement.

Step 6 (content-phase def-tying): lift each of the eight protocol theorems into a probabilistic `_negl` form whose advantage is a `Pr[…]`-based `def` (not a free function symbol), whose pointwise bound is proven (not assumed) via `probEvent_mono` + `probEvent_bind_pure_comp`, and whose bundle structure matches the classical proof's actual probabilistic-failure-mode count (not an inflated axiom-count classification). The sequence runs cycles 6.4 through 6.11, with the terminal lift (`cross_component_session_bind_negl`) reduced from a 5-summand union bound to a single Groth16-soundness probabilistic-failure mode under the current carrier model.

Step 6.12 (IsPPT placeholder rename): the seven `*Game_secure_of_*_bundle_secure` packagings are renamed to `*_AGAINST_UNBOUNDED_ADVERSARIES` with explicit docstrings about the placeholder gap. The `IsPPT` predicate remains a `True`-placeholder pending oracle-access adversary types (Round A attack #5, surface-side closure via Option (b)). The substantive `IsPPT := PolyQueries` instantiation is queued behind cycle 6.13 (`OracleComp ProtocolSpec` wiring).

Step 7 (audit-ready ledger): the integration ledger at `.colosseum/ledger.md` records the 26-axiom 4-bucket classification, the 8-theorem lift index, the cross-bundle composition map for the terminal lift, and the per-tool coverage snapshot. The ledger paragraph is intended as the spine of this PR description.

### Verus prototype hardening (Round D + cross-critique)

The Verus prototypes under `crates/contracts/core/verus-prototype/` and `crates/enclave/core/verus-prototype/` (six files, 1431 lines) are feasibility specs over a `cw_storage_plus` + `cosmwasm-std` stub layer. A 7-voice adversarial fan-out (Round D, 2026-05-14/15) surfaced 30 distinct attacks after dedup, with five flagged as critical. A 6-voice cross-critique (2026-05-20) ratified four of the five and refined the fifth.

The fix sequence:

Critical 1 (commit `ec24934`): `signing_key_bytes_roundtrip_axiom` was unsound. The axiom had `requires true` and was applied at `import_export_roundtrip` with bare unbound parameters, concluding `verifying_key_spec(decoded) == verifying_key_spec(sk)` for any triple. This forced `verifying_key_spec` to be constant, admitting derivation of `false`. The fix introduces two uninterpreted spec functions (`signing_key_to_bytes_spec`, `signing_key_from_slice_spec`), adds `ensures` clauses on the exec wrappers tying their results to those spec functions, and tightens the axiom's `requires` to bind the parameters non-trivially.

Critical 2 (commit `832fb2e`): `session_set_pub_key.rs` did not model the `SEQUENCE_NUM` reset. Production `SessionSetPubKey::handle` writes `SEQUENCE_NUM.save(.., Uint64::new(0))` after the session save as the replay-protection foundation for every downstream `Sequenced<T>` handler. The fix adds `sequence_num: Option<u64>` to the prototype's `Storage` struct, introduces a `SequenceNumItem` mirroring production's `SEQUENCE_NUM`, extends the handler's Ok postcondition with `final(storage).sequence_num == Some(0)`.

Critical 3 (commit `a6232c3`): the prototype's docstring promised a compensating `concrete_att_handle_maybe_err` external_body variant for inner-handler error propagation but the variant did not exist in the file. The fix adds `ConcreteAtt::handle_maybe_err` plus a new wrapper variant `attested_handle_with_fallible_att` that uses it. Verus's verification of the new wrapper IS the inner-handler error propagation theorem. Both wrappers' catch-all `Err(_)` arms tightened to witness the user_data pre-check held.

Critical 4 Verus side (commit `3267015`, ratified 5-of-5 DEFEND in cross-critique): production `DstackZkAttestation::handle` forwards `zkdcap_proof` and `zkdcap_public_inputs` to the gnark verifier with no equality check binding the proof's public inputs back to the wrapper-validated `user_data` and `compose_hash`. An attacker can submit a valid Groth16 proof for enclave A while self-declaring `user_data` and `compose_hash` matching enclave B; the wrapper's pre-checks pass against the self-declared fields, the verifier accepts the proof against the supplied public inputs, and the contract accepts. The Verus side fix adds a `proof_journal_binds` uninterpreted predicate, a `verify_proof_journal_binds` external_body verification step, and tightens the `dstack_zk_handle` Ok postcondition to require both gnark-verifier acceptance and the binding. The production-side fix is queued (see "Known follow-up work" below).

Critical 5 cheap fix (commit `3267015`, refined 3-of-5 THIRD_OPTION in cross-critique): the named theorem `pub_key_matches_sk` was a propositional tautology of the form `forall k. f(k.sk) == f(k.sk)`, contributing nothing. The fix deletes the tautology and replaces it with a docstring redirect to where the actual snapshot binding contract lives (the `pub_key` exec function's `ensures`). The substantive Critical 5 remediation is a follow-up cycle (see below).

Verification across the prototype tree: 46 verified, 0 errors total (attested 14, instantiate 8, session_create 6, session_set_pub_key 7, encryption 6, key_manager 4).

## Methodology trail

The verification claims rest on the adversarial-review trail recorded under `.colosseum/attacks/`. Round A (2026-05-14) ran a multi-model attack on the eight Lean `_negl` lifts and surfaced 12 attacks across two arms (Claude file-access, Gemma local). Cycles 6.4-6.11 are the structured response. Round B (2026-05-14) attacked two recently-revised Quint specs (`sealed-auction`, `ranked-choice`) and surfaced a critical tie-break inversion in `find_loser` that was fixed pre-merge. Round C (2026-05-14) attacked four previously-unattacked Quint specs (handshake, attestation, pingpong, transfers) and surfaced three criticals; the docstring-honesty fixes and the strict-monotone replay invariant landed in the same commit. Round D (2026-05-14/15) attacked the Verus prototype tree with 7 voices and surfaced five criticals. The Round D cross-critique pass (2026-05-20, 6 voices, cloud-only) ratified Critical 4 and refined Critical 5 before commit.

Per-round synthesis documents and per-voice reports persist verbatim under `.colosseum/attacks/`. The methodology repository at `/Users/mvid/Development/reliq/colosseum/` is dogfood-validated by this work and tracks v0.4 ask candidates surfaced here.

## Known follow-up work (called out, not blocking this PR)

Critical 4 production-side. The Verus spec now requires `proof_journal_binds` on the Ok branch, but the production handler at `crates/contracts/core/src/handler/execute/attested.rs:94-99` does not yet enforce it. The production handler must decode `zkdcap_public_inputs` (or the existing-but-unused `zkdcap_journal` field surfaced by GPT-5.5 in cross-critique) and verify-equal the encoded `report_data` and `compose_hash` against `self.user_data` and `self.compose_hash` before returning Ok. The gnark circuit at `zkdcap/circuits/dcap-gnark/circuit/types.go:100-107` already exposes `MrTd`, `RTMRs`, and `ReportData` as public inputs, so the cryptography is sound; the gap is purely at the on-chain wrapper layer. This is a Quartz-agent follow-up per the two-agent split in `CLAUDE.md:5-12`.

Critical 5 substantive remediation. The cross-critique synthesis records a four-part plan: model `DefaultKeyManager` import as a mutating operation, model `DstackKeyManager` (production default per `CLAUDE.md`, currently unmodeled per Round D Critical 19), add a session-lifecycle ghost layer with a `contract_pub_key` field and invariants tying it to `km.sk` across state transitions, and decide production key-rotation policy (remove `Import` impls vs. add a `session_rotate_pub_key` contract message). This is a Colosseum-agent follow-up cycle, scoped at `.colosseum/attacks/verus-prototype-cross-critique-2026-05-20/synthesis.md`.

External discharge of `(d)`-bucket axioms. The Lean `_negl` lifts are parametric over hardness hypotheses on five primitives: ArkLib Groth16 knowledge-soundness coverage (upstream roadmap), a Lean reference DCAP verifier (multi-month effort with no current owner), a PCK-signature unforgeability reduction (Intel-spec dependent), and VCVio random-oracle + birthday bound coverage for `commitHashE` and `commitHashBytesE` (requires `[Fintype UserData]` carrier refinement). None block this PR's verification claims; the parametric formulation is the honest interim form.

IsPPT-PolyQueries instantiation. Currently `IsPPT := True`. The substantive Option-(a) fix instantiating `IsPPT := PolyQueries` requires cycle 6.13 (`OracleComp ProtocolSpec` adversary wiring) as prereq. Round A attack #5 surface-side closure landed in cycle 6.12 via the `_AGAINST_UNBOUNDED_ADVERSARIES` rename so the placeholder gap is visible at every call site.

## Files changed

Lean: 14 spec files split across `proofs/lean/Specs/Quartz/{Crypto,Attestation,Protocol}/`. Five carrier modules pair with their `*VCVio.lean` companions. Protocol layer splits by bundle cardinality (`ProtocolVCVio` foundations, `ProtocolVCVioDual` / `Triple` / `Quad` containing the eight lifted `_negl` theorems). Classical `_classical` re-exports preserve unchanged behavior for engineering code.

Verus: six prototype files at `crates/{contracts,enclave}/core/verus-prototype/`. Production Rust source is unchanged in this PR; the only production hook flagged is the Critical 4 follow-up at `crates/contracts/core/src/handler/execute/attested.rs:94-99`, which is a separate Quartz-agent change.

Methodology: 10 change records at `.colosseum/changes/2026-05-13T*.md` and `.colosseum/changes/2026-05-14T*.md` covering Steps 1-7 and cycles 6.4-6.12. Adversarial review trail at `.colosseum/attacks/{lean-negl-lifts,quint-recently-revised,quint-unattacked,verus-prototype,verus-prototype-cross-critique}-{2026-05-14,2026-05-14,2026-05-14,2026-05-14,2026-05-20}/`. Integration ledger at `.colosseum/ledger.md`.

## Verification

```
$ lake build
Build completed successfully (2667 jobs).

$ for f in crates/{contracts,enclave}/core/verus-prototype/*.rs; do verus "$f" 2>&1 | tail -1; done
verification results:: 14 verified, 0 errors  # attested.rs
verification results::  8 verified, 0 errors  # instantiate.rs
verification results::  6 verified, 0 errors  # session_create.rs
verification results::  7 verified, 0 errors  # session_set_pub_key.rs
verification results::  6 verified, 0 errors  # encryption.rs
verification results::  4 verified, 0 errors  # key_manager.rs

$ # CI workflows: kani.yml, quint.yml, verus.yml, lean.yml — all green
```

## Reviewer pointers

For a 60-second read: the ledger's audit-ready paragraph at `.colosseum/ledger.md:22` is intended as a self-contained trust-boundary summary. For depth: the per-cycle change records at `.colosseum/changes/` walk each step's axiom inventory delta and dependent theorem update. For methodology: the per-round synthesis documents at `.colosseum/attacks/*/synthesis.md` show the multi-voice adversarial trail with per-voice reports persisted verbatim.

The two follow-up scopes (Critical 4 production-side, Critical 5 substantive) are tracked in the ledger's "Round D blocker resolution" section with named owners (Quartz-agent for the production hook, Colosseum-agent for the lifecycle remediation cycle).
