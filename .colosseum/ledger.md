# Colosseum integration ledger — Quartz (post-VCVio refactor)

> **CORRECTION 2026-05-14 (initial)**: Round A adversarial review (`.colosseum/attacks/lean-negl-lifts-2026-05-14/`) returned BREAKS on the content-phase lift. The 8 `_negl` theorems were content-free tautologies — each binding its protocol-fail advantage as a free `ℝ≥0∞` function symbol with no defining equation; proofs went through via `negligible_of_le` + `negligible_add` (closure properties of `negligible`), proving only that the negligible class is closed under pointwise domination and finite sums.
>
> **UPDATE 2026-05-14 (post-cycle-6.4–6.11)**: Round A's structural critique has been substantially addressed. Cycles 6.4–6.11 (8 commits) replaced every `_negl` lift's free-symbol advantage with a `Pr[…]`-based `def`, replaced caller-supplied bounds with proven bounds via `probEvent_mono` + `probEvent_bind_pure_comp`, and made the bundle structure honest about which axioms are probabilistic-failure modes vs. unconditional carrier-substrate. Round A attacks #1 (free-symbol tautology), #2 (Trojan h_bound), #3 (no reduction relation), #4 (disjunction-decomposition cosmetic at terminal), and #11 (over-quantified signature) are structurally closed.
>
> Round A attacks #5 (`IsPPT := True` vacuity), #6 (`ProtocolSpec` unused), #8 (Option-(b) for `commitHashE`) remain open. **Cycle 6.12 (2026-05-14) closes #5 surface-side via Option (b)**: the seven `*Game_secure_of_*_bundle_secure` packagings were renamed to `*_AGAINST_UNBOUNDED_ADVERSARIES` with explicit docstrings about the placeholder gap (change record `.colosseum/changes/2026-05-14T20-30-00Z-cycle-6.12-ispptrename.md`). **Cycle 6.13 (2026-05-20) closes #6**: all five adversary types across `ProtocolVCVio*.lean` lifted from `ℕ → ProbComp T` to `ℕ → OracleComp ProtocolSpec T`; an honest-deterministic `protocolSpecHonestSim : QueryImpl ProtocolSpec ProbComp` interprets the four protocol oracles via `pure` of the classical-Prop function values, and every advantage def wraps with `simulateQ protocolSpecHonestSim`. Lift proofs gain a one-line `simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]` step before `probEvent_mono`. Build green at 2670 jobs (+3 from the new `SimSemantics.Append` import); 0 `sorry`. Change record `.colosseum/changes/2026-05-20T22-35-36Z-cycle-6.13-protocolspec-wiring.md`. Cycle 6.13 unblocks the substantive Option-(a) `IsPPT := PolyQueries` instantiation, now queued as cycle 6.14.
>
> **Round C 2026-05-14**: adversarial review of 4 previously-unattacked Quint specs (handshake, attestation, pingpong, transfers) returned 27 distinct attacks (3 critical, 13 serious, 11 advisory). Per-spec verdicts (both arms agree): handshake.qnt **WEAKENS**, attestation.qnt **HOLDS WITH CAVEATS**, pingpong.qnt **WEAKENS**, transfers.qnt **BREAKS**. Three critical findings: (1) `inv_plaintext_private` vacuous (pingpong); (2) conservation theorem ignores `BankMsg::Send` plaintext leak (transfers); (3) `update` action processes 1 request while Rust drains a prefix with attacker-controllable `msg.quantity` (transfers). Same-commit response: docstring-honesty caveats applied to all 3 critical invariants (vacuity made explicit at call sites); substantive `prev_sequence_num` ghost + strict-monotone invariant added for the replay-protection finding. Substantive parameterize-by-quantity `update` refactor deferred. See `.colosseum/attacks/quint-unattacked-2026-05-14/synthesis.md`.
>
> **Round D 2026-05-14/15**: 7-voice adversarial fan-out (Claude subagent, Qwen, Gemma, Mistral local; Kimi, GLM, GPT-OSS via gateway) on the Verus prototype tree under `crates/{contracts,enclave}/core/verus-prototype/` (6 files, 1431 LOC). 30 distinct attacks after dedup, with 5 critical, 19 serious, 6 advisory. Every file reaches WEAKENS or worse in the cross-family majority verdict; `attested.rs`, `session_set_pub_key.rs`, and `key_manager.rs` reach BREAKS across both Claude and gpt-oss arms. Five critical findings:
>
> 1. `signing_key_bytes_roundtrip_axiom` in `key_manager.rs` was unsound: `requires true` plus application at `import_export_roundtrip` with unbound parameters concluded `verifying_key_spec(decoded) == verifying_key_spec(sk)` for any triple, propositionally forcing `verifying_key_spec` to be constant and admitting the derivation of `false`. Three voices agreed independently. **Closed 2026-05-20 (commit `ec24934`)** by adding two uninterpreted spec functions (`signing_key_to_bytes_spec`, `signing_key_from_slice_spec`) with `ensures` clauses on the exec wrappers, and tightening the axiom's `requires` to bind the parameters non-trivially. `verus key_manager.rs` reports 5 verified, 0 errors against the new axiom.
> 2. `SEQUENCE_NUM` reset never modeled in `session_set_pub_key.rs`. Production force-resets the replay counter to zero as the foundation for every downstream `Sequenced<T>` handler. Universal across the six structured-or-prose voices, the highest-agreement-density finding in Round D. Open.
> 3. `Attested<M,A>::handle` inner-handler error propagation lost. The prototype monomorphises both handlers to total-Ok and admits in a comment that it depends on a compensating `concrete_att_handle_maybe_err` external_body variant. That variant does not exist in the file. Open.
> 4. DstackZk handler spec terminates at "verifier said yes on `(proof, public_inputs)`" without binding `public_inputs` back to the wrapper's `compose_hash` and `user_data`. Production has the same omission. The load-bearing security property of the entire zkdcap pipeline is unencoded. Open. Claude-only finding (requires cross-file Rust reading the no-file-access voices did not have).
> 5. `pub_key_matches_sk` proves the binding for a frozen `DefaultKeyManager` value. Production `Import::import` mutates `self.sk` in place, after which the previously-published `pub_key` is stale. The temporal binding property is not proved. Open. Claude-only.
>
> Recurring patterns (Round D): body-verified storage stubs that are not the documented "Variant B" external_body shape, tautological lemmas inflating the verified count, external_body axioms without `requires` linkages (Critical 1 was the worst instance), type narrowing without recapture (UserData / MrEnclave / zkdcap_vkey collapsed to `u64`), confidentiality vs correctness conflation in `encryption.rs`, monomorphisations that erase the only interesting failure mode, mock-mode invisibility. The Verus prototypes are now formally labeled **feasibility specs**, not integration-ready. The "5 of 43 verified" framing in the per-tool snapshot below was honest pre-Round-D but is misleading post-Round-D until Criticals 2 and 3 are resolved. See `.colosseum/attacks/verus-prototype-2026-05-14/synthesis.md`.
>
> Methodology refinements surfaced by Round D, filed as colosseum v0.4 ask candidates at `colosseum/methodology-v0.4-candidates.md`: Mistral 119B crashed at 22K-token prompts (substitute or skip the slot); reasoning-model `max_tokens` budgeting needs to allocate `reasoning_budget + visible_budget` separately because Kimi and Gemma both burned their entire budget on hidden reasoning tokens with zero structured visible output; LM Studio cross-session contention can balloon local-model elapsed time roughly 10x. The newer opencode-dispatch shape at `verified-rcv/.colosseum/scripts/opencode_dispatch.py` resolves the truncation issue via per-slice subagent dispatch rather than single-shot fan-out, and is the recommended pattern for any future Quartz adversarial round.
>
> **Round D cross-critique 2026-05-20 (v0.4 Ask O)**: cloud-only 6-voice pass on Round D Criticals 4 and 5 (both Claude-only in the original fan-out). Voices: Claude subagent (file-access), openai/gpt-5.5 (newly-added OAuth path), burnt/gpt-oss-120b, burnt/kimi-k2-6, burnt/cloudflare-nemotron-3-120b-a12b (all variant=high), burnt/gemini-3-1-flash-lite (returned empty stdout, excluded). Results: Critical 4 ratified at 5-of-5 DEFEND; Critical 5 refined at 3-of-5 THIRD_OPTION with convergent refinements from Claude, GPT-5.5, and Kimi. Spec-side closures landed 2026-05-20 in commit `3267015`: Critical 4 Verus side adds the `proof_journal_binds` uninterpreted predicate, the `verify_proof_journal_binds` external_body verification step, and tightens the `dstack_zk_handle` Ok postcondition to require both gnark-verifier acceptance AND public-inputs/wrapper-fields binding; Critical 5 deletes the tautological `pub_key_matches_sk` theorem (whose ensures was `forall k. f(k.sk) == f(k.sk)`, contributing nothing) and replaces it with a docstring redirect to where the actual snapshot binding lives. The substantive Critical 5 remediation (model DefaultKeyManager import as mutation, model DstackKeyManager which is the production default and currently unmodeled, add session-lifecycle ghost layer with a `contract_pub_key` field plus state-transition invariants, decide production key-rotation policy) becomes a follow-up cycle. See `.colosseum/attacks/verus-prototype-cross-critique-2026-05-20/synthesis.md`.
>
> **Round D blockers status post-cross-critique**: Criticals 1, 2, 3, 4-Verus-side, and 5 are all closed by 2026-05-20. Critical 5's substantive remediation landed in commit `69d27eb`: `DefaultKeyManager::import` is now a mutating method, `DstackKeyManager` is modeled (closing Round D Critical 19 simultaneously) with the KMS-fallback random-key risk path explicit, and two `*Lifecycle` ghost structs wrap each manager with a `contract_pub_key` field and a `binding_holds` invariant tying the contract's view to the enclave's current sk. Two import variants (`import_with_invalidate` and `import_with_rotate`) are proved to preserve the invariant; the production-side policy choice between them is documented in the prototype. The only remaining Round D item is the Critical 4 production-side hook, queued as a Quartz-agent follow-up: the production `DstackZkAttestation::handle` at `crates/contracts/core/src/handler/execute/attested.rs:94-99` must decode `zkdcap_public_inputs` (or the existing-but-unused `zkdcap_journal` field) and verify-equal the encoded `report_data` and `compose_hash` against `self.user_data` and `self.compose_hash` before returning Ok. The two-agent split (Quartz-agent owns `crates/`, Colosseum-agent owns `.colosseum/`, `proofs/lean/`, `specs/`) per `CLAUDE.md:5-12` cleanly partitions the remaining work.
>
> **Round E 2026-05-20 (Kani harness surface, 5 cloud voices)**: the only spec-class artifact never previously adversarially reviewed. 33 distinct attacks after dedup, 4 critical, 16 serious, 13 advisory. The load-bearing methodology finding: the Kani harness suite is strictly weaker than the Quint surface for the example contracts because the harnesses verify pure helpers in `#[cfg(kani)]` modules rather than the production handlers. Round C's three critical Quint findings (pingpong vacuous privacy, transfers BankMsg::Send leak, transfers single-vs-drain) have no corresponding Kani coverage. Cross-voice agreement on this gap was 4-of-5 voices.
>
> **Colosseum-side Round E follow-ups landed in commit `1c3d4f8`** (2026-05-20):
> - Removed 5 tautological pingpong harnesses (reduced to "Rust by-value + derive(Clone) work").
> - Removed framework `session_with_pub_key_no_panic` (function body has no panic source).
> - Reframed transfers `mod verification` to `mod spec_harnesses` with explicit docstring that the helpers are pure mirrors of code production does not invoke.
> - Strengthened `session_create_roundtrip` and `session_set_pub_key_raw_roundtrip` to assert all fields (GPT-5.5 #2 + sibling).
> - Replaced `h_phase_transition_no_skip` with exhaustive 16-pair enumeration (Kimi #13).
> - Added `h_tally_round_vote_conservation` (Nemotron #7) and `h_bid_count_matches_map_cardinality` (Nemotron #8).
> - Withdrew `user_data` determinism harnesses (Kimi #5): CBMC could not bound the SHA-256 + serde_json path in 10 minutes at `#[kani::unwind(64)]`. Documented as a Quartz-agent follow-up.
>
> **Round E undecidable blocker (Quartz-agent scope)**: the two `#[cfg(kani_slow)]` LightClientOpts harnesses in `crates/contracts/core/src/state.rs` cannot run in CI even with `--cfg kani_slow` enabled, because `StdError::msg` constructs a `std::backtrace::Backtrace` whose `drop_in_place::<[BacktraceSymbol]>` loop unwinds indefinitely. Verified locally: 16+ unwind iterations before manual kill. The fix requires replacing `StdError::msg` with a backtrace-free constructor under `#[cfg(kani)]`, which is a production code change in `quartz-contract-core`. The Colosseum side cannot land this; it is queued as the second Quartz-agent follow-up alongside the Round D Critical 4 production-side hook.
>
> **Remaining Quartz-agent follow-ups (all surfaced by the Colosseum side; none block further Colosseum-side work)**:
> 1. Round D Critical 4 production hook at `crates/contracts/core/src/handler/execute/attested.rs:94-99` — decode `zkdcap_public_inputs` or `zkdcap_journal` and verify-equal the encoded `report_data` and `compose_hash` against `self.user_data` and `self.compose_hash` before returning Ok.
> 2. Round D Critical 5 production deletion (policy choice A landed 2026-05-20): remove `impl Import for DefaultKeyManager` at `crates/enclave/core/src/key_manager/default.rs:49-57`, remove `impl Import for DstackKeyManager` at `crates/enclave/core/src/key_manager/dstack.rs:164-181`, remove the `try_restore` path at `crates/enclave/core/src/lib.rs:317-338` that depends on the deleted impls. If a future operational requirement reintroduces the need for live key rotation, the Verus prototype's `*Lifecycle::import_with_rotate` variant documents the sound add-back path (would also require a corresponding `session_rotate_pub_key` contract message and binding-to-attestation discipline).
> 3. Round E `kani_slow` CI integration — replace `StdError::msg` with backtrace-free constructor under `#[cfg(kani)]` so the LightClientOpts validation harnesses become tractable under standard `cargo kani`. Also unlocks the Kimi #5 `user_data` determinism harnesses (same underlying tractability issue).
>
> Also Quartz-agent-territory but lower priority: re-host the transfers `safe_drain_len` / `checked_sum_withdrawals` helpers as production code so the spec_harnesses module covers deployed behavior instead of phantom-helper code.
>
> **New methodology finding (cycle-6.4–6.11 sequence)**: 7 of 8 lifts were over-bundled in the original Step 6.0–6.3 work. The original plan classified lifts by the union-bound shape implied by an axiom count; the actual probabilistic-failure modes in each classical proof are fewer than the axiom count suggests. The terminal lift (5-summand union bound in the original) has only one probabilistic-failure mode (Groth16-soundness) under the current carrier model — the other 4 axioms are consumed unconditionally in the classical proof and do not lift to probabilistic hypotheses. Worth back-porting to colosseum methodology v0.2 as a new ask: **bundle-count derivation must come from per-conjunct failure-mode analysis of the classical proof, not from a static axiom-count classifier**.
>
> Specific retractions remain inline below, each marked with `[RETRACTED 2026-05-14]`. The corrective trail across initial retraction → cycle 6.4–6.11 sequence is visible in `.colosseum/changes/2026-05-14T*-cycle-6.{4..11}-*.md`. See also the synthesis at `.colosseum/attacks/lean-negl-lifts-2026-05-14/synthesis.md`.

- Project: /Users/mvid/Development/reliq/quartz
- Generated: 2026-05-13T16-30-00Z (Step 7, post-Step-6.3 regeneration)
- Compared against: prior emission 2026-05-12T12:57:07Z (40 axioms, 5 composition theorems, pre-VCVio)
- Generator: `colosseum-compose` skill (manual walk; methodology v0.1; v0.2 asks below)
- Build status: `lake build` green at 2670 jobs (cycle 6.13 added the `SimSemantics.Append` transitive import); **14 axioms** from the original 26-axiom inventory (cycles 6.16–6.20 refined `Nonce`/`MrEnclave`/`UserData`/`PrivKey`/`PubKey`/`Plaintext`/`DomainSep`/`Addr`/`ByteSeq` to concrete types and demoted `rawDomainSep`/`rawBoundContract`/`rawPlaceholderPubKey` to defs); cumulative form-phase reduction 40 → 14 = –65%; `verus` across the prototype tree green (55 verified, 0 errors total: attested 14, instantiate 8, session_create 6, session_set_pub_key 7, encryption 6, key_manager 14 post-Critical-5-substantive). Round D Criticals 1, 2, 3, 4-Verus-side, and 5 (substantive) all closed by 2026-05-20.
- Phase: ~~end of VCVio refactor Steps 0-6.3 (form-phase axiom reduction 40 → 26 = -14 / -35%; content-phase lift of all 8 protocol theorems complete)~~ — **[UPDATED 2026-05-20]** form-phase reduction holds (40 → 26 axioms); content-phase lift sequence (cycles 6.4–6.11) complete, all 8 `_negl` theorems def-tied with content-bearing `Pr[…]`-based advantages and proven (not assumed) pointwise bounds. Refactor is at "form-phase + def-tying content-phase complete; carrier-refinement / IsPPT-PolyQueries / Option-(b)-commitHash content-phase pending (cycles 6.12–6.14); Verus-prototype Round D Criticals 1, 2, 3, 4-Verus-side, and 5 (substantive: mutating import + DstackKeyManager modeled + session-lifecycle ghost layer) all closed; Critical 4 production-side queued for Quartz agent". This fork is the canonical destination; informalsystems/cycles-quartz upstream is unmaintained and does not carry the dstack TDX / zkdcap / Xion changes, so no upstream PR is planned.

## Audit-ready trust-boundary summary (60-second read) — [RETRACTED 2026-05-14, see banner]

After the VCVio refactor, Quartz's Lean trust boundary decomposes into three honest classes. **Honest carriers** (14 opaque types + 3 named-constant witnesses + 5 function/predicate signatures = 22 of 26 axioms) are non-cryptographic abstractions over types and named values from the deployed Rust stack (k256/ECIES key shapes, serde_json byte sequences, DCAP quote bytes, gnark vkey/proof/input bytes). They compile to nothing — they are the parametric model the Lean tree refines. **Honest cryptographic assumptions** (4 bundled record axioms — `commitHashE`, `commitHashBytesE`, `tdxVerifier`, `groth16Verifier`) name real cryptographic / attestation primitives; two are spec-impossible-as-stated injections (pigeonhole bound on hash codomain), two are classical-Prop verification implications dropping computational-soundness qualifiers. Each is consumed by the protocol-layer classical theorems but is **shadowed at the content layer** by 8 `_negl` lifts in `ProtocolVCVio*.lean` that re-state the trust claim as parametric negligibility hypotheses (zero `sorry`). **Externally deferred** discharges (5 negligibility budgets feeding the `cross_component_session_bind` 5-summand union bound) point to: ArkLib Groth16 KS coverage (upstream), a Lean reference DCAP verifier (separate effort), a PCK-signature unforgeability reduction (Intel-spec + crypto-lib), and VCVio random-oracle + birthday bound after `[Fintype UserData]` carrier refinement. The protocol layer's verified surface is now: 5 honest cryptographic assumptions on real-world primitives, plus standard carrier axioms, plus a parametric union-bound composition — *none* of the 8 lifted theorems carry a bundle axiom in its `_negl` closure (only carriers + standard logic + the parametric negligibility hypotheses).

## Per-axiom inventory (26 axioms, 4-bucket classification)

Categories: **(a)** demotable-to-def-or-dead · **(b)** demotable-to-derived-theorem · **(c)** honest-computational-assumption · **(d)** impossibility-or-over-strength

| # | Axiom | Module | Cat | Sub-tag | Discharge path | Carried by |
|---|-------|--------|-----|---------|----------------|------------|
| 1 | `PrivKey : Type` | Ecies | (c) | carrier | k256/ECIES Rust crate type model | all 8 lifted (carrier) |
| 2 | `PubKey : Type` | Ecies | (c) | carrier | k256 Rust crate type model | all 8 lifted (carrier) |
| 3 | `Plaintext : Type` | Ecies | (c) | carrier | application-level type model | all 8 lifted (carrier) |
| 4 | `keyOf : PrivKey → PubKey` | Ecies | (c) | carrier | deterministic key derivation, k256 spec | classical chain only (not in `_negl` closures) |
| 5 | `DomainSep : Type` | UserDataCommit | (c) | carrier | named-constant byte-string type | 7 of 8 lifted (carrier; not in cross_transfers/auction `_negl`) |
| 6 | `Addr : Type` | UserDataCommit | (c) | carrier | Cosmos chain-address type model | all 8 lifted (carrier) |
| ~~7~~ | ~~`Nonce : Type`~~ — **removed (cycle 6.16, 2026-05-20)**: refined to `abbrev Nonce : Type := BitVec 256`; no longer an axiom | UserDataCommit | n/a | n/a | n/a | n/a |
| 8 | `commitHashE : UserDataCommit ↪ UserData` | UserDataCommit | (d) | pigeonhole-impossible | concrete `H : UC → UD` carrier + `randomOracle` birthday bound, requires `[Fintype UserData]` | classical chain (4 theorems); shadowed in `_negl` by `CommitHashCollisionAdv` hypothesis |
| 9 | `ByteSeq : Type` | RawMessages | (c) | carrier | serde_json byte-sequence type model | 3 of 8 lifted (carrier; cross_transfers, auction, cross_component_session_bind) |
| 10 | `serializeRawSessionCreateE : RawSessionCreate ↪ ByteSeq` | RawMessages | (c) | carrier (genuine injectivity claim) | serde_json byte layout determinism on fixed struct schema | classical chain only |
| 11 | `serializeRawSessionSetPubKeyE : RawSessionSetPubKey ↪ ByteSeq` | RawMessages | (c) | carrier (genuine injectivity claim) | serde_json byte layout determinism on fixed struct schema | classical chain + cross_component_session_bind `_classical` |
| 12 | `commitHashBytesE : ByteSeq ↪ UserData` | RawMessages | (d) | pigeonhole-impossible | concrete `H_b : ByteSeq → UD` carrier + `randomOracle` birthday bound | classical chain (3 theorems); shadowed in `_negl` by `CommitHashBytesCollisionAdv` hypothesis |
| 13 | `rawDomainSep : DomainSep` | RawMessages | (a) | blocked-by-abstract-carrier | demote to `def` once `DomainSep` carrier refined to concrete byte string | classical chain + cross_component_session_bind `_classical` |
| 14 | `rawBoundContract : Addr` | RawMessages | (a) | blocked-by-abstract-carrier | demote to `def` once `Addr` carrier refined to concrete bech32 string | classical chain + cross_component_session_bind `_classical` |
| 15 | `rawPlaceholderPubKey : PubKey` | RawMessages | (a) | blocked-by-abstract-carrier | demote to `def` once `PubKey` carrier refined to concrete bytes | classical chain only |
| 16 | `userDataOfSessionSetPubKey_eq_commitHash` | RawMessages | (c) | carrier (genuine bridge equality) | constructive byte-level model of serde_json AND `commitHash` | classical chain + cross_component_session_bind `_classical` |
| 17 | `userDataOfSessionCreate_eq_commitHash` | RawMessages | (c) | carrier (genuine bridge equality) | same — constructive byte-level + commit model | classical chain only |
| 18 | `TdxQuote : Type` | Dstack | (c) | carrier | DCAP-quote-v4 wire-format byte-blob model | all 8 lifted (carrier) |
| 19 | `MrEnclave : Type` | Dstack | (c) | carrier | MRTD / RTMR digest byte-string model | 7 of 8 lifted (carrier; not in `verifyGroth16_yields_decoded_negl`) |
| 20 | `UserData : Type` | Dstack | (c) | carrier | 64-byte report_data slot model | all 8 lifted (carrier) |
| 21 | `was_signed_by_dstack : TdxQuote → Prop` | Dstack | (c) | carrier (off-chain reality witness) | irreducible — propositional witness for "a real dstack TEE produced this quote" | classical chain only (sidestepped by `IsPPT`/`Classical.propDecidable` in `_negl`) |
| 22 | `tdxVerifier : TdxVerifier` | Dstack | (d) | classically-over-strong-single-negligibility (sound) + preconditional (complete) | (sound) PCK-signature unforgeability reduction; (complete) explicit collateral-freshness / non-revocation preconditions; both require Lean reference DCAP verifier | classical chain (7 theorems); shadowed in `_negl` by `TdxVerifierSoundAdv` hypothesis |
| 23 | `Groth16Proof : Type` | Zkdcap | (c) | carrier | BN254 proof byte-string model | all 8 lifted (carrier) |
| 24 | `PublicInputs : Type` | Zkdcap | (c) | carrier | concatenated 32-byte fr.Element values | all 8 lifted (carrier) |
| 25 | `VKey : Type` | Zkdcap | (c) | carrier | gnark verification-key byte-string model | 1 of 8 lifted (only in cross_component_session_bind `_negl` carrier; not in others) |
| 26 | `groth16Verifier : Groth16Verifier` | Zkdcap | (d) | classically-over-strong-doubled-negligibility | (KS half) ArkLib Groth16 reduction; (circuit-eq half) Lean reference DCAP verifier + circuit-equivalence theorem; **decomposes into 2 summands at the terminal lift** | classical chain (8 theorems); shadowed in `_negl` by `Groth16SoundAdv` (intermediate) or `Groth16KSAdv` + `CircuitEqAdv` (terminal) hypotheses |

### Bucket totals (25 axioms — post-cycle-6.16)

- **(a) demotable-to-def-or-dead** — 3 (rawDomainSep, rawBoundContract, rawPlaceholderPubKey); all blocked-by-abstract-carrier
- **(b) demotable-to-derived-theorem** — 0 (all demotables of this kind were already discharged in Steps 1-5: `roundtrip`, `commitHash_inj`, `commitHashBytes_inj`, `serializeRaw*_inj`, `verifyTdxQuote_sound`/`_complete`, `verifyGroth16_sound`)
- **(c) honest-computational-assumption** — 18 (13 carriers + 3 function/predicate signatures + 2 bridge equalities; `Nonce` removed by cycle 6.16)
- **(d) impossibility-or-over-strength** — 4 (`commitHashE`, `commitHashBytesE`, `tdxVerifier`, `groth16Verifier`); each shadowed at content layer by parametric `_negl` hypothesis

### Sub-bucket (d) sub-taxonomy

- (d-pigeonhole-impossible): 2 — `commitHashE`, `commitHashBytesE`
- (d-classically-over-strong-single-negligibility): 1 — `tdxVerifier.sound`
- (d-classically-over-strong-preconditional): 1 — `tdxVerifier.complete`
- (d-classically-over-strong-doubled-negligibility): 1 — `groth16Verifier.sound`

(`tdxVerifier` carries two distinct (d) sub-tags inside one record axiom.)

## Lifted theorem index (8 of 8, all `_negl`-shadowed) — [PARTIALLY RETRACTED 2026-05-14]

> The 8 lifted theorems exist and type-check, but their `_negl` forms bind the protocol-fail advantage as a free `ℝ≥0∞` function symbol rather than a defined probability event. Round A established that each can be vacuously satisfied by instantiating the fail-advantage to `0`. Reading this section: the theorem *names* and *bundle composition* below are correct; the trust claim attached to each (that the `_negl` form constitutes a content-bearing parametric security reduction) is retracted pending the def-tying refactor.

| # | Theorem | Module | Bundle card. | Summands in union bound | `_negl` closure | `_classical` closure |
|---|---------|--------|--------------|-------------------------|-----------------|----------------------|
| 1 | `verifyGroth16_yields_decoded_negl` | ProtocolVCVio | single | 1 | carriers (Groth16Proof, PublicInputs) + std logic | `tdxVerifier` + `groth16Verifier` + carriers |
| 2 | `handshake_sound_negl` | ProtocolVCVioDual | dual | 2 (groth16 + tdx) | carriers (MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs) + std logic | `tdxVerifier` + `groth16Verifier` + carriers |
| 3 | `handshake_binds_ecies_key_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashE-CR) | carriers (Addr, DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs, Plaintext, PrivKey, PubKey) + std logic | `tdxVerifier` + `groth16Verifier` + `commitHashE` + carriers |
| 4 | `session_confidentiality_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashE-CR) | same as #3 | `tdxVerifier` + `groth16Verifier` + `commitHashE` + carriers |
| 5 | `session_confidentiality_via_extractor_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashE-CR) | same as #3 | `tdxVerifier` + `groth16Verifier` + `commitHashE` + carriers |
| 6 | `cross_component_transfers_conservation_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashBytesE-CR) | carriers (Addr, ByteSeq, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs) + std logic | `tdxVerifier` + `groth16Verifier` + `commitHashBytesE` + carriers + `serializeTransferRequest`, `Conservation.addrOf` |
| 7 | `cross_component_auction_winner_determinism_negl` | ProtocolVCVioTriple | triple | 3 (groth16 + tdx + commitHashBytesE-CR) | same as #6 | `tdxVerifier` + `groth16Verifier` + `commitHashBytesE` + carriers + `serializeResolveMessage`, `Conservation.addrOf`, `AuctionDeterminism.decryptBid` |
| 8 | `cross_component_session_bind_negl` | ProtocolVCVioQuad | quadruple | **5** (groth16-KS + circuit-eq + tdx + commitHashE-CR + commitHashBytesE-CR) | carriers (Addr, ByteSeq, DomainSep, Nonce, MrEnclave, TdxQuote, UserData, Groth16Proof, PublicInputs, VKey, Plaintext, PrivKey, PubKey) + std logic | `commitHashE` + `commitHashBytesE` + `tdxVerifier` + `groth16Verifier` + carriers + `rawBoundContract`, `rawDomainSep`, `serializeRawSessionSetPubKeyE`, `userDataOfSessionSetPubKey_eq_commitHash`, `was_signed_by_dstack`, `keyOf` |

**Invariant across all 8 lifts**: the `_negl` form's axiom closure contains **only carriers + standard logic** (`propext`, `Classical.choice`, `Quot.sound`) — *no bundle axioms*. Bundles enter through parametric hypotheses, not closure. The `_classical` corollary preserves the original bundle dependency unchanged for downstream consumers that still want the classical form.

Each lifted theorem comes in four packagings: `_classical` (corollary), `_negl` (raw `negligible` form), `_secure_of_*_bundle_secure` (`SecurityExp`), `*Game_secure_of_*_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES` (`SecurityGame` with `IsPPT` filter, body still `True` as a placeholder — name made honest in cycle 6.12).

## Cross-bundle composition map → `cross_component_session_bind_negl`

The terminal load-bearing lift composes all 4 classical bundles via a 5-summand union bound (Groth16 decomposes into 2 summands per the Step 5 doubled-negligibility finding):

```
                     Step 2 bundle              Step 3 bundle
                     ┌────────────┐             ┌────────────────┐
                     │ commitHashE│             │commitHashBytesE│
                     │ (UC ↪ UD)  │             │ (ByteSeq ↪ UD) │
                     └─────┬──────┘             └────────┬───────┘
                           │                             │
                           │ (d-pigeonhole)              │ (d-pigeonhole)
                           ▼                             ▼
              Pr[commitHashE collision]    Pr[commitHashBytesE collision]
                  ← CommitHashCollisionAdv   ← CommitHashBytesCollisionAdv
                           │                             │
                     Step 4 bundle              Step 5 bundle (DECOMPOSED)
                     ┌────────────┐             ┌──────────────────────┐
                     │ tdxVerifier│             │  groth16Verifier     │
                     │ (verify    │             │  (vkey+verify+       │
                     │  +sound    │             │   inputsToQuote+sound)│
                     │  +complete)│             └──┬────────────────┬──┘
                     └─────┬──────┘                │                │
                           │ (d-single-negl)       │ (d-doubled-negl)
                           ▼                       ▼                ▼
                  Pr[tdxVerifier forgery] negligible_groth16  negligible_circuit
                  ← TdxVerifierSoundAdv   ← Groth16KSAdv       ← CircuitEqAdv
                           │                       │                │
                           └─────────┬─────────────┴────────────────┘
                                     ▼
       Pr[cross_component_session_bind fails]
         ≤ Pr[commitHashE coll]          (summand 1, Step 2)
         + Pr[commitHashBytesE coll]     (summand 2, Step 3)
         + Pr[tdxVerifier forgery]       (summand 3, Step 4)
         + negligible_groth16            (summand 4, Step 5 KS half)
         + negligible_circuit            (summand 5, Step 5 circuit-eq half)
```

### Which lifted theorems carry which bundles (classical closures)

| Bundle | Carrying classical theorems |
|--------|-----------------------------|
| `commitHashE` (Step 2) | `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`, `cross_component_session_bind` (4) |
| `commitHashBytesE` (Step 3) | `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`, `cross_component_session_bind` (3) |
| `tdxVerifier` (Step 4) | `verifyGroth16_yields_decoded`, `handshake_sound`, `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`, `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`, `cross_component_session_bind` (8) |
| `groth16Verifier` (Step 5) | all 8 |

### Composition shape per theorem

- **Single** (1): `verifyGroth16_yields_decoded`
- **Dual** (1): `handshake_sound`
- **Triple-commitHashE** (3): `handshake_binds_ecies_key`, `session_confidentiality`, `session_confidentiality_via_extractor`
- **Triple-commitHashBytesE** (2): `cross_component_transfers_conservation`, `cross_component_auction_winner_determinism`
- **Quadruple → 5 summands** (1): `cross_component_session_bind`

## Companion-module inventory (9 new modules)

Carrier-side (5):
- `Specs/Quartz/Crypto/EciesVCVio.lean` — `eciesAlg : AsymmEncAlg Id ...`
- `Specs/Quartz/Crypto/UserDataCommitVCVio.lean` — `CommitHashSpec`, `commitHashOC`
- `Specs/Quartz/Crypto/RawMessagesVCVio.lean` — `CommitHashBytesSpec`, `commitHashBytesOC`
- `Specs/Quartz/Attestation/DstackVCVio.lean` — `VerifyTdxQuoteSpec`, `verifyTdxQuoteOC`
- `Specs/Quartz/Attestation/ZkdcapVCVio.lean` — `VerifyGroth16Spec`, `verifyGroth16OC`

Protocol-side (4):
- `Specs/Quartz/Protocol/ProtocolVCVio.lean` — scaffolding (combined `ProtocolSpec` via `(+)`-sum, `IsPPT`, `Decidable was_signed_by_dstack`, Step 6.0 single-bundle lift)
- `Specs/Quartz/Protocol/ProtocolVCVioDual.lean` — Step 6.1 dual-bundle lift
- `Specs/Quartz/Protocol/ProtocolVCVioTriple.lean` — Step 6.2 five triple-bundle lifts
- `Specs/Quartz/Protocol/ProtocolVCVioQuad.lean` — Step 6.3 quadruple-bundle terminal lift

Companion-module invariant: VCV-io's transitive instance load is kept out of the `Decidable`-synthesis hot path. Classical theorems do not import these modules; `Specs.lean` is the only top-level importer.

## Coverage delta vs prior ledger (2026-05-12T12:57:07Z)

| Metric | Prior | Post-Step-6.3 | Delta |
|--------|-------|---------------|-------|
| Total Lean axioms | 40 | 26 | **-14 (-35%)** |
| Bundled record axioms (Step 1-5 condensation) | 0 | 4 | +4 |
| Demoted to def/theorem | 0 | 14+ (roundtrip, commitHash, commitHash_inj, commitHashBytes, commitHashBytes_inj, serializeRaw*_inj×2, verifyTdxQuote, verifyTdxQuote_sound, verifyTdxQuote_complete, verifyGroth16, inputs_to_quote, verifyGroth16_sound, zkdcapVKey) | +14+ |
| Dead axioms removed | 0 | 1 (`RtmrLog`, Step 4) | -1 |
| Protocol theorems (classical) | 5 | 8 (extended scope: Conservation + AuctionDeterminism added) | +3 |
| Protocol theorems lifted to `_negl` | 0 | **8 of 8** | +8 |
| Companion modules | 0 | 9 (5 carrier + 4 protocol) | +9 |
| `lake build` jobs | 104 | 2667 (VCVio adds ~2534 transitive targets) | +2563 |
| `sorry` count | 0 | 0 | 0 |
| Trust density (axioms / total theorems) | 40/16 = 2.5 | 26/(16+14+8 derived/lifted) ≈ 0.68 | -1.82 |

## Per-tool coverage snapshot

| Tool | Artifacts | Proven / Verified | Outstanding | Notes |
|------|-----------|-------------------|-------------|-------|
| Lean | 26 axioms + classical theorems + 8×4 = 32 new lifted/packaged theorems | `lake build` green, 2667 jobs, 0 `sorry` | parametric negligibility hypotheses (5 budgets) deferred to ArkLib + ref-DCAP-verifier + carrier refinement | Step 6 complete — 8/8 lifted |
| Quint | 22 invariants | 2 Apalache-verified (handshake `inv_pubkey_set_once`, attestation temporal violation reproducible) | 20 not exhaustively verified | unchanged from prior ledger; attestation `temporal_zk_accept_requires_vkey` rewrite landed (`temporal_zk_accept_action_tag` change record) |
| Verus | 6 prototypes (feasibility specs, post-Round-D-hardened with one queued production-side follow-up) | 55 verified, 0 errors across the tree (Round D Criticals 1, 2, 3, 4-Verus, and 5 (substantive: mutating import + DstackKeyManager + session-lifecycle layer) all closed by 2026-05-20) | 38 unsampled annotations; Critical 4 production-side queued for Quartz agent (see banner) | post-Round-D + cross-critique: see `.colosseum/attacks/verus-prototype-2026-05-14/synthesis.md` and `.colosseum/attacks/verus-prototype-cross-critique-2026-05-20/synthesis.md` |
| Kani | 41 harnesses | 1 verified, 1 prover-stuck | 39 unsampled | unchanged from prior ledger |
| proptest | 0 | n/a | — | unchanged |

## Outstanding work

### External discharges (the 5 negligibility hypotheses)

1. `negligible_groth16_ks` — ArkLib Groth16 knowledge-soundness coverage (upstream)
2. `negligible_circuit` — Lean reference DCAP verifier + circuit-equivalence theorem (separate effort)
3. `negligible_tdx` — PCK-signature unforgeability reduction (Intel-spec + crypto-lib)
4. `negligible_commitHash` — VCVio `randomOracle` + birthday bound; requires `[Fintype UserData]`
5. `negligible_commitHashBytes` — same shape as (4) on byte domain

### Carrier refinement queue (14 abstract carriers blocking concrete `Pr[...]`)

Crypto: `DomainSep`, `Addr`, `Nonce`, `Plaintext`, `Ciphertext` (now def), `PrivKey`, `PubKey`, `ByteSeq`
Attestation: `TdxQuote`, `MrEnclave`, `UserData`
Zkdcap: `Groth16Proof`, `PublicInputs`, `VKey`

Concrete `Pr[...]` statements (instead of parametric `[Fintype X] → ...`) require these refined to concrete byte-list / `BitVec n` representations. Currently sidestepped by parametric formulation in all 8 `_negl` lifts.

### In-codebase work

- Adopt VCV-io's `PolyQueries` as the `IsPPT` body (currently placeholder `True`). **No longer blocked**: cycle 6.13 (done 2026-05-20) wired `OracleComp ProtocolSpec` into adversary types, so `PolyQueries` is now type-compatible with the adversary classes. Queued as cycle 6.14.
- Replace `Classical.propDecidable` instance for `was_signed_by_dstack` with extractor reformulation if a less-classical move is desired.
- Demote `rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey` to `def`s once their carriers (`DomainSep`, `Addr`, `PubKey`) are refined.

### Round D Verus-prototype blocker resolution (closed; remaining items queued as named follow-ups)

All five Round D criticals are now either closed or partitioned into named follow-up scopes per the two-agent split. Status summary:

1. Critical 1 (unsound `signing_key_bytes_roundtrip_axiom`) — closed 2026-05-20 in commit `ec24934`. Tightened the axiom's `requires` from `true` to a non-trivial precondition linking the `(sk, bytes, decoded)` parameters via two new uninterpreted spec functions; `import_export_roundtrip` updated to provide the new precondition. Three Round D voices agreed on the soundness break; cross-checked post-fix that the axiom can no longer derive `false`.
2. Critical 2 (`session_set_pub_key.rs` missing `SEQUENCE_NUM` reset) — closed 2026-05-20 in commit `832fb2e`. Added `sequence_num: Option<u64>` to `Storage`, introduced `SequenceNumItem` mirroring production's `SEQUENCE_NUM`, extended the handler's Ok postcondition with `final(storage).sequence_num == Some(0)`. Critical 11 (atomicity gap) documented as out of scope for this fix.
3. Critical 3 (`Attested<M,A>::handle` compensating variant missing) — closed 2026-05-20 in commit `a6232c3`. Added `ConcreteAtt::handle_maybe_err` external_body variant and `attested_handle_with_fallible_att` wrapper variant. Verus's verification of the new wrapper IS the inner-handler error propagation theorem the original docstring promised but did not deliver. Both wrappers' catch-all Err arms tightened to witness the user_data pre-check held.
4. Critical 4 (DstackZk `public_inputs` not bound to wrapper `compose_hash`/`user_data`) — **partially closed 2026-05-20 in commit `3267015`**. Cross-critique ratified at 5-of-5 DEFEND. Verus side now adds `proof_journal_binds` predicate, `verify_proof_journal_binds` external_body verification step, and tightens `dstack_zk_handle` Ok postcondition to require both gnark-verifier acceptance AND public-inputs/wrapper-fields binding. **Production side remains queued as a Quartz-agent follow-up**: the production handler at `crates/contracts/core/src/handler/execute/attested.rs:94-99` must decode `zkdcap_public_inputs` (or the existing-but-unused `zkdcap_journal` field GPT-5.5 surfaced) and verify-equal the encoded `report_data` and `compose_hash` against `self.user_data` and `self.compose_hash` before returning Ok. The Verus spec now requires this; production code does not yet enforce it.
5. Critical 5 (`pub_key_matches_sk` does not survive `Import::import`) — **closed across two commits (`3267015` + `69d27eb`) on 2026-05-20**. Cross-critique reached 3-of-5 THIRD_OPTION with convergent refinements from Claude, GPT-5.5, and Kimi. The cheap-honest part landed in `3267015`: the tautological `pub_key_matches_sk` theorem (whose `ensures` was `forall k. f(k.sk) == f(k.sk)`) is deleted and replaced with a docstring redirect to where the snapshot binding actually lives. The substantive four-part remediation landed in `69d27eb`: (a) `DefaultKeyManager::import` is now a mutating `&mut self` method with proper Ok/Err semantics; (b) `DstackKeyManager` is modeled with both production stale-key risk paths (KMS-fallback random key on `new`, KMS-rederivation on `import`) — this closes Round D Critical 19 simultaneously; (c) two `*Lifecycle` ghost structs (`DefaultKeyManagerLifecycle`, `DstackKeyManagerLifecycle`) wrap each manager with a `contract_pub_key` field and a `binding_holds` invariant tying the contract's view to the enclave's current sk, with `publish`, `import_with_invalidate`, and `import_with_rotate` operations each proved to preserve the invariant; (d) the production-side policy choice between remove-the-Import-impls vs. add-a-session_rotate_pub_key-contract-message is documented in the prototype, with the prototype proving both variants preserve the invariant so either is sound.
   
   **Policy decision (2026-05-20): Option A, `import_with_invalidate` semantics, implemented by removing the `Import` impls from production entirely.** No `session_rotate_pub_key` contract message will be added. The Verus prototype's `import_with_rotate` variant is retained as a documentary counterfactual for any future cycle that revisits the decision. The Quartz-agent task is concrete deletion (see follow-up queue below), not a policy design question.
   
   See `.colosseum/attacks/verus-prototype-cross-critique-2026-05-20/synthesis.md` for the original refined plan.

### Adversarial review

- Run `colosseum-adversarial` against the composed single+dual+triple+quadruple `_negl` surface (Step 6.3 explicitly queued this — all 4 lift levels in place provide the right granularity to surface union-bound-tightness, doubled-negligibility-correlation, and Option-(b) symmetric-framing findings).
- Specifically challenge the Option-(b) collision-resistance framing for `commitHashE` / `commitHashBytesE` — is the lift's hypothesis the *correct* statement of collision resistance for the concrete real-world hash, or has the embedding-to-concrete-hash mapping smuggled past a subtlety?

### Unchanged from prior ledger

- 1 clippy result_large_err
- 1 prover-stuck Kani harness
- 3 ignored unit tests in contracts/core
- attestation `temporal_zk_accept_requires_vkey` design decision (Option A/B per change record `2026-05-12T17-13-32Z-temporal_zk_accept_action_tag.md`)
- 38 unsampled Verus annotations, 39 unsampled Kani harnesses, 20 unsampled Quint invariants

## Reviewer checklist — [REVISED 2026-05-14 after Round A]

- [ ] All 26 axioms reviewed — bucket assignments stand?
- [ ] ~~All 4 (d)-bundle sub-tags match their discharge paths?~~ → Round A finds the sub-tag *labels* are correct but their *discharge mechanism* is cosmetic at the current code state. Re-frame as: do the (d) sub-tags name the right discharge paths *and* is each path's advantage abbrev tied to a concrete win predicate? (Currently no — see attacks #4, #8.)
- [ ] ~~All 8 `_negl` closures verified to carry **no bundle axioms**?~~ → **VACUOUSLY SATISFIED**. The closures are clean because the lifts say nothing about the bundle axioms (or about Quartz). Reframe as: does each `_negl` closure contain *exactly* the axioms its `_classical` form contains, *minus* the bundle axiom shadowed by the parametric negligibility hypothesis?
- [ ] `cross_component_session_bind_negl` 5-summand union bound matches the load-bearing claim the protocol layer is meant to make? — **Round A: no**, because the 5 underlying adversaries are unconstrained from the main one. See attack #3.
- [ ] No new `sorry` introduced in the lift modules? — Yes, still none.
- [ ] No regression in classical-chain axiom closures (each `_classical` corollary preserves its pre-refactor closure)? — **Yes, Round A confirms this is honest.**
- [x] ~~Option-(b) collision-resistance framing is the framing the team intended?~~ → **Closed surface-side by cycle 6.15 (2026-05-20)**: `commitHashCollisionAdv` and `commitHashBytesCollisionAdv` def-tied to `Pr[…]` collision events. Substantive Option-(a) closure (replacing the impossible `commitHashE` injection axiom with a random-oracle model) remains blocked on `[Fintype UserData]` carrier refinement.
- [x] `IsPPT := True` placeholder is acceptable as a documented gap (or is `PolyQueries` adoption a blocker)? → **Closed end-to-end by cycles 6.12 + 6.14.a/b/c (2026-05-20)**: placeholder retained for backwards-compatible `_AGAINST_UNBOUNDED_ADVERSARIES` packagings, with substantive `IsPPT_proper := Nonempty (PolyQueries …)` and parallel `_AGAINST_PPT_ADVERSARIES` packagings landed. The PPT packagings discharge each summand via per-reduction `IsPPT_proper`-preservation lemmas.

**New items added by Round A:**

- [x] For each `_negl` theorem, is the protocol-fail advantage a `def` over a concrete win event, or a free function symbol? → **Closed by cycles 6.4–6.11 + 6.15**: all advantages are now `def`s over `Pr[…]` events mentioning the concrete cryptographic functions.
- [x] For each `*Advantage` `abbrev`, is it tied to a concrete win condition involving the actual verifier/hash, or is it a `Type`-only alias? → **Closed by cycles 6.4–6.11 + 6.15**: every advantage has a content-bearing def. `Type`-only abbrevs are retained alongside for backwards-compatibility with the generic packagings.
- [ ] At the terminal lift, are the bundle adversaries *derived* from the main adversary (via a `reduce : 𝒜 → 𝒜_low` function with a `reduce_correct` lemma), or are they free arguments? → **Partial closure** at cycle 6.11 (terminal lift's bundle adversaries are derived from the main one), full closure of attack #3 remains tracked under the wider Round A surface.
- [x] Has the `ProtocolSpec` oracle-access framework been wired into adversary types, or is it imported but unused? → **Closed by cycle 6.13 (2026-05-20)**: all five adversary types lifted to `OracleComp ProtocolSpec`-valued; advantages route through `simulateQ protocolSpecHonestSim` over the four protocol oracles.

---

## Methodology v0.2 asks

Four findings accumulated across Steps 4-6.3 (one-line each, with change-record provenance):

1. **`dead_axiom_scan` checkpoint in `colosseum-compose`** — per-step global reference scan to surface axioms with zero downstream uses; "found" and "none" both valid outputs. Provenance: Step 4 first instance (`RtmrLog`, removed: `2026-05-13T14-56-59Z-dstack-vcvio.md`); Step 5 first explicit "none" outcome (`2026-05-13T15-05-36Z-zkdcap-vcvio.md`).

2. **Bundle-cardinality drift tracking** — bundle-count changes (dual → triple → quadruple) silently accumulate downstream of bundling steps; mid-refactor an originally-dual theorem can be promoted to triple by an upstream bundle without warning. Methodology should track bundle count per dependent theorem and flag promotions. Provenance: Step 6.1 (`2026-05-13T15-27-38Z-protocol-vcvio-dual-bundle.md` — three of four originally-dual targets turned out triple-bundle after Step 2's `commitHashE` cascade).

3. **Meta-(d): vacuous-impossible-axiom-as-hypothesis** — a classical theorem consuming a spec-impossible axiom is vacuously satisfied; the OracleComp lift cannot inherit the vacuous satisfaction and must restate the truthful cryptographic hypothesis (collision resistance of the concrete real-world hash). The lift *upgrades* the hypothesis from vacuous to non-vacuous, but only if the upgraded hypothesis is correctly identified. Provenance: Step 6.2 (`2026-05-13T15-48-32Z-protocol-vcvio-triple-bundle.md`, "(d-vacuous-hypothesis)" sub-variant; the Option-(b) framing for `commitHashE`).

4. **(d-disjunction-vs-decomposition) — load-bearing-terminal-lift discipline** — disjunctions in (d) axioms (e.g. `groth16Verifier`'s doubled-negligibility = Groth16-KS ∨ circuit-equivalence) can be honestly *collapsed* at intermediate composition levels but must *expand* at the load-bearing terminal lift. Compose-time should track which disjunctions are still collapsed at the current level and flag any that survive past the terminal lift. Requires a machine-checkable `terminal: true` flag in the refactor plan. Provenance: Step 6.3 (`2026-05-13T16-02-47Z-protocol-vcvio-quad-bundle.md`, methodology-side ask M-1).

### Prior methodology asks referenced from earlier change records

Already on the docket (pre-Step-6, not specific to this refactor):

- **PPT predicate hardening** — replace placeholder `IsPPT := True` with VCV-io's `PolyQueries`. Blocked on adversaries gaining `OracleComp ProtocolSpec` access (Step 6.1, sustained through 6.3).
- **`_negl` reduction-skeleton in companion modules** — currently the 5 carrier-side companion modules (`*VCVio.lean`) carry documentary informal-statement comments only; the load-bearing `_negl` content lives in the 4 protocol-side modules. Methodology could push the documentary skeletons one layer earlier so each carrier-side module ships its own `_collision_negl` / `_forgery_negl` theorem stub (Steps 2-5, recurring suggestion).
- **Impossible-axiom flag in ledger** — separate sub-category for axioms whose mathematical content is known impossible (Steps 2-3, surfaced when `commitHashE` and `commitHashBytesE` first bundled). This ledger now encodes it via the (d-pigeonhole-impossible) sub-tag.
- **Companion-module template** — naming convention `<Module>VCVio.lean`, isolation of `OracleSpec`/`OracleComp` material to keep `Decidable`-synthesis paths clean, documentary `…OC` definition + informal negligibility statement (Steps 1-5; pattern now stable across 5+4 = 9 modules).
- **Trust-density metric** — ratio of axioms-per-theorem; was 40/16 = 2.5 at first ledger emission; is now 26/(16+14 derived + 8 lifted at 4 packagings each = 30+) ≈ 0.68 if counting derived theorems. `colosseum-compose` should emit this delta automatically (Steps 1-6, recurring).
- **`temporal_state_mismatch` ≠ `temporal_intent_mismatch`** sub-classification for adversarial findings where a state-only invariant correctly state-checks but a temporal property would reveal a violation (prior ledger meta-finding 1; revalidated by the attestation-spec change record).
- **`design_intent_mismatch` ↔ `code_wrong-by-design`** classifier sub-category (attestation change record's methodology meta-finding 4).

## Discrepancies, unknowns, and emergent findings

### Discrepancies between change records

- **Ledger axiom counts vs change-record running totals**: Step 3's change record predicts post-refactor will land at ~14-18 axioms; Step 4's predicts ~14-19; Step 5 lands at 26 (Steps 6.0-6.3 are content-phase, no further axiom reduction). The 26 figure is correct (verified by summing per-module post-step columns: 4+4+9+5+4). The earlier predictions were optimistic about which (a)-bucket items could be discharged in Steps 4-5; the carrier-refinement blockers were heavier than the per-step predictions assumed.
- **Step 2 says `commitHashE` has 5 dependent theorems; Step 3 says 5 dependents on `commitHashE` plus 6 new on `commitHashBytesE`; Step 4 says 9 total dependents; Step 5 says 16 total dependents.** Each is correct for its time-slice (the dependent set grows as later steps bundle their own axioms and as the protocol-layer trust statement is extended). Step 5's "16" includes all derived theorems and `_negl` candidates. Latest authoritative: see this ledger's "Cross-bundle composition map".
- **Step 6.0's predicted Step 6.1 was "lift the dual-bundle theorem `handshake_sound`" — Step 6.1 ran this**, but Step 6.1 also surfaced that *three of four originally-dual targets had become triple-bundle*, deferring them to Step 6.2. Step 6.0's bundle-count expectation was correct for the original ledger state but incorrect for the post-Step-5 state. This is the Methodology v0.2 ask #2 above.

### Classification uncertainties (Part C)

- **`tdxVerifier` is bucketed (d) with two sub-tags** (single-negl on sound, preconditional on complete). Defensible because it's a single record axiom carrying two distinct over-strength shapes. An auditor could argue this should be 2 separate axiom rows.
- **`groth16Verifier` is bucketed (d-doubled-negligibility)**. The (d-disjunction-vs-decomposition) finding (Step 6.3) implies this is a meta-level concern about *how* the lift expands the disjunction — not a fifth sub-variant of (d) on the axiom itself. The bucket label here treats it as Step 5 did (doubled-negligibility); Step 6.3's framing is captured in the Methodology v0.2 asks rather than the bucket.
- **`serializeRawSessionCreateE` / `serializeRawSessionSetPubKeyE`** are (c) genuine because serde_json on a fixed schema *is* plausibly injective (no pigeonhole obstruction — the codomain `ByteSeq` is open-cardinality). This is structurally different from the `commit*E` embeddings, which face pigeonhole because their codomain is fixed-width `UserData`. Auditor could ask: does serde_json *actually* serialize injectively in the deployed encoder, including edge cases (NaN floats, key ordering)? Not in scope here.
- **`userDataOf*_eq_commitHash` bridge equalities** are (c) genuine: they connect `commitHashBytes ∘ serialize` with `commitHash` over `UserDataCommit`. Discharging them requires both a constructive byte-level serde_json model AND a constructive `commitHash` over abstract carriers. Could plausibly be reclassified (a) once carriers are concrete.

### Emergent findings from regeneration

- ~~**All 8 `_negl` lifts hide bundle axioms from their closures uniformly** — a stronger invariant than any single change record states. This is the *single most important observable* in the ledger: external auditors can take any lifted theorem, run `lean_verify`, and confirm that the bundle axiom is absent from the closure. The trust claim moves from "the bundle axiom is honest" (which it isn't, for the 4 (d) cases) to "the lift's parametric negligibility hypothesis is honest" (which it can be, given the discharge paths).~~ **[RETRACTED 2026-05-14]** The uniform invariant is satisfied vacuously: the `_negl` forms have no bundle axiom in closure *because they say nothing about Quartz*. A theorem of the form `negligible f → negligible f` (which is what each lift currently reduces to under the right adversarial instantiation) trivially has no axiom closure beyond standard logic. The invariant's intended reading — "the lift's parametric negligibility hypothesis stands in for the bundle axiom" — requires the advantage symbols to be tied to defined probability events; they are not. See Round A attacks #1, #2, #7 in `.colosseum/attacks/lean-negl-lifts-2026-05-14/claude.md`.
- **Companion-module count is asymmetric**: 5 carrier-side modules paired with 4 protocol-side modules. The asymmetry is structural — the carrier-side modules are 1-per-trust-primitive (Ecies, UserDataCommit, RawMessages, Dstack, Zkdcap) while protocol-side modules are sliced by bundle cardinality (foundations, dual, triple, quad). The 9 total is correct per the Step 7 brief.
- **The `_classical` corollaries form a load-bearing "exit door"**: downstream consumers (engineering code that wants the classical Prop form) get unchanged behaviour via `*_classical` re-exports. Removing the classical chain would break this exit door. The lift sequence preserves backward compatibility intentionally.
- **None of the 8 lifts use `Function.Injective` directly** — the spec-level injectivity claims (`commitHash_inj`, `commitHashBytes_inj`, etc.) are now derived theorems consumed by `_classical` corollaries only. The `_negl` chain bypasses injectivity entirely, substituting collision-resistance hypotheses on the underlying concrete hash.
- **`Ecies.lean` produced no (d)-bucket axioms** — alone among the 5 modules. The original ECIES roundtrip was demoted to a real theorem; the carrier axioms are (c). This is a methodology-positive observation: when the substrate supports a concrete spec-level model (here a deterministic `Ciphertext := PubKey × Plaintext`), no (d) emerges.

## What's next — recommendation — [REVISED 2026-05-14 after cycles 6.4–6.11]

Cycle-6.4-through-6.11 sequence complete. All 8 `_negl` lifts def-tied with content-bearing `Pr[…]`-based advantages, proven pointwise bounds, and bundle structures matching their classical proofs' actual probabilistic-failure mode counts. Round A attacks #1, #2, #3, #4 (partial at terminal), #11 are structurally closed across all lifts.

**Cycle outcome summary**:

| Cycle | Lift | Bundle (was → is) | Failure mode |
|---|---|---|---|
| 6.4 | `verifyGroth16_yields_decoded_negl` | single → single | Groth16 |
| 6.5 | `handshake_sound_negl` | dual → single | Groth16 |
| 6.6 | `handshake_binds_ecies_key_negl` | triple → single | Groth16 |
| 6.7 | `session_confidentiality_negl` | triple → zero | None |
| 6.8 | `session_confidentiality_via_extractor_negl` | triple → zero | None |
| 6.9 | `cross_component_transfers_conservation_negl` | triple → single | Groth16 |
| 6.10 | `cross_component_auction_winner_determinism_negl` | triple → single | Groth16 |
| 6.11 | `cross_component_session_bind_negl` (terminal) | quad (5-summand) → single | Groth16 |

7 of 8 lifts were over-bundled in the original. Six have a single surviving Groth16-soundness probabilistic-failure mode; two are degenerate-zero (deterministic-only — the spec models unconditional correctness, not CPA security).

**Open work**:

1. **Cycles 6.12–6.14** (deeper refactors than def-tying):
   - 6.12 **(done 2026-05-14, Option-(b))**: 7 `*Game_secure_of_*_bundle_secure` packagings renamed to `*_AGAINST_UNBOUNDED_ADVERSARIES` to surface the `IsPPT := True` placeholder gap at every call site. This is the cheap surface-side closure of Round A attack #5; the substantive Option-(a) closure (`IsPPT := PolyQueries`) is queued as part of cycle 6.14 below and requires cycle 6.13 as prereq.
   - 6.13 **(done 2026-05-20)**: wired `OracleComp ProtocolSpec` into all five adversary types across `ProtocolVCVio*.lean`; added the `protocolSpecHonestSim` honest-deterministic simulator; all 8 lifts rewired through `simulateQ`. Closes Round A attack #6. Change record `.colosseum/changes/2026-05-20T22-35-36Z-cycle-6.13-protocolspec-wiring.md`. Unblocks the Option-(a) `PolyQueries` instantiation.
   - 6.14.a **(done 2026-05-20)**: scaffolding-only. Added `IsPPT_proper {T} (𝒜 : ℕ → OracleComp ProtocolSpec T) : Prop := Nonempty (PolyQueries ...)` alongside the placeholder `IsPPT` (kept for backwards-compatibility with `_AGAINST_UNBOUNDED_ADVERSARIES` packagings). Four `Classical.decEq` local instances added for the abstract carriers (UserDataCommit, ByteSeq, TdxQuote, VerifyGroth16Query) to satisfy `PolyQueries`'s `[DecidableEq ι]` requirement. Build green at 2670 jobs. Change record `.colosseum/changes/2026-05-20T22-55-00Z-cycle-6.14a-ispptproper-scaffolding.md`.
   - 6.14.b/c **(done 2026-05-20)**: closes Round A attack #5 substantive content side. Generic `IsPPT_proper_of_bind_pure_comp` preservation lemma in ProtocolVCVio.lean (proof: `← map_eq_bind_pure_comp; isPerIndexQueryBound_map_iff`). 5 per-reduction corollaries — one-line invocations of the generic lemma for each reduction (`reduce_handshake_to_groth`, `reduce_binds_to_groth`, `reduce_transfers_to_groth`, `reduce_auctionDeterm_to_groth`, `reduce_crossSessionBind_to_groth`). 7 new `*_AGAINST_PPT_ADVERSARIES` packagings parallel to the existing `*_AGAINST_UNBOUNDED_ADVERSARIES`: each takes a `reduce_preserves_ppt` hypothesis bundling the per-summand `IsPPT_proper`-preservation and discharges via that. The `_AGAINST_UNBOUNDED_ADVERSARIES` packagings are retained in parallel for callers wanting the all-adversaries claim. Build green at 2670 jobs; 0 sorry. Change record `.colosseum/changes/2026-05-20T23-25-00Z-cycle-6.14bc-ppt-packagings.md`.
   - 6.15 **(done 2026-05-20)**: def-tied `commitHashCollisionAdv` and `commitHashBytesCollisionAdv` via `Pr[…]` collision events (`p.1 ≠ p.2 ∧ commitHash p.1 = commitHash p.2`), wrapped through `simulateQ protocolSpecHonestSim`. Type-only abbrevs `CommitHashCollisionAdvantage`/`CommitHashBytesCollisionAdvantage` retained for backwards-compatibility with existing packagings. Closes Round A attack #8 surface-side content gap (the advantage is no longer a free symbol). Substantive Option-(a) closure (replacing the impossible `commitHashE` axiom with a random-oracle model) remains blocked on `[Fintype UserData]` carrier refinement. Build green at 2670 jobs. Change record `.colosseum/changes/2026-05-20T23-45-00Z-cycle-6.15-collision-adv-deftying.md`.
   - 6.16 **(done 2026-05-20)**: first carrier refinement. `Nonce` refined from `axiom Nonce : Type` to `abbrev Nonce : Type := BitVec 256`. Axiom count drops 26 → 25. Verified via `lean_verify` that `Nonce` is gone from the closure of every theorem that previously carried it. `abbrev` (reducible) preserves all definitional equalities downstream, so no other theorem statement or proof changes. Build green at 2670 jobs. Change record `.colosseum/changes/2026-05-21T00-10-00Z-cycle-6.16-nonce-carrier-refinement.md`. Next carrier refinements queued in change-record order of tractability (MrEnclave, UserData, Plaintext, DomainSep, Addr).
   - 6.17 – 6.20 **(done 2026-05-20)**: carrier refinement batch. `MrEnclave` → `BitVec 384` (6.17, Intel TDX MRTD 48-byte SHA-384 digest); `UserData` → `BitVec 512` (6.18, DCAP report_data 64-byte slot — highest-leverage refinement, provides `Fintype UserData` which unblocks the `commitHashE` random-oracle discharge); `PrivKey` → `BitVec 256`, `PubKey` → `BitVec 264`, `Plaintext` → `List UInt8` (6.19, ECIES carriers); `DomainSep` → `List UInt8`, `Addr` → `String`, `ByteSeq` → `List UInt8` (6.20, remaining carriers). Same cycle 6.20 also demoted the three (a)-bucket named-constant axioms (`rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey`) to concrete `def`s with documentary values (`"QUARTZ-HS-V1".toUTF8.toList`, `"xion1quartzdeploymentaddress"`, `0 : BitVec 264`). Original-inventory axiom count: 25 → 14 (cumulative from baseline 40 → 14 = –65%). (a)-bucket count: 3 → 0. (c)-bucket count: 18 → 10. (d)-bucket count: unchanged at 4 (the four bundle axioms still require external or random-oracle discharge). Build green at 2670 jobs across all four cycles, zero new sorry. Honesty caveat: `commitHashE` and `commitHashBytesE` are now visibly pigeonhole-impossible at the type level (`UserDataCommit` infinite via `List UInt8`/`String` fields, codomain `BitVec 512` finite); no existing proof attempts to use this to derive `False`. Substantive Option-(a) closure of (d-pigeonhole-impossible) via VCV-io's `randomOracle` + birthday bound is now tractable and queued as cycle 6.21. Change record `.colosseum/changes/2026-05-21T00-40-00Z-cycles-6.17-6.20-carrier-refinement-batch.md`.

2. **Methodology v0.2 back-port**: send the **over-bundling meta-finding** to the colosseum agent — bundle-count derivation must come from per-conjunct failure-mode analysis of the classical proof, not from a static axiom-count classifier. Also send the **degenerate-zero-advantage sub-kind** observation from cycles 6.7/6.8 — when a lift's advantage proves identically zero, the cycle should explicitly state whether the spec is intentionally not modelling the relevant probabilistic phenomenon (yes/no).

3. ~~**Round C adversarial review**: 4 unattacked Quint specs (handshake, attestation, pingpong, transfers), 39 Kani harnesses, 43 Verus invariants. Background-runnable; not blocking.~~ **[UPDATED 2026-05-20]** Round C complete 2026-05-14 (27 distinct attacks, 3 critical, fixes landed in commits `6e90f51`, `981d1a1`, `4e23075`). Round D complete 2026-05-14/15 against the Verus prototype tree (30 distinct attacks, 5 critical; Critical 1 fixed in commit `ec24934`, four Round D blockers remain — see banner and "Round D Verus-prototype blockers" subsection above). Kani harnesses (39 unsampled) are the only spec-class surface that has not been adversarially reviewed.

4. **External discharges** (mostly upstream-paced):
   - `negligible_groth16_ks` — ArkLib Groth16 KS coverage (upstream roadmap)
   - `negligible_circuit` — Lean reference DCAP verifier (multi-month, no owner)
   - `negligible_tdx` — PCK-signature unforgeability reduction
   - `negligible_commitHash` / `_commitHashBytes` — VCV-io random-oracle + birthday bound + `[Fintype UserData]`

**[REVISED 2026-05-20 after Round D + cross-critique + Critical 5 substantive cycle]** All five Round D criticals are closed on the Colosseum-agent side. One named follow-up remains on the Quartz-agent side: Critical 4 production-side hook at `crates/contracts/core/src/handler/execute/attested.rs:94-99` (decode `zkdcap_public_inputs` or `zkdcap_journal`, verify-equal encoded `report_data` and `compose_hash` against the wrapper-validated fields). The Verus spec already requires this binding; the production code does not yet enforce it.

This fork is the canonical destination for the verification surface; the original informalsystems/cycles-quartz upstream is unmaintained and does not carry the dstack TDX / zkdcap / Xion changes the refactor depends on. No upstream PR is planned. Near-term work continues here.

Next near-term Quartz-side item that was already on the queue: demote `rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey` to `def`s once their carriers are refined to concrete byte strings. That refactor would close out the (a) bucket entirely. Methodology-side, the v0.2 back-port has progressed past the Round-A meta-finding into v0.4 candidates O through T at `colosseum/methodology-v0.4-candidates.md` (cross-critique as standard post-fan-out, defense round, intent-tightening, re-cross-critique, ghost-variable encoding, `--variant high` default for spec-class dispatch). The external Quartz discharges (concrete hash spec, ArkLib integration, reference DCAP verifier, carrier refinement) remain upstream-blocked at the same cadence as before; "upstream" here refers to the dependency libraries (ArkLib, Mathlib, k256, the gnark circuit), not to informal's cycles-quartz.
