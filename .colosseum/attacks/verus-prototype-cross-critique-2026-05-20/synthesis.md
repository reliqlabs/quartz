# Cross-critique synthesis: Round D Criticals 4 and 5

- Target findings: Round D Critical 4 (zkdcap public_inputs not bound to wrapper compose_hash/user_data) and Critical 5 (pub_key_matches_sk does not survive Import::import).
- Reviewed at: 2026-05-20
- Methodology: v0.4 Ask O (cross-critique as standard post-fan-out step) using cloud-only voices per user request, no local LM Studio voices.
- Adversarial lineup (6 voices total, 5 productive):

  | Voice | Channel | Model | Elapsed | C4 | C5 |
  |---|---|---|---|---|---|
  | Claude (subagent) | Agent | claude-opus-4-7 (file-access) | 172s | DEFEND | THIRD_OPTION |
  | GPT-5.5 | opencode/openai | openai/gpt-5.5 (OAuth) | 83s | DEFEND | THIRD_OPTION |
  | GPT-OSS | opencode/burnt | burnt/gpt-oss-120b (variant=high) | 113s | DEFEND | DEFEND |
  | Kimi | opencode/burnt | burnt/kimi-k2-6 (variant=high) | 270s | DEFEND | THIRD_OPTION |
  | Nemotron | opencode/burnt | burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b (variant=high) | 132s | DEFEND | DEFEND |
  | Gemini-flash-lite | opencode/burnt | burnt/gemini-3-1-flash-lite | 10s | (empty stdout) | (empty stdout) |

Per-voice reports persisted verbatim alongside this synthesis. Gemini-3-1-flash-lite returned empty stdout at 10s, presumably a refusal or output-channel issue. The other five voices all produced structured responses.

## Critical 4 outcome: ratified

5-of-5 productive voices vote DEFEND. The finding stands as critical-severity.

Cross-voice agreement on the attack mechanism: production `DstackZkAttestation::handle` at `crates/contracts/core/src/handler/execute/attested.rs:94-99` constructs the `QueryVerifyGnarkRequest` from `self.zkdcap_proof` and `self.zkdcap_public_inputs` verbatim, with no extraction or equality check against `self.user_data` or `self.compose_hash`. The outer `Attested<M, A>::handle` wrapper at `attested.rs:179-186` validates self-declared attestation fields, not values extracted from the proof's public inputs. An attacker can submit a valid Groth16 proof for enclave A while declaring user_data and compose_hash matching enclave B; the wrapper's pre-checks pass against the self-declared fields, the ZK module verifies the proof against the supplied public inputs, and the contract accepts a proof that does not attest to the claimed enclave.

Claude's subagent voice additionally confirmed the gnark circuit at `zkdcap/circuits/dcap-gnark/circuit/types.go:100-107` exposes MrTd, RTMRs, and ReportData as public inputs, so the cryptography itself is sound. The gap is purely at the on-chain wrapper layer: the public inputs are not parsed, so the binding between the proof and the wrapper's claimed values is never checked.

GPT-5.5 noted an additional production detail: `DstackZkAttestation` carries a `zkdcap_journal` field whose comment claims it contains the fields the contract needs, but the handler never decodes or checks it. The intended binding mechanism exists in the message structure but is unused.

Suggested fix shape, with cross-voice convergence: production side, the handler must decode `zkdcap_public_inputs` (or `zkdcap_journal`) and verify-equal the encoded `report_data` against `self.user_data` and the encoded compose_hash against `self.compose_hash` before accepting `verified == true`. Verus side, add an uninterpreted predicate `proof_journal_binds(proof, public_inputs, expected_compose_hash, expected_user_data)` and require it on the Ok branch of `dstack_zk_handle`. Both sides need to land together; either alone is insufficient.

## Critical 5 outcome: refined

3-of-5 voices vote THIRD_OPTION (Claude, GPT-5.5, Kimi). 2-of-5 vote DEFEND (GPT-OSS, Nemotron). The three THIRD_OPTION voices independently converge on the same refinements:

**Refinement 1** (Claude, GPT-5.5, Kimi): the original finding's framing as a `DefaultKeyManager`-specific issue understates the production exposure. `CLAUDE.md` states the production default is `DstackKeyManager`, not `DefaultKeyManager`. `DstackKeyManager` has the same mutate-on-import shape at `dstack.rs:164-180` plus an additional risk path: `derive_from_dstack` at `dstack.rs:56-62` can fall back to a random key on KMS unavailability during restore, producing a different `sk` without updating the contract's stored pub_key. The Verus prototype does not model `DstackKeyManager` at all (Round D synthesis Critical 19, separate finding). Fixing only `DefaultKeyManager` would miss the production-relevant attack surface.

**Refinement 2** (GPT-5.5, Kimi): the named theorem `pub_key_matches_sk` at `key_manager.rs:184-194` is currently a propositional tautology of the form `forall |k| verifying_key_spec(k.sk) == verifying_key_spec(k.sk)`. The actual binding contract is in the exec function `pub_key`'s postcondition at `key_manager.rs:150-153`, not in the named theorem. Both voices flagged this as a separate Round D-era issue (tracked at synthesis.md as Claude attack #17). The refined fix needs to first make the named theorem non-vacuous (state the binding for an arbitrary `km`, not the tautology), then address the temporal-binding gap.

**Refinement 3** (Claude, GPT-5.5): the suggested defense of a `pub_key_published` ghost field on `DefaultKeyManager` is in the wrong layer. The published pub_key lives in contract/session state (set by `session_set_pub_key.rs:13-21`), not inside the key manager. The right abstraction is a small lifecycle model spanning publish, backup, and restore, with a ghost `contract_pub_key` and an invariant that restore either preserves `verifying_key_spec(km.sk) == contract_pub_key` or marks the session unhandshaken. Claude's subagent voice further noted the production handler `session_set_pub_key` errors when the pub_key is already set, so after an enclave-side import there is no documented key-rotation path; the contract pub_key becomes permanently stale.

**Refinement 4** (Kimi): the severity downgrades from "critical" to "serious" because the modeled-system attack scenario for `DefaultKeyManager` is not clearly reachable. Legitimate `export` + `import` preserves the key (the roundtrip property closed by Critical 1). The stale-pub_key scenario requires `import` with different data after handshake, which has no production code path on `DefaultKeyManager`. The genuinely-critical instance is on `DstackKeyManager`'s KMS-fallback path, which is unmodeled.

Synthesized fix shape: address Critical 5 as a combined remediation rather than the original ghost-field-on-DefaultKeyManager fix. Specifically:

a. Replace the tautological `pub_key_matches_sk` ensures with a non-vacuous statement of the binding for an arbitrary `km` (Refinement 2).
b. Model `DefaultKeyManager` import as a mutating operation, prove the snapshot binding holds at the moment of import but warn explicitly that it does not survive subsequent calls (Refinement 1, narrow).
c. Add a session/lifecycle ghost layer (`contract_pub_key`, `session_handshaken` flag) and prove that any state transition that changes `km.sk` either preserves the binding or invalidates the session (Refinement 3). This is the substantive content the original C5 was reaching for, expressed at the right layer.
d. As a production hardening, either remove the `Import` impls (cheap, safe, requires re-init from scratch on the rare key-rotation case) or add a `session_rotate_pub_key` contract message that resets the session state when the enclave key changes (Claude's subagent suggestion). The current path is "no rotation path exists" which is itself a serious deficiency.
e. Model `DstackKeyManager` in the Verus prototype (closes Round D Critical 19 simultaneously). This is the production default and is where the KMS-fallback temporal-stale-key risk is concrete.

Severity: 3 of 5 voices say the original "critical" label overstates the reachable risk on the modeled subsystem. Treat as "serious modeling gap with a critical production hardening implication on the unmodeled DstackKeyManager path." The upstream PR description should call this out as a known-uncovered area rather than as a single-line fix.

## Net recommendation

Land Critical 4 in the upstream PR as a real fix on both the production and Verus sides. The shape is unambiguous: production handler decodes zkdcap_public_inputs/journal and verify-equals the encoded compose_hash and report_data against the wrapper's claimed values before accepting, plus a Verus spec predicate `proof_journal_binds` required on the Ok branch.

Do not land Critical 5's original ghost-field-on-DefaultKeyManager fix as written. Land the refined remediation per Refinement 3 + 4 + 5: fix the tautological theorem, add a session-lifecycle ghost layer, decide on production key-rotation policy (remove Import or add a rotation message), and model DstackKeyManager. The refined work is larger than Critical 5's original scope and should be tracked as its own cycle rather than folded into the upstream PR. The PR description should call out Critical 5 as a known-uncovered area pending the lifecycle-modeling cycle.

For the v0.4 methodology Ask O ledger: this cross-critique pass shifted one finding from BLOCKER (must-fix-pre-PR) to KNOWN-GAP (call-out-in-PR-description, fix in a follow-up cycle), and confirmed the other as BLOCKER. Three of five voices producing useful THIRD_OPTION verdicts on the more complex finding validates the methodology: a single voice's framing of a finding can miss the right fix layer, and cross-critique surfaces the refinement before commitment.

## Methodology notes for v0.4 archives

The two DEFEND-on-C5 voices (GPT-OSS, Nemotron) both took Claude's original framing at face value without questioning whether `DefaultKeyManager` is the production path. They reasoned correctly within the original framing but did not surface the DstackKeyManager-is-production-default refinement. The three THIRD_OPTION voices (Claude subagent, GPT-5.5, Kimi) reached the refinement independently by either reading CLAUDE.md (Claude subagent), reading dstack.rs (GPT-5.5), or both (Kimi). This is a data point for the v0.4 Ask O claim that cross-critique adds value over consensus-style multi-vote: the DEFEND consensus (3 voices) would have been a false positive on the original framing if not cross-checked.

Gemini-3-1-flash-lite returned empty stdout at 10s. The model may have refused the request, returned no content for filter reasons, or hit an opencode CLI handling issue. Excluded from the tally. The colosseum-bug doc should track this as a fresh observation about gemini-flash-lite on the gateway under cross-critique-style prompts.

Variant=high was enabled on the burnt gateway voices (gpt-oss, kimi, nemotron) per v0.4 Ask T. The OpenAI direct voice rejects the temperature parameter and does not accept variant flags; openai/gpt-5.5 ran without variant. Both kimi (270s) and nemotron (132s) elapsed well under the gateway Bug 3 ~240s ceiling, so the variant=high reasoning effort did not push past the cap on this prompt size (~1.9K tokens).
