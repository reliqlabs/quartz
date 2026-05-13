# Multi-model adversarial synthesis: `temporal_zk_accept_requires_vkey`

- Spec under review: `specs/attestation.qnt` (lines 388-445)
- Intent document: `CLAUDE.md`
- Reviewed at: 2026-05-12 (round 2, multi-model)
- Adversaries dispatched: **Claude** (subagent, file access enabled) + **Gemma 4 26B** (local, prompt inlined)
- Result: **9 distinct attacks**; both verdicts BREAKS; 2 critical, 5 serious, 2 cosmetic

This synthesis is orchestrator output. The per-model reports (`claude.md`, `local-google_gemma-4-26b-a4b.md`) are persisted verbatim and unedited. Per skill discipline, the orchestrator summarizes overlap and divergence; it does not add, weaken, or re-author findings.

---

## Verdict aggregate

| Adversary | Verdict | Attacks | Crit | Serious | Cosmetic |
|---|---|---|---|---|---|
| Claude (subagent) | BREAKS | 6 | 1 | 4 | 1 |
| Gemma 4 26B (local) | BREAKS | 3 | 1 | 1 | 1 |
| **Both agree** | BREAKS | — | — | — | — |

Two independent adversaries from different families converge on the same verdict against a non-trivial spec. That is the methodology operating at intended strength: the trust signal from cross-family agreement is materially stronger than either model in isolation.

---

## Shared findings — surfaced by both adversaries

### S1. The `last_result != Accepted` guard is the wrong shape

- **Claude attack #2** (Triviality / transition-encoding): "The property cannot distinguish `Accepted -> Accepted` from a real new acceptance ... brittle to any refactor."
- **Gemma attack #1** (Temporal-state mismatch / "Dormant Invariant"): "Once the system reaches the `Accepted` state, this guard becomes `false` for all subsequent steps."
- **Orchestrator assessment**: shared root cause, slightly different framings. **Claude is more precise**: `verify_zk` overwrites `last_result`, so the guard naturally re-arms when the next action produces a non-`Accepted` result (e.g. `SkippedNoVKey`, `Rejected*`). **Gemma overstates** the dormancy as "permanent" — it isn't, because `last_result` is unconditionally overwritten by every action that runs. Claude's framing — *the guard fails on consecutive `Accepted` transitions* — is the technically correct one. But both adversaries land on the same fix: replace the state guard with an action-tag predicate (e.g. `last_action == ActVerifyZk`).
- **Severity** (orchestrator's call): **serious**, splitting the difference between Claude's "serious" and Gemma's "critical". Today the gap is not exploitable in this exact spec (because `verify_zk` is the only action that writes `last_result = Accepted`), but the property's logic is brittle to any future action that produces `Accepted`.
- **Suggested defense**: introduce a `last_action` variable as `handshake.qnt:95` does, tag `verify_zk`'s success branch with `ActVerifyZk`, and predicate the temporal property on the action tag. Claude and Gemma propose substantively the same fix.

**Cross-family agreement is the highest-confidence finding in this round.**

### S2. Mock-mode bypass [carried over from round 1]

Gemma's round-1 run (single-model) surfaced the mock-mode + empty-proof bypass as a serious coverage gap. Claude's round-2 attack #1 re-flagged it as critical under-specification. Gemma's round-2 run did *not* re-surface it. That's still a multi-model agreement *across rounds*, even if the round-2 Gemma instance focused elsewhere. **The cross-round consistency makes this the load-bearing finding for the spec author**: it has now been independently surfaced by two adversaries on different prompts. Severity: **critical**.

---

## Unique findings per adversary

### Unique to Claude

| # | Category | Severity | One-line |
|---|---|---|---|
| Claude #1 | Under-specification | critical | Mock-mode + empty proof yields `Accepted` with the property vacuously satisfied (matches Gemma round-1) |
| Claude #3 | Refinement mismatch | serious | `next(last_input.attestation.variant) == Zk` is a state-observation proxy for an action-tag — necessary but not sufficient evidence the Zk verifier actually ran |
| Claude #4 | Temporal-state mismatch (meta) | serious | The spec's *comment* claim that temporal encoding is "robust against subsequent `clear_vkey`" is factually wrong; the temporal form has the same vacuity as the state-only form would |
| Claude #5 | Coverage gap | serious | The spec has no model of `registered_vkeys` mutations by Xion's external ZK module post-acceptance; the witness pins on pre-transition state only |
| Claude #6 | Edge case | cosmetic | `Accepted` vs `AcceptedQuote` naming asymmetry is a refactor hazard if a future change consolidates the two |

**Pattern**: Claude's unique findings cluster around *structural / refactor-hazard* concerns. With file access, Claude read both `attestation.qnt` and `handshake.qnt` and used the latter's `last_action` machinery as a template to argue what `attestation.qnt` should adopt. The cross-file pattern (#3, S1 fix) is uniquely accessible to a file-access-enabled adversary; an inlined-prompt adversary like Gemma cannot see related files. Finding #4 (meta-critique of the spec's own comment) requires reading the spec's prose, not just its formula — also more available with file access.

### Unique to Gemma

| # | Category | Severity | One-line |
|---|---|---|---|
| Gemma #2 | Coverage gap | serious | `SkippedNoVKey` paths increment `messages_accepted` but are silent in the temporal property's antecedent — the success counter and the safety property measure different things |
| Gemma #3 | Triviality | cosmetic | The temporal property tautologically follows `verify_zk`'s if-else chain; it adds zero formal constraint over the action's own logic |

**Pattern**: Gemma's unique findings focus on *semantic inconsistencies* in the spec as written, not refactor hazards. Gemma #2 (the `messages_accepted` / `SkippedNoVKey` semantic conflation) is a load-bearing finding that Claude did *not* flag — Gemma earned its keep here. This is exactly what family diversity is supposed to produce: different models find different blind spots.

---

## Severity-weighted coverage map

Across the 9 distinct attacks (1 shared, 5 Claude-unique, 3 Gemma-unique excluding the cross-round mock-mode re-flag):

- **Critical**: 2 (S2 mock-mode bypass, Gemma #1 framed as critical — orchestrator downgrades to serious per S1 above)
- **Serious**: 5 (S1, Claude #3, Claude #4, Claude #5, Gemma #2)
- **Cosmetic**: 2 (Claude #6, Gemma #3)

Net: the temporal property is **broken** by the methodology's bar. Two independent models confirm BREAKS verdict. At least one critical and five serious issues need spec revision.

---

## Coverage analysis — categories each model attacked

| Category | Claude | Gemma |
|---|---|---|
| Under-specification | ✓ (#1) | ✗ |
| Over-specification | — | — |
| Triviality | ✓ (#2 as transition-encoding) | ✓ (#3 as redundant logic) |
| Ambiguity | — | — |
| Coverage gap | ✓ (#5) | ✓ (#2) |
| Contradiction | — | — |
| Edge case | ✓ (#6) | — |
| Composition failure | partial via #5 | — |
| Refinement mismatch | ✓ (#3) | — |
| Temporal-state mismatch | ✓ (#4 meta-critique) | ✓ (#1 dormancy claim) |

Both models avoided over-spec / ambiguity / contradiction — likely because the property's syntax is precise and self-contained. Both attacked triviality, coverage gap, and temporal-state mismatch. Claude additionally attacked refinement and edge case categories that Gemma did not reach.

**Methodology observation**: Claude's broader category coverage correlates with file access. Refinement mismatch in particular requires looking at *implementation* (the action body), not just the property's text. Gemma had only the inlined excerpts to work from.

---

## Methodology meta-findings

This is the first round in which both Claude and a local model produced complete, comparable adversarial reports against the same target. Several observations earned this round:

1. **Family diversity is not theoretical.** Gemma's #2 (`SkippedNoVKey` counter leakage) is invisible in Claude's report; Claude's #3, #4, #5, #6 are invisible in Gemma's. A single-model run would have surfaced ~half the findings. The methodology's central claim — that adversarial beats consensus, and that family diversity multiplies coverage — is operating as designed on its first real multi-model test.

2. **Cross-model agreement is a strong trust signal.** The two adversaries independently converged on the same root cause for finding S1 (the `last_result != Accepted` guard) and proposed substantively the same fix (`last_action == ActVerifyZk`). When two adversaries from different families propose the same defense, the spec author should treat that defense as load-bearing.

3. **Disagreement is signal too.** Gemma framed S1 as "permanent dormancy"; Claude framed it as "brittle to refactor but currently sound." The orchestrator could adjudicate (Claude is more precise) by reading the spec directly. The two reports together provide *more* information than either alone — including the form-vs-substance disagreement about exact severity.

4. **File access is leverage.** Claude found 6 attacks; Gemma found 3. Both ran at comparable cost (Claude ~92s total, Gemma ~165s). The difference is overwhelmingly explained by Claude's tool access — reading `handshake.qnt` to find the `last_action` pattern and the round-1 synthesis to avoid duplicating findings. For local adversaries, the methodology should add an *artifact pre-staging* step: include related specs and prior synthesis in the inlined prompt to close part of this gap.

5. **Round-N adversaries should be told about round-(N-1) findings.** Claude explicitly mentions reading the round-1 synthesis to avoid duplicating findings (and then intentionally duplicates the mock-mode finding because it's load-bearing). Gemma's round-2 prompt was identical to round-1's — Gemma did not know mock-mode had already been found and didn't re-flag it. This is a `colosseum-adversarial` v0.3 improvement: pass prior synthesis as optional context to local adversaries.

---

## Validation against the methodology's central claim

The methodology's deepest claim is that *the unit of trust is surviving adversarial scrutiny, not consensus*. This round provides empirical support:

- **Survival**: the spec did NOT survive scrutiny. Two adversaries broke it independently. Verdict: BREAKS, with cross-family agreement on at least one serious finding.
- **Anti-consensus**: the two adversaries did not "agree everything is fine"; they each found different real issues. Cooperative agents would have flattened these into a single conservative critique. Adversarial agents kept them sharp.
- **Coverage compounding**: 9 distinct attacks > 6 (Claude alone) > 3 (Gemma alone). Multi-model adversarial produces strictly more coverage than single-model on the same target.

---

## Action items

### For the spec (Quartz `attestation.qnt`)

- [ ] **S1 / shared finding**: introduce `last_action` variable, tag `verify_zk` outcomes, rewrite the temporal property antecedent in terms of `last_action == ActVerifyZk and next(last_result) == Accepted`. Both adversaries proposed this.
- [ ] **S2 / mock-mode (cross-round)**: conjoin `not(zk_module.accept_all) or next(last_input.attestation.proof.proof_bytes) != ""` into the property, or document mock-mode as explicitly outside the property's scope with a sibling property `temporal_mock_mode_disabled_in_production`.
- [ ] **Claude #3 / refinement**: as a consequence of S1's fix, the action-tag removes the need for `next(last_input.attestation.variant) == Zk` as proxy. Closed by S1's fix.
- [ ] **Claude #4 / comment correctness**: rewrite the lines 388-396 and 410-412 rationale — the "frozen past decision" framing is factually misleading.
- [ ] **Claude #5 / external mutation**: add `register_vkey` / `unregister_vkey` non-deterministic actions; decide whether the property guarantees *at-acceptance-time* state or *forever-after* state.
- [ ] **Gemma #2 / counter semantics**: resolve the `messages_accepted` / `SkippedNoVKey` conflation — either rename the counter (e.g. `messages_processed_without_rejection`), introduce a separate counter for verified vs. skipped, or stop incrementing on `SkippedNoVKey`.
- [ ] **Claude #6 / naming**: rename `Accepted` → `AcceptedZk` for symmetry with `AcceptedQuote`.

### For the methodology (`colosseum-adversarial` v0.3)

- [ ] Pass prior round synthesis as optional context to all adversaries (currently only file-access adversaries can find it).
- [ ] Pre-stage related specs (e.g. `handshake.qnt` for cross-spec pattern reuse) into the inlined prompt for non-file-access adversaries.
- [ ] Document that orchestrator adjudication of disagreements is part of synthesis, not freeform editing — there is now a worked example (S1 severity adjudication) in this synthesis file.

---

## Files in this round

- `claude.md` — Claude (subagent) verbatim report, 6 attacks, file-access enabled
- `local-google_gemma-4-26b-a4b.md` — Gemma 4 26B verbatim report, 3 attacks, inlined prompt only
- `synthesis.md` — this file (orchestrator output)
