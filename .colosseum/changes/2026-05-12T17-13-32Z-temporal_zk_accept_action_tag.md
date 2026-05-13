# Change record: rewrite `temporal_zk_accept_requires_vkey` with action-tag provenance

- Date: 2026-05-12T17-13-32Z
- Classification: **spec-touching** (full change-loop, not impl-only)
- Driven by: `.colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/synthesis.md`
- Files touched: `specs/attestation.qnt` only (Lean / Verus / Kani not affected — this is a spec-axis change)

## Description

After a multi-model adversarial review (Claude + Gemma) of `temporal_zk_accept_requires_vkey`, both adversaries proposed substantively the same fix: replace the `last_result != Accepted` guard (a state proxy for "the action just fired") with an explicit action provenance tag. The rewrite also conjoins a mock-mode clause that closes the cross-round-confirmed critical finding (mock-mode + empty-proof bypass).

This change record covers stages 4-7 of the `colosseum-change` workflow.

## Stage 1: Triage

- **Classification**: spec-touching. The temporal property changes shape; the implementation changes nothing semantically (only adds a provenance tag).
- **Affected surface**: `specs/attestation.qnt` (single file).
- **Why full loop**: a property revision can silently invalidate downstream verification (e.g. a re-verification of an existing invariant that referenced the old form, or a Lean refinement that imports the temporal property as an axiom). Verified there are no such downstream references.

## Stage 2: Intent revision

CLAUDE.md doesn't describe `temporal_zk_accept_requires_vkey` at this level of detail. Intent doc unchanged.

The implicit intent — "every accepted Zk message must, at acceptance time, have been verified against a registered vkey, unless mock mode is explicitly enabled" — was made *explicit* in the revised property's antecedent and RHS. No intent.md edit was required, but a real Colosseum project would have one and would have to revise it.

## Stage 3: Impact analysis

| Artifact type | Touched | Notes |
|---|---|---|
| Quint invariants in `attestation.qnt` | `temporal_zk_accept_requires_vkey` (rewrite); `inv_zk_accept_requires_vkey` (left as `true` stub with a now-stale comment) | Stub left untouched intentionally |
| Quint invariants in `handshake.qnt` | none | Independent spec |
| Lean theorems | none reference this property by name | `proofs/lean/` examined; no references |
| Verus annotations | none | Spec-axis change; no exec-axis impact |
| Kani harnesses | none | Spec-axis change |
| Tests | none | No integration tests bind this property's name |
| Composition theorems in ledger | none directly | `cross_component_session_bind` rides on Lean axioms, not this Quint property |

Conclusion: change is contained to the one Quint property.

## Stage 4: Spec revisions (upstream-first)

Edits to `specs/attestation.qnt`:

1. **Added `type Action`** enumeration with five variants: `ActNone`, `ActVerifyQuote`, `ActVerifyZk`, `ActEnableMock`, `ActClearVkey`
2. **Added `var last_action: Action`** alongside existing state variables
3. **Added `last_action' = ActNone`** to `init`
4. **Added `last_action' = ActVerifyQuote`** to each of the 3 branches of `verify_quote`
5. **Added `last_action' = ActVerifyZk`** to each of the 6 branches of `verify_zk`
6. **Added `last_action' = ActEnableMock`** to `enable_mock`
7. **Added `last_action' = ActClearVkey`** to `clear_vkey`
8. **Rewrote `temporal_zk_accept_requires_vkey`**:

   ```quint
   temporal temporal_zk_accept_requires_vkey = always(
     (next(last_action) == ActVerifyZk
      and next(last_result) == Accepted)
     implies (config.zkdcap_vkey != ""
              and zk_module.registered_vkeys.contains(config.zkdcap_vkey)
              and (not(zk_module.accept_all)
                   or next(last_input.attestation.proof.proof_bytes) != ""))
   )
   ```

9. **Replaced the misleading comment** with a clear rationale that names the action-tag motivation (Claude attack #4 / Gemma attack #1 share root) and the mock-mode conjunct (Claude attack #1 / Gemma round-1 finding).

12 `last_action'` assignments injected via scripted edit, plus 1 type declaration, 1 var declaration, and one rewritten temporal property + comment.

## Stage 5: Code revisions

N/A — pure spec-axis change.

## Stage 6: Re-verification

### `quint typecheck`

```
returncode 0, no errors
```

### `quint run` (random simulation, 2000 samples × 10 steps)

```
[ok] No violation found (33ms at 60606 traces/second).
Trace length statistics: max=11
```

The state-only stub `inv_zk_accept_requires_vkey = true` trivially passes (intentional; the real obligation is in the temporal property).

### `quint verify --temporal` (Apalache, max-steps=4)

**`[violation] Found an issue (2182ms).`**

Counterexample trace (final state):

```
config:  { compose_hash: "aabbccdd", zkdcap_vkey: "zkdcap-gnark" }
zk_module: { accept_all: TRUE, registered_vkeys: Set("zkdcap-gnark") }
last_action: ActVerifyZk
last_result: Accepted
last_input.attestation.variant: Zk
last_input.attestation.proof.proof_bytes: ""
messages_accepted: 1
```

The trace witnesses exactly the mock-mode + empty-proof bypass that Round 1 Gemma and Round 2 Claude #1 flagged adversarially. **The methodology produced a mechanically-verifiable counterexample to the property**, not just an adversarial assertion. This is the highest-strength signal the methodology can emit.

### Failure classification

Per `colosseum-failure-classifier`:

- **Classification**: `code_wrong` (the implementation admits a path the property — now correct after the rewrite — forbids).
- **Confidence**: high.
- **Evidence**: `verify_zk` line 245 (`else if (proof_bytes == "" and not(accept_all))`) means when `accept_all == true`, an empty proof bypasses the rejection and falls through to the final `else` setting `last_result = Accepted`. This is *deliberate* per the comment, but the property — encoding the safety intent — forbids it.
- **Recommended action**: this is a design-decision point for the spec author, not a mechanical fix:
  - **Option A** — accept the property's verdict as the safety claim; tighten `verify_zk` so mock mode does NOT accept empty proofs. Mock mode then means "skip cryptographic verification, but require a non-empty proof". The property and implementation align; the design intent of mock mode is narrowed.
  - **Option B** — accept the implementation's permissiveness as the design choice; scope-out mock mode in the property (either weaken the conjunct or add `temporal_mock_mode_disabled_in_production`). Document explicitly that "accepted Zk messages under `accept_all` are not bound by the vkey-and-proof safety claim" — i.e. mock mode is by design a hole, and the methodology surfaces it as such rather than hiding it.

Both options are correct refinements of the methodology's current state — what they share is making the trade-off visible.

## Stage 7: Composition re-check

The integration ledger at `.colosseum/ledger.md` is unaffected — `cross_component_session_bind` and the Lean protocol theorems do not depend on this Quint property by name. The composition layer is untouched.

## Stage 8: Outstanding follow-ups from the adversarial synthesis

This change record addresses the load-bearing fixes (S1, S2, Claude #4). The remaining adversarial findings remain open for future changes:

- [ ] **Claude #5 — external `registered_vkeys` mutation**: add nondet `register_vkey` / `unregister_vkey` actions in step, or document that the property only guarantees vkey state *at acceptance time*.
- [ ] **Gemma #2 — counter semantics**: resolve `messages_accepted` / `SkippedNoVKey` conflation.
- [ ] **Claude #6 — naming asymmetry**: rename `Accepted` → `AcceptedZk` for symmetry.

These are not blocking; the next round of `colosseum-adversarial` should re-attack the revised property to check the fix is complete.

## Methodology meta-findings

This change-loop validates several methodology claims and surfaces several improvements.

### Validated

1. **Multi-model adversarial → mechanical verification.** Two LLMs (Claude + Gemma) flagged the same critical issue (mock-mode bypass); the methodology's revised property + Apalache produced a concrete counterexample trace witnessing exactly that bug. Adversarial-to-mechanical is the strongest verification pipeline the methodology offers.
2. **Action-tag pattern is reusable.** Both adversaries proposed it; `handshake.qnt` already uses it (line 95-ish). Worth promoting to a methodology pattern: spec-axis state machines should have a `last_action` provenance variable so temporal properties can predicate on which action fired.
3. **Change-loop runs cleanly when impact analysis is tight.** Single-file change → single-file re-verify → no downstream invalidations. The skill's "upstream-first" discipline kept the blast radius narrow.

### Methodology issues surfaced this round

1. **`quint-mcp` doesn't pipe `y` to Apalache's interactive consent prompt for temporal mode.** The MCP `verify_quint` hangs/timeouts on temporal property verification. **Fix for v0.2**: prepend `yes |` to the verify command, or pass `--yes` if Quint supports it. Documented in the MCP README.

2. **`quint-mcp` server disconnected after a 15-min timeout.** No auto-reconnect from the Claude Code side. **Fix for v0.2**: shorter default timeout for verify calls; document explicit retry steps.

3. **State-space blowup from adding a single state variable.** The original spec's `inv_zk_accept_requires_vkey` (state-only stub) verified in 1.1s at max-steps=8. The new spec at max-steps=8 timed out (>900s); at max-steps=4 it found a counterexample in 2.2s. Adding `last_action` as a state variable expanded the state space materially. **Methodology note**: when adding provenance tags, consider whether they can be views over existing state rather than new state variables — or simply expect to reduce max-steps for verification.

4. **The `colosseum-failure-classifier` should explicitly distinguish "code_wrong by design" from "code_wrong by bug".** The mock-mode bypass is intentional; the property's failure to allow it is the result of the design intent not being expressed in the property's text. This is a real subcategory that the classifier should name — `design_intent_mismatch` perhaps — distinct from genuine implementation bugs.

## Files

- Changed: `/Users/mvid/Development/reliq/quartz/specs/attestation.qnt` (single file, additive + one property rewrite)
- Verification result: `[violation] Found an issue (2182ms)` from Apalache — counterexample preserved in the bash log; can be regenerated with `yes | quint verify attestation.qnt --temporal temporal_zk_accept_requires_vkey --max-steps 4`
- Adversarial input: `.colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/synthesis.md`
