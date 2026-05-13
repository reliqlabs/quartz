# Adversarial review synthesis: `temporal_zk_accept_requires_vkey`

- Spec under review: `specs/attestation.qnt` (lines 388-445)
- Intent document: `CLAUDE.md`
- Reviewed at: 2026-05-12
- Round: 1
- Adversary: google/gemma-4-26b-a4b (local, MLX runtime)
- Result: **complete report** — 3 attacks, verdict BREAKS

---

## Adversary verdict

**Gemma 4 26B**: `VERDICT: BREAKS`. Three attacks across categories `coverage gap`, `refinement mismatch`, and `triviality`. Two serious, one cosmetic. Confidence: high.

Other adversaries not run this round (Claude native, local Qwen, cloud OpenAI / Gemini). Per the skill, multi-model would compare these against each other; single-model gives one voice, no consensus check.

## Findings — orchestrator assessment

### Finding 1 — Mock-mode bypass [serious; load-bearing]

The temporal property `temporal_zk_accept_requires_vkey` requires the *pre-transition* vkey to be set and registered, but it does not require a valid proof. The `verify_zk` action has a branch `else if (proof_bytes == "" and not(accept_all))` whose negation — `accept_all == true` AND empty proof — falls through to the final `else` and reaches `last_result = Accepted`.

Implication: with `enable_mock` left on (deliberately or accidentally), an empty-proof Zk attestation accepts AND the temporal property still witnesses the (now meaningless) vkey state. The temporal property gives a false sense of safety when mock mode is active.

This is **genuine adversarial value**. The orchestrator's pyramid run did not surface this. The fix is to strengthen the temporal property:

```
implies (config.zkdcap_vkey != ""
         and zk_module.registered_vkeys.contains(config.zkdcap_vkey)
         and (zk_module.accept_all
              or next(last_input.attestation.proof.proof_bytes) != ""))
```

### Finding 2 — Counter leakage on SkippedNoVKey [serious; load-bearing]

`messages_accepted` increments in the `config.zkdcap_vkey == ""` branch where `last_result = SkippedNoVKey` is assigned. The temporal property is silent because it only fires on transitions into `Accepted`. The `messages_accepted` metric therefore conflates "verified accept" with "skipped-because-no-vkey accept" — a refinement mismatch between the metric's name and its actual semantics.

This is **genuine adversarial value**. Likely a deliberate design choice for backwards compatibility with non-Zk flows, but the spec doesn't justify it. Either rename the counter (`messages_processed_without_rejection`), introduce a separate counter for verified accepts, or stop incrementing on `SkippedNoVKey`.

### Finding 3 — Temporal property tautologically true [cosmetic]

Gemma argues the temporal property is a redundant observer of verify_zk's atomic logic. The orchestrator partially disagrees: the temporal property's role is precisely to make the action-local obligation tractable for Apalache verification at the spec level. It's not "redundant" — it's the *spec-axis expression* of the property the implementation enforces. But Gemma has a partial point: under the current action set, no other action can set `last_result' = Accepted` without going through `verify_zk`'s guard, so the temporal property adds no constraint *beyond* the action's local logic. It would become load-bearing the moment any new action assigns `last_result' = Accepted`.

Severity downgraded by the orchestrator from Gemma's "cosmetic" to "cosmetic-but-flag-for-future-extensions". The defense is to keep the temporal property as a structural invariant against precisely the kind of future refactor that would make it load-bearing.

## Process record

Four attempts, three failure modes, one success:

| Attempt | Model | max_tokens | Timeout | Reasoning tokens | Visible | Outcome |
|---|---|---|---|---|---|---|
| 1 | qwen3.6-27b-mlx | 4096 | 300s | 4095 | 0 | runtime hit timeout, zero visible output (reasoning still in flight) |
| 2 | gemma-4-26b-a4b | 4096 | 1800s | 4093 | 0 | budget exhausted by reasoning before output |
| 3 | gemma-4-26b-a4b | 16384 | 1800s | 16163 | 220 | truncated mid-attack (1 partial finding) |
| 4 | gemma-4-26b-a4b | 32768 | 1800s | 32765 | 2 | budget consumed by reasoning despite directive to cap it |
| 5 | gemma-4-26b-a4b | **65536** | **3600s** | 12231 | **4566 chars (~1146 tokens)** | **`finish_reason: stop`; complete report** |

The pivotal change in attempt 5 was the generous max_tokens budget. Once the model had clear headroom beyond its reasoning budget, it concluded reasoning at ~12k tokens and produced a complete report in ~1.1k tokens. Total runtime: 3 minutes.

## Methodology meta-findings

1. **Reasoning-mode local models are usable but need budget headroom.** A reasonable default for adversarial work on reasoning models is `max_tokens >= 2 × expected_reasoning_tokens`. Empirically: Gemma 4 26B used ~12k reasoning tokens on this 5.5k-token prompt; budgeting 65k worked. `crucible-adversarial` should not pass `4096` as a default for local models.
2. **Per-model adversarial calibration.** Gemma 4 produced 3 attacks on the first complete run, two serious. That's the methodology working at intended strength — a non-frontier local model finding real issues a frontier model (Claude in this session) had not surfaced. Validates the "family diversity" claim of the adversarial layer.
3. **Hidden reasoning is content, not waste.** Even when `text` is empty and reasoning consumed the full budget, the reasoning *did happen* — the model worked through the problem. Future v0.3 of `lm-studio-mcp` should extract `reasoning_content` from the response when text is empty, surfacing the partial analysis as adversarial signal rather than discarding it.

## Action items

For the spec (Quartz `attestation.qnt`):

- [ ] Strengthen `temporal_zk_accept_requires_vkey` to incorporate proof-bytes integrity under accept_all mode (Finding 1)
- [ ] Resolve `messages_accepted` semantics on `SkippedNoVKey` paths (Finding 2 — either fix counter or rename)
- [ ] Optionally: leave Finding 3's note in the spec comments as documentation that the temporal property is a defensive structural invariant against future refactors

For the methodology (`crucible-adversarial` v0.3):

- [ ] Default `max_tokens` for local-adversarial to a generous value (e.g., 65536 for reasoning models)
- [ ] Pass-through `extra_body` for thinking-disable on Qwen 3 series (`{"enable_thinking": false}`)
- [ ] Extract and persist `reasoning_content` when `text` is empty
- [ ] Update `lm-studio-mcp` README with the reasoning-mode pitfall and recommended budgets
