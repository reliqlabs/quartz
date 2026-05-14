# Multi-model adversarial synthesis: 8 Lean `_negl` lifts (Quartz VCV-io refactor)

- Artifacts under review: `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean`, `ProtocolVCVioDual.lean`, `ProtocolVCVioTriple.lean`, `ProtocolVCVioQuad.lean` (Steps 6.0–6.3 of the VCV-io refactor)
- Ledger: `.colosseum/ledger.md`
- Intent document: `CLAUDE.md`
- Reviewed at: 2026-05-14 (Round A, multi-model)
- Adversaries dispatched: **Claude** (subagent, file access, Opus 4.7 / 1M context) + **Gemma 4 26B** (local via LM Studio, full context inlined to ~57k tokens)
- Result: **12 distinct attacks**; both verdicts negative; 3 critical, 6 serious, 3 advisory

This synthesis is orchestrator output. The per-model reports (`claude.md`, `local-google_gemma-4-26b-a4b.md`) are persisted verbatim and unedited. The orchestrator summarizes overlap and divergence; it does not add, weaken, or re-author findings.

---

## Verdict aggregate

| Adversary | Verdict | Attacks | Crit | Serious | Advisory |
|---|---|---|---|---|---|
| Claude (subagent, file access) | **BREAKS** | 11 | 3 | 5 | 3 |
| Gemma 4 26B (local, prompt-inlined) | **WEAKENS** | 5 | 1 | 2 | 2 |
| **Cross-family agreement** | NEGATIVE | 4 shared themes | 1 | 3 | 1 |

Both adversaries from different model families converge on a negative verdict and overlap on **four** structural concerns. Claude's verdict (BREAKS) is one step harsher because it surfaces a root-cause attack — the "free-symbol tautology" finding (Claude #1–3) — that Gemma did not articulate. Gemma's WEAKENS verdict is consistent with the same lifts but stops at the level of the named asks rather than reaching the structural triviality beneath them. Methodology operating at intended strength: cross-family agreement on the named concerns; depth-of-analysis advantage to the file-access-enabled, larger-context arm.

---

## The headline finding

**Claude unique, critical: the 8 `_negl` lifts are content-free tautologies of `negligible_of_le` + `negligible_add`.** Every `_negl` theorem binds its protocol-fail advantage as a free `ℝ≥0∞`-valued function symbol with no defining equation. The user can instantiate the fail-advantage to `fun _ _ => 0`, pick any pointwise-dominating right-hand-side advantages, and the proof goes through via closure properties of `negligible`. The lifts collectively prove one fact — "the negligible class is closed under pointwise domination and finite sums" — which is a content-free fact of VCV-io and not a statement about Quartz. The `_secure_of_*_bundle_secure` and `*Game_secure_of_*_bundle_secure` packagings (24 downstream theorems total) inherit the same defect.

Gemma did not surface this root cause directly. Gemma's findings 1 (`IsPPT` placeholder) and 2 (parametric `adv` over abstract carriers) cluster *around* the same structural region but don't reach the diagnosis that the protocol-fail advantage itself is a free symbol. The file-access advantage matters here: Claude was able to inspect the exact theorem signatures and observe that no `def` ties the advantage to the protocol semantics.

**Severity**: critical. Implication: the ledger's claim that all 8 lifts are "audit-ready" is incorrect at the current code state. They are scaffolding awaiting content.

---

## Shared findings — surfaced by both adversaries

### S1. `IsPPT := True` placeholder is vacuous and load-bearing

- **Claude attack #5** (`IsPPT` placeholder vacuity, serious): `SecurityGame.secureAgainst IsPPT` with `IsPPT := True` quantifies over *all* adversaries, not PPT ones, making the `*Game_secure_of_*_bundle_secure` packagings claim a stronger property than the classical statement can sustain. Suggests renaming theorems to `*_AGAINST_UNBOUNDED_ADVERSARIES` until `PolyQueries` adoption.
- **Gemma attack #1** (`IsPPT` placeholder loophole, critical): An adversary with super-polynomial resources finds a SHA-256 collision or breaks BN254 — the `IsPPT := True` predicate is vacuously satisfied, so the theorem applies to that adversary. Suggests replacing with `PolyQueries`.
- **Orchestrator assessment**: same finding, different framings. Claude's is **technically sharper** — it identifies that the placeholder makes the conclusion *over-strong* (security against unbounded adversaries is something the bundle assumptions cannot supply), not merely that the placeholder admits unbounded adversaries. Gemma frames it as "smuggling unbounded adversaries"; Claude frames it as "claiming a stronger property than the assumption layer supports". Both fixes converge on `PolyQueries` adoption. The ledger already flags this as a methodology v0.2 ask.
- **Severity** (orchestrator's call): **serious**. The placeholder is a known gap per the ledger; the synthesis adds that it interacts with the free-symbol root cause (headline finding above) to produce a maximally-vacuous "for all adversaries, this opaque function is negligible" certificate.

### S2. The `(d-disjunction-vs-decomposition)` expansion at the terminal lift is cosmetic

- **Claude attack #4** (disjunction-collapse, serious): Terminal `cross_component_session_bind_negl` does split `groth16Verifier`'s bound into two summands (`groth16KSAdv` + `circuitEqAdv`), but both are opaque `Type := Adv → ℕ → ℝ≥0∞` aliases. The decomposition is type-level only — neither advantage abbrev mentions the protocol, so an auditor cannot verify that an attack on either underlying primitive lifts to a `cross_component_session_bind` failure. The methodology v0.2 ask 4 is satisfied cosmetically.
- **Gemma attack #5** (intermediate disjunction collapse, advisory): The KS ∨ CircuitEq disjunction is only expanded at the terminal quad-bundle lift. Intermediate triple-bundle lifts collapse it into a monolithic `Groth16SoundAdv` — so any audit that doesn't reach the terminal lift misses the CircuitEq risk.
- **Orchestrator assessment**: complementary findings on the same axiom. **Claude attacks the terminal**: the expansion that did happen is empty. **Gemma attacks the intermediate**: the expansion that didn't happen elsewhere hides risk visibility. Both are correct. Claude's is more critical (the load-bearing terminal lift's expansion is cosmetic); Gemma's is the wider observation (every level should make the disjunction visible, not just terminal).
- **Severity** (orchestrator's call): **serious** at the terminal (Claude's framing), **advisory** at intermediate levels (Gemma's framing). The methodology ask itself needs revising: "must expand at terminal" is necessary but not sufficient; the expansion must also tie advantage abbrevs to concrete win conditions, not just split a `Type` alias.

### S3. Carrier / parametric-advantage smuggling

- **Claude attacks #6, #8** (oracle-access spoofing, Option-(b) restates nothing; serious each): `ProtocolSpec` and the companion `*OC` definitions are exported but never used in the lifts; adversary types use `ProbComp` (no oracle access). Option-(b) for `commitHashE` introduces `CommitHashCollisionAdv` and a `Type`-aliased advantage but never ties the advantage back to `commitHash`. The "collision-resistance hypothesis" is a parametric `negligible (hashAdv 𝒜)` for `hashAdv` opaque — instantiate `hashAdv := 0`, hypothesis trivially holds, no statement about the real hash.
- **Gemma attack #2** (carrier-refinement smuggling, serious): The parametric `adv` over abstract carriers admits degenerate `Fintype` instances (1-bit `UserData` etc.). Negligibility is a precondition supplied by the user, not derived from the carrier types. Suggests prioritizing the carrier-refinement queue.
- **Orchestrator assessment**: same structural concern, three framings. Claude's #6 names the specific "oracle access pretended but not delivered" defect; Claude's #8 names the specific "Option-(b) restatement does not actually restate anything" defect (this is the methodology v0.2 ask 3 satisfied cosmetically). Gemma's #2 names the more general "parametric over carriers" pattern. **Claude's framings are more actionable** — they identify the specific places in the source that need changing. **Gemma's framing is more conceptual** — it points at the broader pattern. Both are correct; Claude's lands closer to a fix.

  Note: Claude's "Categories not attacked" section explicitly disputes one premise of Gemma's #2 — none of the lifts use a `[Fintype X]` quantifier, so the 1-element-Fintype attack path Gemma described is *not* literally exploitable; the parametric smuggling happens through different mechanism (the `Type`-only advantage abbrev). This is a real disagreement at the *exact-attack-path* level, but the underlying structural concern (the advantage is opaque) is shared.

- **Severity** (orchestrator's call): **serious**. Multiple methodology v0.2 asks (ask 3 specifically) are satisfied cosmetically because of this pattern. The ledger should not claim ask 3 is discharged until advantages are tied to concrete win predicates.

### S4. Hypothesis correlation across SHA-256-derived bundles

- **Claude attack #9** (hypothesis correlation, serious): Terminal lift's 5-summand union bound treats `commitHashE` and `commitHashBytesE` collisions as independent. Both bottom out at the same SHA-256 primitive. A real attack on either is an attack on both; the union bound conceals the doubling. Similar concern for Groth16-KS and CircuitEq (both rely on the same R1CS generator setup).
- **Gemma attack #4** (hypothesis correlation, serious): Same observation, slightly narrower scope (only the SHA-256 case, not the Groth16/R1CS case).
- **Orchestrator assessment**: shared finding, Claude broader. Both agree the union bound is asymptotically valid but suggests a tighter bound than exists. Both propose introducing a joint SHA-256 collision-resistance assumption with the two summands as reductions to it.
- **Severity** (orchestrator's call): **serious** for the asymptotic-vs-concrete claim mismatch; advisory if the ledger only ever claims asymptotic negligibility. Today the lifts don't make concrete-security claims — but the ledger's "discharge via VCV-io `randomOracle` + birthday bound" framing suggests concrete bounds are the eventual goal, and at that level the correlation matters.

---

## Unique findings per adversary

### Unique to Claude (file access, deeper analysis)

| # | Category | Severity | One-line |
|---|---|---|---|
| Claude #1 | Triviality / root cause | **critical** | Free-symbol `protocolFailAdv` reduces every lift to `negligible_of_le` + `negligible_add` closure — they prove nothing about Quartz |
| Claude #2 | Hypothesis smuggling | **critical** | `h_bound` is a Trojan horse — user can prove `negligible f → negligible f` for *any* `f` by appropriate instantiation |
| Claude #3 | Reduction-relation absence | **critical** | Terminal lift's 5 underlying adversaries (`𝒜_groth_ks` etc.) are not constrained to be derived from `𝒜` — no reduction structure |
| Claude #7 | Closure invariant vacuity | serious | Ledger's "all 8 lifts hide bundle axioms uniformly" is satisfied vacuously because lifts say nothing — the `_classical` form's `userDataOfSessionSetPubKey_eq_commitHash` bridge dep silently dropped |
| Claude #10 | Decidability hygiene | advisory | `was_signed_by_dstack`'s `Classical.propDecidable` instance is dead — no `Pr[…]` is built over it; supporting comments overstate what it enables |
| Claude #11 | API shape | advisory | `protocolFailAdv : Groth16SoundAdv → ℕ → ℝ≥0∞` over-quantifies — cosmetic but symptomatic of root cause |

**Pattern**: Claude's unique findings cluster around *structural defects in the theorem statements themselves*. With file access, Claude read the exact `theorem` declarations and verified which arguments are free vs defined. Findings #1–3 are the most consequential of the round — they reframe the entire lift sequence as scaffolding-without-content.

### Unique to Gemma (local, prompt-inlined)

| # | Category | Severity | One-line |
|---|---|---|---|
| Gemma #3 | `_classical` re-export honesty | advisory | `_classical` corollaries still carry the impossible bundled axioms; engineering teams may treat them as load-bearing when they're mathematical fiction |

**Pattern**: Gemma's unique finding is a *consumer-facing* concern — that `_classical` re-exports may be inadvertently used by engineering code expecting the security semantics rather than the legacy classical-Prop interface. Claude addressed the `_classical` re-exports differently: Claude confirms they honestly preserve the original classical theorem, but argues this is fine because *the classical theorems themselves* are what the engineering code already relied on. The disagreement is about whose problem the `_classical` form is: Gemma sees it as a new risk introduced by the lift; Claude sees it as a continuation of the pre-lift status quo.

**Orchestrator's call**: Gemma is partially right — the lift's existence does *suggest* to a reader that the `_negl` form is now the authoritative statement, and the `_classical` form is "convenience". If consumers misread which is load-bearing, that's a real risk. Severity advisory.

---

## Severity-weighted unified attack list

After de-duplication across the 11 + 5 = 16 raw attacks, **12 distinct attacks**:

**Critical** (3):
1. **Free-symbol tautology** (Claude #1) — root cause; all 8 lifts and their 24 packagings affected
2. **Trojan-horse `h_bound`** (Claude #2) — exploits root cause to admit arbitrary `negligible f` certificates
3. **No reduction relation at terminal lift** (Claude #3) — five free underlying adversaries unconstrained from the main one

**Serious** (6):
4. **`IsPPT := True` placeholder vacuity** (S1; Claude #5 / Gemma #1)
5. **Disjunction-decomposition cosmetic at terminal** (S2; Claude #4)
6. **Carrier / Option-(b) smuggling** (S3; Claude #6, Claude #8, Gemma #2)
7. **Hypothesis correlation across SHA-256 bundles** (S4; Claude #9 / Gemma #4)
8. **Closure-invariant vacuity** (Claude #7) — ledger's hidden-bundle-axiom invariant true only because lifts say nothing
9. **Composition-step downstream impact** (Claude meta) — 24 packaging theorems inherit the root cause

**Advisory** (3):
10. **Disjunction visibility at intermediate lifts** (Gemma #5)
11. **`_classical` consumer confusion** (Gemma #3)
12. **Decidability hygiene + API shape cosmetics** (Claude #10, Claude #11)

---

## Coverage analysis — what each model brought

| Attack category | Claude | Gemma |
|---|---|---|
| Theorem-signature inspection (free symbols, type-only abbrevs) | ✓✓ deep | — |
| Reduction-structure analysis | ✓✓ deep | — |
| Closure / axiom-hiding semantics | ✓✓ | — |
| Methodology-ask cosmetic-discharge | ✓✓ | ✓ |
| `IsPPT` placeholder analysis | ✓ | ✓ |
| Hypothesis-correlation analysis | ✓ | ✓ |
| Disjunction-decomposition analysis | ✓ terminal | ✓ intermediate |
| Carrier-type degeneracy analysis | (disputes premise) | ✓ |
| Consumer-side `_classical` confusion | (different framing) | ✓ |
| Oracle-access framework usage check | ✓✓ | — |
| Decidability + Pr[…] measurability | ✓ | — |

**Claude's coverage advantage** comes from file access + larger context. With the actual `theorem` declarations in hand, Claude could read off the free-vs-defined structure directly. **Gemma's coverage contribution** is the consumer-side risk that the lift's existence introduces a new layer of confusion, plus independent confirmation on `IsPPT`, hypothesis correlation, and disjunction-decomposition.

If the orchestrator had only Gemma's report, the takeaway would be "the lifts have a few methodology gaps, needs work, WEAKENS." With Claude's report added, the takeaway is "the lifts are scaffolding without content, do not merge, BREAKS." **Cross-family adversarial review with at least one large-context, file-access-enabled arm is necessary to surface this class of finding.** Methodology implication: future adversarial-review skill rounds must include a file-access arm; prompt-inlined-only review is insufficient for this depth.

---

## Recommended actions

In priority order, scoped to what can be done without first refining carriers:

1. **Halt the merge-to-mainline claim** for the 8 `_negl` lifts. The ledger's "audit-ready" framing is incorrect. Reword the ledger to "framework-ready, content-pending"; mark the 8 `_negl` theorems as scaffolding awaiting carrier refinement. The methodology v0.2 PR for colosseum still goes through — the asks are correctly identified — but the *Quartz-side* claim of having addressed them needs to be retracted.

2. **Define one `protocolFailAdv` as a concrete function** (suggested by Claude #1's "suggested defense"). Pick the simplest lift — `verifyGroth16_yields_decoded_negl` — and replace the free-symbol `protocolFailAdv` with a `def` over `evalDist` and the actual `verifyGroth16` semantics. Even if `[Fintype]` carrier refinement isn't yet available, the `def` makes the theorem's logical content non-trivial. This converts the root-cause finding from a structural defect into a per-lift execution task.

3. **Tie advantage abbrevs to concrete win predicates** (Claude #2, #4, #8). `Groth16SoundAdvantage`, `CommitHashCollisionAdvantage`, etc. should be `def`s, not `Type`-only abbrevs. Each `def` mentions the underlying verifier or hash and the win condition. This is several days of work per advantage but unblocks the methodology v0.2 ask discharge claims.

4. **Constrain the bundle adversaries to be derived from the main one** (Claude #3). At the terminal lift, replace `𝒜_groth_ks : ...` etc. as free arguments with `𝒜_groth_ks := reduce_groth_ks(𝒜)` etc., where `reduce_*` are concrete `OracleComp`-program reductions. This is the load-bearing fix for the terminal lift's "is there actually a reduction" question.

5. **Update the methodology v0.2 asks PR** (currently pending the colosseum agent's b596782 cross-reference). Asks 3 and 4 specifically: their satisfaction criteria need strengthening. Currently the asks check "is the disjunction expanded" and "is the hypothesis restated" — both can be (and are) satisfied cosmetically. The strengthened criteria need to check "is the advantage tied to a concrete win predicate" and "is the disjunction's expansion tied to disjoint events on the underlying primitive". Send a follow-up to the colosseum agent with this strengthening.

6. **Methodology meta-finding**: adversarial review with file-access + large-context arm surfaces a class of finding (theorem-signature analysis, free-symbol detection) that prompt-inlined review misses. The colosseum `crucible-adversarial` skill should require at least one arm with file-access enabled.

---

## What does NOT change

- The classical-chain theorems (`Handshake`, `Confidentiality`, etc.) are unaffected — the `_classical` re-exports honestly preserve them (Claude confirmed; Gemma's #3 frames this as a consumer risk but not a correctness defect).
- The 26 → 40 axiom reduction is real and durable (the form-phase reduction of Steps 1–5 stands).
- The CI workflows and `lake build` greenness are unaffected — the lifts compile; they just don't say what the ledger claims.
- The Quint, Kani, and Verus tracks are unaffected.

What changes is the **interpretation** of what the lifts achieve. The trust posture before this synthesis was "8 of 8 protocol theorems lifted onto VCV-io's `OracleComp` framework, parametric on cryptographic-assumption negligibility hypotheses." The trust posture after this synthesis is "8 of 8 theorems have the *shape* of a security reduction but their content is the closure properties of `negligible`. The substantive lift work is pending carrier refinement and advantage-definition work."
