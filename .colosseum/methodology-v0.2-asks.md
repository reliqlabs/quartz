# Methodology v0.2 back-port — 4 asks from Quartz VCVio refactor

**Audience**: colosseum maintainers / colosseum agent.
**Origin**: Quartz Lean trust-boundary refactor, Steps 0–6.3, completed 2026-05-13.
**Status**: Revised 2026-05-14 after colosseum-agent review.

## Revision notes from colosseum review (2026-05-14)

1. **Naming**: agent/skill prefixes are `crucible-` (the repo rename did not propagate to internal names). All `colosseum-compose` references rewritten to `crucible-compose`.
2. **Ask 1 subsumption claim**: colosseum agent reports commit `b596782` already covers this; cross-reference table pending — do not re-implement until the table is reviewed and overlap confirmed.
3. **Sub-tag location**: Asks 3 and 4 originally suggested adding sub-tags to `crucible-failure-classifier`. Correct location is `crucible-compose` (sub-tags are consumed at compose time, not at classification time).
4. **Documented vs enforced split**: Asks 2–4 each have two landing forms.
   - **Documented** form: prose checkpoint added to the skill, with no executable check. Lands immediately, costs nothing architecturally.
   - **Enforced** form: compose runs an actual check (grep, count diff, comment-presence test). Requires colosseum to gain an executable layer — a separate architectural decision not in scope for this PR.

   The v0.2 PR should ship the documented form for all 4 asks. The enforced form is deferred behind the executable-layer question.

## Strengthening notes from Round A adversarial review (2026-05-14)

The Round A multimodel adversarial review of the 8 Quartz Lean `_negl` lifts (`.colosseum/attacks/lean-negl-lifts-2026-05-14/synthesis.md`) returned BREAKS. The findings show that Asks 3 and 4 as currently worded can be (and were) satisfied **cosmetically**. The asks themselves are correctly named; their *satisfaction criteria* are too weak. The strengthening below replaces the original criteria.

### Ask 3 strengthening — `(d-vacuous-hypothesis)` sub-tag

**Original criterion** (now too weak): "lifts of so-tagged axioms must carry the restatement comment `-- Lifts vacuous classical X to non-vacuous Y because Z`".

**Round A finding**: A comment is not a definition. Quartz's `commitHashCollisionAdvantage` was declared as `abbrev … : Type := Adv → ℕ → ℝ≥0∞` — a `Type`-only alias with no `def`. The "restatement" was in a docstring above the abbrev. The lift's hypothesis `negligible (hashAdv 𝒜)` is satisfied by `hashAdv := 0`, regardless of whether the real hash is collision-resistant.

**Strengthened criterion**: Lifts of `(d-vacuous-hypothesis)`-tagged axioms must define the advantage as a `def` (or theorem-form, not `abbrev`) that mentions the actual cryptographic primitive (e.g. `commitHash`) and the actual win condition (e.g. "outputs a collision"). Compose-time check: read the advantage symbol's *definition body*; verify it is not just a type alias. The presence of a restatement comment is necessary but not sufficient.

### Ask 4 strengthening — `(d-disjunction-vs-decomposition)` terminal-lift discipline

**Original criterion** (now too weak): "verify both disjuncts appear as parametric hypotheses in the lifted statement".

**Round A finding**: Quartz's terminal lift `cross_component_session_bind_negl` does split `groth16Verifier`'s disjunction into two summands (`groth16KSAdv` + `circuitEqAdv`). Both summands are opaque `Type`-only abbreviations; neither mentions the protocol. The split is type-level only.

**Strengthened criterion**: At the terminal lift, the disjunction must be split *and* each split summand must be tied to a concrete win condition. Compose-time check: each disjunct's advantage abbrev's definition body must reference (a) the underlying primitive (`verifyGroth16` / circuit), and (b) the disjoint event each summand bounds (KS-attack wins / circuit-equivalence violation). Naming alone is necessary but not sufficient.

### New Ask 5 — Free-symbol detection at lift time

**Symptom**: Quartz's 8 `_negl` lifts each bind a "protocol-fail advantage" as a free `ℝ≥0∞`-valued function symbol with no defining equation. The proofs typecheck via `negligible_of_le` + `negligible_add` (closure properties) without any semantic content tying the LHS to the actual protocol-fail event. This is a structural defect upstream of all 4 v0.2 asks: even if asks 3 and 4 are satisfied as strengthened above, a lift with a free protocol-fail advantage is still a tautology of `negligible f → negligible f`.

**Provenance**: Round A adversarial review attacks #1, #2, #3 (`.colosseum/attacks/lean-negl-lifts-2026-05-14/claude.md`).

**Proposed criterion**: For each lifted theorem, identify each `ℝ≥0∞`-valued (or `ℕ → ℝ≥0∞`-valued) argument in the theorem signature. For each: verify it is *defined* (in terms of the adversary's output and a concrete win predicate) before the theorem statement, rather than bound as a free `(arg : T → ℕ → ℝ≥0∞)` parameter. Free probability-valued parameters in a lift are a code smell pointing at the free-symbol tautology defect.

**Documented form** (lands in this PR): extend `crucible-compose`'s prose with a "free-symbol check" step at lift time. The executing agent reads each lifted theorem's signature and confirms no probability-valued argument is a bare parameter.

**Enforced form** (deferred): compose programmatically inspects the Lean elaborator output for free `ℝ≥0∞`-valued arguments and fails-loud on any. Same executable-layer dependency as the other asks.

### Methodology meta-finding — file-access requirement for adversarial arms

Round A's most critical finding (the free-symbol tautology) was surfaced by the file-access-enabled, large-context Claude arm. The prompt-inlined Gemma arm (57k tokens of context, ~26B parameters) reached the ask-level concerns but did not reach the structural triviality beneath them.

**Implication**: `crucible-adversarial` skill rounds must include at least one arm with file-access enabled. Prompt-inlined-only multimodel review is insufficient for theorem-signature-analysis findings. Suggest adding a precondition check to `crucible-adversarial`: refuse to emit a synthesis if all arms are prompt-inlined; require explicit file-access acknowledgment from at least one arm.

### v0.2 PR shape (revised)

5 commits (one per ask + the meta-finding), single PR titled `methodology: v0.2 — back-port 5 asks from Quartz VCVio refactor + Round A adversarial review`. The Round A synthesis is itself a colosseum artifact that should be referenced in the PR description as the strengthening rationale.

## Context

Quartz Lean trust boundary just landed an axiom-reduction + OracleComp-lift refactor: 40 → 26 axioms (-35%), 8 protocol theorems lifted with zero `sorry`. The work ran as 9 sequential `colosseum-change` cycles. During execution the ledger surfaced 4 methodology findings that should be absorbed before the next refactor in any project.

Source material in the Quartz tree:

- **Ledger**: `.colosseum/ledger.md` — audit-ready summary at top, methodology asks at line ~227
- **Refactor plan**: `.colosseum/refactor-plan-vcvio.md`
- **Change records**: `.colosseum/changes/` — 9 records, each cited per-ask below

Each ask cites the change record that first surfaced it. **Read the record before editing colosseum** — framing matters and "found" / "none" wording was load-bearing in at least one case.

---

## Ask 1 — `dead_axiom_scan` checkpoint in `crucible-compose`

**Symptom**: During Step 4, the `RtmrLog` axiom became unreferenced after `Dstack.lean` was reshaped. No mechanical signal — caught by manual inspection. Silence on "are there orphan axioms?" is the bug; both "found these N orphans" and "none" need to be explicit outputs.

**Provenance**:
- First detected: `.colosseum/changes/2026-05-13T14-56-59Z-dstack-vcvio.md` (Step 4)
- First explicit "none" outcome: `.colosseum/changes/2026-05-13T15-05-36Z-zkdcap-vcvio.md` (Step 5)

**Proposed change**: Add a `dead_axiom_scan` checkpoint to `crucible-compose`. After each step's `lake build` succeeds, run a `git grep` for each axiom name across the project's spec tree and verify ≥1 downstream consumer. Emit one of:

- `dead_axiom_scan: found {names...}` — candidates for deletion in this step
- `dead_axiom_scan: none` — explicit no-orphans message

**Documented form**: prose in `crucible-compose` instructing the executing agent to perform the grep and emit one of the two outputs in the per-step report.

**Enforced form**: compose programmatically runs `git grep` and gates step exit on emitting one of the two messages. Deferred behind executable-layer decision.

**Subsumption check pending**: colosseum reports commit `b596782` may already cover this. Do not implement Ask 1 until the cross-reference table is reviewed.

---

## Ask 2 — Bundle-cardinality drift tracking

**Symptom**: When Step 2 bundled `commitHashE`, three theorems that were originally dual-bundle (2 axioms) silently became triple-bundle (3). Step 6.1's plan still said "lift the dual-bundle theorem `handshake_sound`" — at execution time the theorem was triple-bundle, forcing a defer to Step 6.2. Plan was correct at authoring time, stale at execution.

**Provenance**: `.colosseum/changes/2026-05-13T15-27-38Z-protocol-vcvio-dual-bundle.md` (Step 6.1)

**Proposed change**: Carry a per-target `bundle_count: N` annotation in the refactor-plan schema. After each bundling step, the executing agent re-derives actual bundle count from the current `lean_verify` axiom closure, diffs against the plan's value, and emits:

```
bundle_drift: theorem_X 2 → 3 (axiom Y bundled at step Z)
```

Non-blocking — bundles legitimately grow during a refactor — but makes drift mechanical to spot.

**Documented form**:
- Add `bundle_count: N` to the refactor-plan front matter schema (this is a static doc change).
- Add prose to `crucible-compose` instructing the executing agent to perform the diff post-step and emit `bundle_drift:` lines.

**Enforced form**: compose programmatically extracts axiom closure via `lean_verify`, computes the diff, and fails-loud on undocumented promotion. Deferred behind executable-layer decision.

---

## Ask 3 — Meta-(d): vacuous-impossible-axiom-as-hypothesis classifier

**Symptom**: Some axioms in the classical chain are vacuously true because the spec-level claim is structurally absurd (e.g. `commitHashE` claims injectivity of a fixed-codomain hash, contradicting pigeonhole). Classical theorems consuming these are vacuously satisfied. The OracleComp lift cannot inherit the vacuous satisfaction — it must restate the truthful cryptographic hypothesis (collision resistance on the concrete real-world hash).

The lift's *value* is upgrading the hypothesis from vacuous to non-vacuous. If the upgraded hypothesis is wrong, the lift is silently re-vacuous and the new theorem is just as honest as the old one (i.e. not).

**Provenance**: `.colosseum/changes/2026-05-13T15-48-32Z-protocol-vcvio-triple-bundle.md` (Step 6.2; sub-tag "(d-vacuous-hypothesis)"; concrete case is the Option-(b) framing for `commitHashE` / `commitHashBytesE`).

**Proposed change**: Add a `(d-vacuous-hypothesis)` sub-bucket to the axiom-classification taxonomy consumed by `crucible-compose` at lift time. When a lift target carries this sub-tag, the lift step should require an explicit hypothesis-restatement comment of the form:

```lean
-- Lifts vacuous classical X to non-vacuous Y because Z
```

Without it, the lift is silently re-vacuous.

**Location correction (from colosseum review)**: sub-tag definitions live in `crucible-compose`, not `crucible-failure-classifier`. Compose consumes the sub-tag at lift execution; classifier only assigns the primary bucket.

**Documented form**: extend `crucible-compose`'s taxonomy section with the `(d-vacuous-hypothesis)` sub-tag and a prose instruction that lifts of so-tagged axioms must carry the restatement comment.

**Enforced form**: compose programmatically checks for the `-- Lifts vacuous ...` comment string in the lifted theorem's preamble and fails-loud on its absence. Deferred behind executable-layer decision.

---

## Ask 4 — (d-disjunction-vs-decomposition): load-bearing-terminal-lift discipline

**Symptom**: Some (d) axioms carry disjunctions — `groth16Verifier`'s doubled-negligibility is `Groth16-KS ∨ circuit-equivalence`. Intermediate composition levels can honestly *collapse* such a disjunction into a single hypothesis. At the **load-bearing terminal lift** — the final cross-component theorem an external auditor will read — the disjunction must **expand**: both summands present and named, because an adversary can attack either. Collapse at terminal level is dishonest.

Methodology currently doesn't distinguish terminal from intermediate lifts; a collapse can silently propagate.

**Provenance**: `.colosseum/changes/2026-05-13T16-02-47Z-protocol-vcvio-quad-bundle.md` (Step 6.3, methodology-side ask M-1).

**Proposed change**: Add a `terminal: bool` flag to refactor-plan entries naming the top-level theorem(s) an auditor will inspect. On a `terminal: true` lift, compose must:

1. Enumerate all (d) axioms in the closure.
2. For each carrying a disjunction (taxonomy sub-tag `(d-doubled-negligibility)` or `(d-disjunction)`), verify both disjuncts appear as parametric hypotheses in the lifted statement.
3. Fail-loud if any disjunction is still collapsed at terminal.

**Location correction (from colosseum review)**: disjunction sub-tags live in `crucible-compose`'s taxonomy, not in `crucible-failure-classifier`.

**Documented form**:
- Add `terminal: bool` to the refactor-plan front-matter schema.
- Add `(d-doubled-negligibility)` / `(d-disjunction)` sub-tags to `crucible-compose`'s taxonomy.
- Add prose to `crucible-compose` instructing the executing agent to perform the disjunction-expansion check on `terminal: true` targets.

**Enforced form**: compose programmatically enumerates (d) closure, parses sub-tags, and fails-loud on collapsed disjunction at terminal. Deferred behind executable-layer decision.

---

## Validation

No Quartz-side change required. Validation: replay Steps 1–6 of the Quartz refactor (records under `.colosseum/changes/`) using the updated methodology. Outcome should be:

- Same final axiom counts and lift outputs (26 axioms, 8 lifted theorems).
- New diagnostics fire where they should — specifically:
  - Step 4 emits `dead_axiom_scan: found RtmrLog`
  - Step 5 emits `dead_axiom_scan: none`
  - Step 6.1 emits `bundle_drift: handshake_sound 2 → 3 (commitHashE bundled at step 2)` + two siblings
  - Step 6.2's `commitHashE` lifts require the `-- Lifts vacuous ...` restatement comment
  - Step 6.3's terminal lift on `cross_component_session_bind_negl` fails-loud unless both `groth16Verifier` disjuncts are surfaced

## Suggested PR shape

Single PR titled `methodology: v0.2 — back-port 7 asks from Quartz VCVio refactor + Round A adversarial review`, 7 commits (one per ask). Each commit touches: schema (plan front matter), one skill (`crucible-compose`), one agent prompt (`crucible-failure-classifier`).

(Originally 4 asks; expanded to 5 after the Round A strengthening review, then to 7 after the cycle-6.4-through-6.11 implementation revealed two further methodology-level findings — see Asks 6 and 7 below.)

---

## Asks 6 and 7 — added 2026-05-14 from the cycle-6.4-through-6.11 implementation

After the strengthened criteria in Asks 1–5 were drafted, the Quartz Lean tree implemented the def-tying refactor across all 8 protocol-layer `_negl` lifts (cycles 6.4 through 6.11; 8 commits at `/Users/mvid/Development/reliq/quartz/.colosseum/changes/2026-05-14T*-cycle-6.{4..11}-*.md`). The implementation surfaced two new methodology-level findings.

### Ask 6 — per-conjunct failure-mode analysis as source of bundle count

**Symptom**: the cycle-6.4-through-6.11 sequence found that **7 of 8 lifts were over-bundled** in the original Step 6.0–6.3 work:

| Lift | Original classification | Actual probabilistic-failure mode count |
|---|---|---|
| verifyGroth16_yields_decoded_negl | single | 1 (Groth16) |
| handshake_sound_negl | dual | 1 (Groth16) |
| handshake_binds_ecies_key_negl | triple | 1 (Groth16) |
| session_confidentiality_negl | triple | 0 (deterministic-only) |
| session_confidentiality_via_extractor_negl | triple | 0 (deterministic-only) |
| cross_component_transfers_conservation_negl | triple | 1 (Groth16) |
| cross_component_auction_winner_determinism_negl | triple | 1 (Groth16) |
| cross_component_session_bind_negl (terminal) | quad (5-summand) | 1 (Groth16) |

The original plan classified each lift by the union-bound shape implied by an *axiom count*: how many axioms appear in the classical-proof closure. The actual probabilistic-failure-mode count is determined by which of those axioms have an actual probabilistic-failure event vs. which are consumed unconditionally (derived theorems, equalities, definitional rewrites).

The terminal lift `cross_component_session_bind_negl` is the most extreme example: 5-summand → single. Its classical proof's 5-conjunct conclusion has only one probabilistic-failure mode (Groth16-soundness via `handshake_sound`); the other 4 conjuncts are unconditional theorems in the current carrier model (`pkOfUserData_commitHash` consumes `commitHashE` but has no probabilistic-failure event; `roundtrip` is a derived theorem).

**Provenance**:
- Most extreme single instance: `/Users/mvid/Development/reliq/quartz/.colosseum/changes/2026-05-14T20-13-44Z-cycle-6.11-terminal-lift-deftie.md`
- Combined sequence summary in the same file under "Pattern summary".
- Every cycle 6.4–6.11 change record contains its own per-conjunct analysis.

**Proposed change**: `crucible-compose` skill prose must require, for each lifted theorem, a per-conjunct table:

| Conjunct | Status | Source |
|---|---|---|
| Pᵢ | probabilistic-failure mode (needs negligibility hypothesis) | underlying primitive |
| Pⱼ | unconditional theorem | derived theorem name |
| Pₖ | derived from `Accepted` / hypotheses | projection name |

The lift's bundle count is the count of `probabilistic-failure mode` rows, NOT the count of axioms in the closure.

**Documented form** (lands in this PR): extend `crucible-compose`'s prose with a "per-conjunct failure-mode classification" step at lift-cycle setup. The executing agent fills in the table; the change record references it.

**Enforced form** (deferred): compose programmatically asks `lean_verify` for the closure of each conjunct and matches against a methodology rule for "is this conjunct a `theorem`, an `axiom`, or a `projection`?" Same executable-layer dependency as the other asks.

**Placement (colosseum-agent recommendation 2026-05-14)**: in `skills/colosseum-compose/SKILL.md` Step 3, as a sub-step **before** the existing "Bundle cardinality: " line. The cardinality N must be derivable from the per-conjunct table; if the table has K probabilistic-failure rows, the bundle cardinality is K — not a free number pulled from axiom-closure size. The colosseum agent's existing drift-detection (Step 6.1's `bundle_drift` line) catches the symptom of over-bundling only after the corrected count lands; Ask 6 closes the upstream gap by requiring the cardinality to have a defensible derivation at the moment it's chosen.

**Cross-project evidence (verified-rcv)**: the colosseum agent confirmed the methodology-level claim with a second-project instance — verified-rcv's bundle B9 went from 5 → 4 summands during the revision pass, driven by attack analysis (KMS-leakage = confidentiality, image-registration = operational-fault). The reduction was correct but ad-hoc; Ask 6's table would have surfaced both at setup.

### Ask 7 — degenerate-zero-advantage cycles must declare intent

**Symptom**: cycles 6.7 and 6.8 produced lifts whose failure advantage is **identically zero** — the classical proof has *no* probabilistic-failure event under the current spec abstraction. The conclusion follows unconditionally from the hypotheses (`roundtrip` is a derived theorem in `Ecies.lean`, not a separately-named axiom; `pkOfUserData_commitHash` is a theorem derived from `commitHash_inj`).

These lifts are valid but underwhelming — they prove "the spec's deterministic-only failure event has probability zero," not a cryptographic claim. A real cryptographic claim (e.g., ECIES IND-CPA) would require a separate refactor to introduce a probabilistic encryption scheme + a CPA game + an IND-CPA hypothesis.

**Provenance**:
- `/Users/mvid/Development/reliq/quartz/.colosseum/changes/2026-05-14T20-03-06Z-cycle-6.7-session-confidentiality-deftie.md` (first instance)
- `/Users/mvid/Development/reliq/quartz/.colosseum/changes/2026-05-14T20-05-22Z-cycle-6.8-session-extractor-deftie.md` (second instance)

**Proposed change**: when a cycle's lift has `failAdv 𝒜 n = 0` proven identically, the change record must explicitly state whether:

- **(a) intentional non-modelling**: the spec is not modelling the relevant probabilistic phenomenon (the lift is honest within the spec's scope; e.g. session_confidentiality_negl models deterministic correctness, not CPA security); OR
- **(b) genuine vacuity**: the lift is structurally trivial and the underlying theorem should not be called a "security lemma" without further refactor.

For session_confidentiality the answer is (a). Without this discipline, an auditor reading a zero-advantage lift could mistake (a) for (b) or vice-versa.

**Documented form** (lands in this PR): extend `crucible-compose`'s prose with an "(a)/(b) declaration" requirement for any cycle whose `failAdv` proves identically zero. The declaration is a short prose statement in the change record naming the specific spec-abstraction limitation that makes the lift degenerate, plus the refactor that would lift it from (a) to a real (non-zero) cryptographic claim.

**Enforced form** (deferred): compose programmatically detects `confFailAdv 𝒜 n = 0` proof structures and gates the cycle exit on a (a)/(b) declaration being present in the change record. Same executable-layer dependency.

**Placement (colosseum-agent recommendation 2026-05-14)**: add an optional `Cycle-outcome intent` field to the change-record schema at `skills/colosseum-change/SKILL.md:146-168` (the existing Step 8 record-fields list: name / classification / description / affected verification surface / adversarial review / ledger delta / outstanding follow-ups). The new field's enumerated values:

  1. `probabilistic-failure-modelled` (default — the lift bounds a real probabilistic event)
  2. `degenerate-by-design — scope excludes the failure event` (the spec is intentionally not modelling the relevant probabilistic phenomenon; e.g. session_confidentiality_negl models deterministic correctness, not CPA security)
  3. `degenerate-by-accident — abstraction collapsed the failure event` (the lift is structurally trivial because the carrier model elided the event; refactor needed to restore it)
  4. `follow-up to add it` (the lift ships now as (2) or (3) but a tracked follow-up cycle will add the probabilistic claim)

The discrete enum (vs. free-form prose) is the auditability win — auditors can grep change records for `Cycle-outcome intent: degenerate-by-accident` and surface all instances at once. For Quartz cycles 6.7 and 6.8 the value is `degenerate-by-design — scope excludes the failure event` (ECIES IND-CPA is out of the current spec abstraction's scope).

---

## Methodology validation evidence (cycle-6.4-through-6.11)

A positive observation for the methodology: the cycle 6.4 def-tying pattern — `Pr[…]`-based advantage `def`, concrete reduction `def`, `probEvent_mono` + `probEvent_bind_pure_comp` proof — applied **mechanically across 8 different lift shapes** (single-bundle, dual, triple, quad; single-conjunct, multi-conjunct, with-existential, all-unconditional). All 8 cycles compiled first-try after the first one (modulo two orphan-docstring cleanups). No new VCV-io infrastructure was needed.

This means: when the colosseum agent runs `crucible-compose` on a new project's lift sequence, the cycle 6.4 def-tying recipe is **the** known-working pattern. The recipe replicates and the cycle plan can confidently set per-cycle effort estimates based on it.

---

## Prior asks — already on the docket, not part of this v0.2 set

For the colosseum agent's awareness. These accumulated in earlier change records and may already be tracked:

- PPT predicate hardening (replace `IsPPT := True` with VCVio `PolyQueries`)
- `_negl` reduction-skeleton in companion modules (push documentary skeletons one layer earlier)
- Impossible-axiom flag in ledger (now encoded as `(d-pigeonhole-impossible)` sub-tag)
- Companion-module naming template (`<Module>VCVio.lean`)
- Trust-density metric (axioms / theorems ratio, emitted automatically by compose)
- `temporal_state_mismatch` vs `temporal_intent_mismatch` classifier sub-tags
- `design_intent_mismatch` ↔ `code_wrong-by-design` classifier sub-category

Pre-date the v0.2 set. Pick up incidentally if convenient; don't block the v0.2 PR on them.
