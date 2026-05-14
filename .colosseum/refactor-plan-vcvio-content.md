# Refactor plan: Content-phase fix for the 8 `_negl` lifts

**Origin**: Round A adversarial review (`.colosseum/attacks/lean-negl-lifts-2026-05-14/synthesis.md`) returned BREAKS on the content-phase lift. The 8 `_negl` theorems are content-free tautologies of `negligible_of_le` + `negligible_add`. This plan scopes the work to convert them to content-bearing parametric security reductions.

**Status**: Scoped 2026-05-14. Not started.

**Build status precondition**: `lake build` green at 2667 jobs (Step 6.3 baseline). All work in this plan must preserve that baseline. CI cannot regress.

## Problem statement

Every `_negl` theorem in `ProtocolVCVio*.lean` binds its protocol-fail advantage as a free `ℝ≥0∞`-valued function symbol with no defining equation. The cryptographic-assumption advantages are `Type`-only abbreviations with no definition body. The proofs go through via closure properties of `negligible` — pointwise domination and finite-sum closure — neither of which requires any semantic content. The result is eight theorems of the logical form `(∀n, f n ≤ Σg_i n) → (∀i, negligible g_i) → negligible f`, with no reference to Quartz at all.

Detailed attack scenarios in `.colosseum/attacks/lean-negl-lifts-2026-05-14/claude.md` attacks #1–3.

## Scope of fix

Three structural changes, each touching all 8 lifts:

1. **Define each protocol-fail advantage** as a concrete function of the adversary's output and the actual protocol-fail event (via `evalDist` / `Pr[…]`). The current free-parameter signature must be replaced by either a `def` preceding the theorem or a `theorem`-internal `let` binding.

2. **Tie each `*Advantage` `abbrev` to a concrete win predicate**. `Groth16SoundAdvantage`, `CommitHashCollisionAdvantage`, `TdxVerifierSoundAdvantage`, `CircuitEqAdvantage`, etc. must become `def`s whose body mentions the underlying verifier/hash and the win condition. The `Type`-only alias form is the smuggling vector; eliminate it.

3. **Constrain the terminal-lift's bundle adversaries to be derived from the main adversary** via concrete `reduce_*` functions and `reduce_*_correct` lemmas. The current setup at `cross_component_session_bind_negl` (`ProtocolVCVioQuad.lean:370`) takes six free adversaries; the fixed version takes one `𝒜 : CrossSessionBindAdv` and constructs the five underlying adversaries from it.

## Sequencing — one lift at a time

Adopt the same `colosseum-change` cadence as Steps 1–6 of the form-phase refactor. One module per cycle, sequenced to minimize re-work:

### Cycle 6.4 — `verifyGroth16_yields_decoded_negl` (single-bundle, easiest)

- Location: `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean:537`
- Defines: `Groth16SoundAdvantage` as a `def` (currently abbrev at line 432)
- Defines: `verifyGroth16FailEvent` as a probabilistic event over `verifyGroth16`'s semantics + `verifyTdxQuote`'s acceptance
- Replaces: free `protocolFailAdv` with `verifyGroth16FailAdv : Groth16SoundAdv → ℕ → ℝ≥0∞` defined as `Pr[verifyGroth16FailEvent]`
- Test: re-run the existing proof; if `negligible_of_le` no longer closes, this is evidence the new statement has content
- Stop condition: theorem typechecks AND a `#check` shows `verifyGroth16FailAdv` unfolds to a non-trivial body referencing `verifyGroth16` and `verifyTdxQuote`

### Cycle 6.5 — `handshake_sound_negl` (dual-bundle)

- Location: `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioDual.lean:243`
- New `def`s: `TdxVerifierSoundAdvantage`, `HandshakeSoundAdvantage`, `handshakeFailEvent`, `handshakeFailAdv`
- Pattern follows cycle 6.4

### Cycles 6.6–6.10 — the 5 triple-bundle lifts

Each is one cycle. Order recommended by complexity ascending: `handshake_binds_ecies_key_negl`, `session_confidentiality_via_extractor_negl`, `session_confidentiality_negl`, `cross_component_transfers_conservation_negl`, `cross_component_auction_winner_determinism_negl`.

### Cycle 6.11 — `cross_component_session_bind_negl` (terminal, hardest)

- Location: `proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioQuad.lean:370`
- Largest change: introduces `reduce_groth_ks : CrossSessionBindAdv → Groth16SoundAdv` and four siblings, each with a `reduce_*_correct` lemma asserting the union-bound summand domination
- This is the load-bearing fix per the ledger and the most consequential single piece of work in the plan
- Stop condition: the terminal lift's `h_bound` follows from the four `reduce_*_correct` lemmas, not from a free `h_bound` hypothesis supplied by the user

### Packaging fixes — folded into cycles 6.4–6.11 (done)

The original plan called for a separate cycle for the 24 downstream
`*_secure_of_*_bundle_secure` and `*Game_secure_of_*_bundle_secure`
packagings. In practice, each lift's packagings were updated alongside
the lift itself across cycles 6.4–6.11. No standalone packaging cycle
was needed.

### Cycle 6.12 — `IsPPT` placeholder rename (done 2026-05-14)

Round A attack #5: `IsPPT := True` makes `secureAgainst IsPPT`
statements vacuous (quantifies over all adversaries, not PPT
adversaries). Two options per attack #5's "Suggested defense":

- (a) Adopt VCV-io's `PolyQueries` as the `IsPPT` body. Requires
  adversaries to gain `OracleComp ProtocolSpec` access (which is
  also Round A attack #6's remediation — see cycle 6.13).
- (b) Rename the `*Game_secure_of_*_bundle_secure` packagings to
  `*_AGAINST_UNBOUNDED_ADVERSARIES` to make the placeholder gap
  visible at the call site. Cheaper short-term move.

**Cycle 6.12 picked (b)** because (a) requires cycle 6.13 as
prereq. The seven packagings now carry the suffix; each docstring
forward-references cycles 6.13/6.14 for the proper PolyQueries
adoption. Change record:
`.colosseum/changes/2026-05-14T20-30-00Z-cycle-6.12-ispptrename.md`.

### Cycle 6.13 — `OracleComp ProtocolSpec` adversary-type integration (queued)

Currently `ProtocolSpec` is defined at `ProtocolVCVio.lean:200-202`
but never used in any adversary type. Adversaries are
`ℕ → ProbComp X`, not `ℕ → OracleComp ProtocolSpec X`. Per Round A
attack #6, the framework upgrade to oracle-access adversaries is
required before any composition reduction is honest — and is a
prereq for instantiating `IsPPT := PolyQueries` (which closes
cycle 6.12's Option-(a) properly).

Multi-day refactor across every adversary type in the protocol
layer. Build-breaking churn; needs careful sequencing.

### Cycle 6.14 — `commitHashE` Option-(b) framing (queued)

Round A attack #8. Replace `pkOfUserData_commitHash`'s reliance on
`commitHash_inj` with a probabilistic collision-resistance
hypothesis. Would surface a real second bundle in the terminal
lift (Groth16 + commitHashE-CR), correcting the cycle-6.11
"single-bundle Groth16-only" framing once `commitHashE` is no
longer consumed unconditionally.

Independent of cycle 6.13 — can run in parallel.

## Stop condition for the plan

The plan is complete when:
- All 8 `_negl` theorems have probability-valued arguments defined (not free)
- All `*Advantage` declarations are `def`s, not `Type`-only abbrevs
- Terminal lift's underlying adversaries are derived from the main adversary
- `IsPPT` is either `PolyQueries` or the packagings are renamed
- Round A's 12 distinct attacks are re-run against the new code (manual or via `crucible-adversarial`) and resolved
- The strengthened v0.2 ask criteria (in `.colosseum/methodology-v0.2-asks.md`) pass on the new code

Then the ledger's "audit-ready" framing can be restored.

## Estimated effort

Per cycle: 2–5 days, depending on how deep the `evalDist`/`Pr[…]` definitions need to go and whether carrier refinement is required. Carrier refinement is *not* a precondition — `Pr[…]` can be defined over abstract carriers with `noncomputable` discipline; what changes is whether the resulting probability has a concrete numeric value (carrier-refinement-dependent) or only a formal-logic statement (carrier-free).

Total: ~3–6 weeks for cycles 6.4–6.14. The 6.11 terminal-lift cycle is the longest; everything else is pattern-replication.

## Open questions

1. **Should `evalDist` be the substrate, or `Pr[…]`?** VCV-io has both. `evalDist` is the lower-level operation; `Pr[…]` is sugar. The lifts probably want `Pr[…]` for readability, but `evalDist` for definitional unfolding when the proofs go through. Decide in cycle 6.4 and commit to the pattern.

2. **Carrier refinement timing**: Round A attack #6 + cycle 6.14 want oracle-access adversary types, which is a precondition for VCV-io's `PolyQueries`. But the form-phase 14-carrier queue is the larger refinement project. Recommend: start cycle 6.4 over *abstract* carriers (carrier-refinement remains parametric); revisit carrier refinement after cycles 6.4–6.12 land.

3. **`_classical` re-exports**: Round A confirmed these are honest, but they still depend on the (d) bundle axioms. Should the def-tying refactor of `_negl` forms eliminate the `_classical` corollaries entirely, or keep them as a "legacy" interface for engineering code? Per Round A attack #7 + Gemma #3, keeping them is fine if labelled, but the `_negl` form must be the load-bearing one going forward. Decide before cycle 6.4 ships.

## Provenance trail

- Round A synthesis: `.colosseum/attacks/lean-negl-lifts-2026-05-14/synthesis.md`
- Claude arm: `.colosseum/attacks/lean-negl-lifts-2026-05-14/claude.md` (11 attacks, BREAKS)
- Gemma arm: `.colosseum/attacks/lean-negl-lifts-2026-05-14/local-google_gemma-4-26b-a4b.md` (5 attacks, WEAKENS)
- Strengthened methodology asks: `.colosseum/methodology-v0.2-asks.md` (Asks 3, 4, and new Ask 5)
- Original form-phase plan (Steps 0–6.3): `.colosseum/refactor-plan-vcvio.md`
- Per-step form-phase change records: `.colosseum/changes/*` (Steps 0–6.3)
