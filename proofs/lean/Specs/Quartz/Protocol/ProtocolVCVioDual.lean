/-
  Protocol-layer VCV-io scaffolding — Step 6.1 dual-bundle lift.

  --------------------------------------------------------------------
  Scope
  --------------------------------------------------------------------

  This module extends `ProtocolVCVio.lean` (Step 6.0) with the
  dual-bundle lift of `Specs.Quartz.Protocol.Handshake.handshake_sound`
  — the first genuine multi-bundle composition in the OracleComp
  lift sequence.

  Bundle inventory for `handshake_sound`:

  * `tdxVerifier`     (Step 4 bundle — verification-oracle soundness)
  * `groth16Verifier` (Step 5 bundle — knowledge-soundness +
                       circuit-equivalence, doubled-negligibility)

  Plus standard logic carriers. Confirmed via `lean_verify`:

      Specs.Quartz.Protocol.Handshake.handshake_sound axioms:
        {tdxVerifier, groth16Verifier, MrEnclave, TdxQuote, UserData,
         was_signed_by_dstack, Groth16Proof, PublicInputs, VKey}

  No `commitHashE` / `commitHashBytesE` dependency — `handshake_sound`
  does not touch hash-collision territory. It is therefore genuinely
  *dual-bundle*, as predicted by Step 6.0's analysis.

  Steps 6.1's three other originally-dual-bundle targets
  (`handshake_binds_ecies_key`, `session_confidentiality`,
  `session_confidentiality_via_extractor`) have all been promoted
  to **triple-bundle** by Steps 2-5 — each now carries a
  `commitHashE` dependency. They are deferred to Step 6.2 per the
  brief's "if triple, defer" instruction. See the change record for
  details.

  --------------------------------------------------------------------
  Lift pattern (dual-bundle template)
  --------------------------------------------------------------------

  The Step 6.0 single-bundle pattern (`verifyGroth16_yields_decoded_negl`)
  reduced to `negligible_of_le`. The dual-bundle case adds a union
  bound: the protocol-fail event is bounded by the *sum* of the two
  underlying soundness advantages, both of which are assumed
  negligible. Negligibility is closed under finite sums
  (`negligible_add`), so the bound is negligible.

  Specifically, for `handshake_sound`, the *failure* event is that
  the contract accepted but no dstack-signed quote with the matching
  fields exists. Decomposing:

      Pr[no dstack-signed quote exists | acc]
        ≤ Pr[Groth16 forgery]   -- adversary forged the proof
        + Pr[TDX forgery]       -- adversary forged the underlying quote

  Both summands are the corresponding bundle's soundness advantage.
  Each is assumed negligible (parametrically); their sum is negligible
  by `negligible_add`; therefore the protocol-fail probability is
  negligible.

  Note: at the Step 6.1 abstraction level, the TDX-forgery summand
  is **redundant** for *this particular* theorem — `verifyGroth16_sound`
  alone discharges the conclusion's `was_signed_by_dstack q` (since
  `inputs_to_quote inputs` recovers the quote, and `groth16Verifier
  .sound` directly yields the signing witness). The dual-summand
  decomposition is retained because:

  1. It correctly models the *cryptographic* threat surface
     (a real adversary can attack either bundle independently).
  2. It matches the union-bound structure Step 6.2/6.3 will need
     for the triple- and quadruple-bundle lifts; building the pattern
     here keeps the composition lemmas mechanical.
  3. The cost of including a vacuous summand is zero — it adds a
     `negligible_add` step but no additional hypotheses.

  The lift is **parametric over the soundness advantages**: like
  Step 6.0, the underlying negligibility assumptions are
  hypotheses, not discharged. Discharging them requires ArkLib
  Groth16 KS coverage + a reference DCAP verifier + a PCK-signature
  unforgeability reduction — all out of scope for this step.

  --------------------------------------------------------------------
  Carrier of adversary types
  --------------------------------------------------------------------

  We introduce one new adversary type:

  * `TdxVerifierSoundAdv : Type` — outputs a candidate `TdxQuote`
    that the verifier accepts but is NOT dstack-signed. The
    Step 6.0 `Groth16SoundAdv` carries over unchanged.

  And one composite adversary:

  * `HandshakeSoundAdv : Type` — outputs a candidate `HandshakeCheck`
    that the contract accepts but for which no dstack-signed quote
    exists. The reduction below maps each `HandshakeSoundAdv` to
    one `Groth16SoundAdv` and one `TdxVerifierSoundAdv` (the
    canonical decomposition the union bound rides on).

  All adversary types are wrapped in `IsPPT` for the project-
  standard efficiency filter (see `ProtocolVCVio.lean` for the
  rationale on the placeholder body).
-/

import VCVio.CryptoFoundations.Asymptotics.Security
import Specs.Quartz.Protocol.ProtocolVCVio

namespace Specs.Quartz.Protocol.ProtocolVCVioDual

open ENNReal
open OracleSpec OracleComp

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap
open Specs.Quartz.Protocol.Handshake
open Specs.Quartz.Protocol.ProtocolVCVio

/-! ## TDX-verifier soundness adversary and advantage -/

/-- A TDX-verifier soundness adversary: at each security parameter
    `n`, outputs a candidate `TdxQuote`. The "win" condition is
    that `verifyTdxQuote q = some (mr, ud)` for some `mr`, `ud`
    AND `¬ was_signed_by_dstack q`.

    Mirrors the Step 6.0 `Groth16SoundAdv` shape. The adversary is
    currently no-oracle-access (a `ProbComp` producer indexed by
    `n`); when carrier-refinement work lands and adversaries gain
    `OracleComp ProtocolSpec` access, this type will be lifted to
    an `OracleComp`-valued one and the placeholder `IsPPT`
    swapped for `PolyQueries`. -/
def TdxVerifierSoundAdv : Type := ℕ → ProbComp TdxQuote

/-- The advantage of a TDX-verifier soundness adversary at security
    parameter `n`, parametrised on an opaque bound.

    Conceptually:

        Pr[verifyTdxQuote q = some _ ∧ ¬ was_signed_by_dstack q
          | q ← 𝒜 n]

    The same `[Fintype]` blocker that prevents concrete computation
    of `Groth16SoundAdvantage` applies here (`TdxQuote` is an
    abstract carrier). The advantage is therefore parametric. -/
abbrev TdxVerifierSoundAdvantage : Type := TdxVerifierSoundAdv → ℕ → ℝ≥0∞

/-- The TDX-verifier soundness security game. -/
def tdxVerifierSoundnessGame (adv : TdxVerifierSoundAdvantage) :
    SecurityGame TdxVerifierSoundAdv where
  advantage := adv

/-! ## Composite handshake-soundness adversary

The handshake-soundness adversary models a real attacker on the
`handshake_sound` theorem: it produces a candidate
`HandshakeCheck` that the contract accepts but for which no
dstack-signed `TdxQuote` with the matching fields exists.

The reduction below shows that every such adversary's advantage is
bounded by the sum of the two bundle-soundness advantages
(`groth16SoundAdvantage` + `tdxVerifierSoundAdvantage`), via a
canonical decomposition: from any `HandshakeCheck` that the
adversary produces, project out a Groth16 attack witness and a
TDX attack witness.
-/

/-- A handshake-soundness adversary: at each security parameter
    `n`, outputs a candidate `HandshakeCheck`. The "win" condition
    is that `Accepted h` holds but there is no dstack-signed quote
    with `userDataOf q = some h.msgUserData` and `mrEnclaveOf q =
    some h.expectedMr`. -/
def HandshakeSoundAdv : Type := ℕ → ProbComp HandshakeCheck

/-- The advantage of a handshake-soundness adversary at security
    parameter `n`, parametrised on an opaque bound.

    The bound parametricity matches `Groth16SoundAdvantage` /
    `TdxVerifierSoundAdvantage`: the advantage cannot be computed
    concretely because the carriers (`TdxQuote`, `HandshakeCheck`,
    etc.) lack `Fintype` instances. -/
abbrev HandshakeSoundAdvantage : Type := HandshakeSoundAdv → ℕ → ℝ≥0∞

/-- The handshake-soundness security game. -/
def handshakeSoundnessGame (adv : HandshakeSoundAdvantage) :
    SecurityGame HandshakeSoundAdv where
  advantage := adv

/-! ## Content-bearing advantage definitions (Cycle 6.5 — Round A fix)

Same shape as cycle 6.4 for `verifyGroth16_yields_decoded_negl`.
Round A established the prior `handshake_sound_negl` was content-free:
`handshakeFailAdv` was a free `ℝ≥0∞`-valued function symbol, both
summand advantages were `Type`-only aliases, and the `h_bound` was a
caller-supplied hypothesis.

**Bundling correction (Round A-adjacent finding)**: the classical
`handshake_sound` at `Handshake.lean:64` uses ONLY `verifyGroth16_sound`
in its proof (witness quote is `inputs_to_quote h.inputs`; `mrEnclaveOf`
and `userDataOf` equalities come directly from `Accepted h`; `tdxVerifier`
is not consumed). The prior dual-bundle decomposition was over-bundled
relative to the actual axiom usage. Cycle 6.5 corrects this by lifting
`handshake_sound_negl` as a **single-bundle** Groth16-only reduction.
`TdxVerifierSoundAdvantage` is retained at the module level for the
downstream lifts that DO consume `tdxVerifier.complete`, but is no
longer threaded through this lift's hypotheses.

The `handshakeFail_secure_of_dual_bundle_secure` and
`handshakeSoundnessGame_secure_of_dual_bundle_secure` packagings below
remain dual-bundle in shape because they are generic over arbitrary
`SecurityExp` / `SecurityGame` summand decompositions — a caller who
wants to bound `handshakeFailExp.advantage` by a sum of two terms can
still do so, the second summand being optionally zero.
-/

/-- **Win predicate for the handshake-soundness game**: the contract
    accepts the handshake check, but there is no dstack-signed
    `TdxQuote` with matching `mrEnclaveOf` and `userDataOf` projections. -/
def handshakeSoundnessWinPred (h : HandshakeCheck) : Prop :=
  Accepted h ∧
  ¬ ∃ q : TdxQuote,
    was_signed_by_dstack q ∧
    mrEnclaveOf q = some h.expectedMr ∧
    userDataOf q  = some h.msgUserData

/-- **Reduction**: from a handshake-soundness adversary, construct a
    Groth16-soundness adversary by projecting the candidate
    `HandshakeCheck`'s `(proof, inputs)` pair. The classical proof of
    `handshake_sound` shows this projection witnesses a Groth16
    soundness break whenever the handshake-soundness adversary wins. -/
def reduce_handshake_to_groth (𝒜 : HandshakeSoundAdv) : Groth16SoundAdv :=
  fun n => do let h ← 𝒜 n; pure (h.proof, h.inputs)

/-- **Content-bearing advantage** for the handshake-soundness game: the
    probability that the adversary's `HandshakeCheck` output causes the
    contract to accept under a quote that is not dstack-signed. -/
noncomputable def handshakeFailAdv (𝒜 : HandshakeSoundAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ handshakeSoundnessWinPred | 𝒜 n ]

/-- Forward implication: a handshake-soundness win on `h` implies a
    Groth16-soundness win on the projected `(h.proof, h.inputs)`. -/
theorem handshakeSoundnessWinPred_imp_groth16SoundnessWinPred_projected
    (h : HandshakeCheck) (hp : handshakeSoundnessWinPred h) :
    groth16SoundnessWinPred (h.proof, h.inputs) := by
  obtain ⟨⟨hZk, hMr, hUd⟩, h_neg⟩ := hp
  refine ⟨hZk, ?_⟩
  intro h_signed
  apply h_neg
  exact ⟨inputs_to_quote h.inputs, h_signed, hMr, hUd⟩

/-! ## Dual-bundle lifted theorem: `handshake_sound_negl` -/

/-- **Classical form (preserved as a corollary)**: `handshake_sound`.

    Re-exported from `Handshake.lean` for convenience. Rides on the
    bundled `tdxVerifier` (Step 4) + `groth16Verifier` (Step 5)
    classical-`Prop` axioms.

    The classical chain remains unchanged: this corollary preserves
    the original axiom closure. -/
theorem handshake_sound_classical (h : HandshakeCheck) (acc : Accepted h) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q  = some h.msgUserData :=
  handshake_sound h acc

/-- **Probabilistic form (Step 6.1 lift, Cycle-6.5-corrected)**:
    `handshake_sound_negl`.

    Given:

    * a handshake-soundness adversary `𝒜 : HandshakeSoundAdv`,
    * a negligibility assumption on the Groth16 soundness-win event
      under the projected adversary
      `reduce_handshake_to_groth 𝒜`:
      `h_groth_negl : negligible (groth16SoundnessAdv (reduce_handshake_to_groth 𝒜))`,

    Then `negligible (handshakeFailAdv 𝒜)`.

    **Cycle 6.5 correction notes** (Round A response):

    - `handshakeFailAdv` is now a `def` over `Pr[handshakeSoundnessWinPred | …]`,
      not a free function symbol. Cannot be instantiated to `0`.
    - The reduction `reduce_handshake_to_groth` is a `def` (not a free
      parameter), so the bundle adversary is provably derived from the
      main adversary — closes Round A attack #3 for this lift.
    - The pointwise bound is proven via `probEvent_mono` +
      `probEvent_bind_pure_comp`, not assumed via `h_bound`.
    - **Bundling**: single-bundle (Groth16-only), matching the
      classical `handshake_sound` proof's actual axiom consumption.
      The prior dual-bundle decomposition was over-bundled; see the
      Content-bearing advantage definitions section above.
    - The remaining hypothesis `h_groth_negl` is the substantive
      cryptographic assumption — Groth16 KS over the deployed
      verifier — which ArkLib + circuit-equivalence would discharge. -/
theorem handshake_sound_negl
    (𝒜 : HandshakeSoundAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_handshake_to_groth 𝒜))) :
    negligible (handshakeFailAdv 𝒜) := by
  refine negligible_of_le ?_ h_groth_negl
  intro n
  -- Goal: handshakeFailAdv 𝒜 n ≤ groth16SoundnessAdv (reduce_handshake_to_groth 𝒜) n
  -- Unfold both sides to Pr[…]; the RHS equals the LHS-projected probability
  -- via `probEvent_bind_pure_comp`.
  show Pr[ handshakeSoundnessWinPred | 𝒜 n ] ≤
       Pr[ groth16SoundnessWinPred | reduce_handshake_to_groth 𝒜 n ]
  -- Rewrite the RHS using probEvent_bind_pure_comp:
  --   reduce_handshake_to_groth 𝒜 n = 𝒜 n >>= pure ∘ (fun h => (h.proof, h.inputs))
  -- so Pr[g | rhs] = Pr[g ∘ (fun h => (h.proof, h.inputs)) | 𝒜 n].
  rw [show reduce_handshake_to_groth 𝒜 n
        = 𝒜 n >>= pure ∘ (fun h : HandshakeCheck => (h.proof, h.inputs))
        from rfl,
      probEvent_bind_pure_comp]
  -- LHS ≤ RHS by probEvent_mono using the forward implication.
  exact probEvent_mono (fun h _ hp =>
    handshakeSoundnessWinPred_imp_groth16SoundnessWinPred_projected h hp)

/-- **Convenience packaging**: the lifted dual-bundle theorem
    expressed via VCV-io's `SecurityExp` reduction shape.

    Given:

    * a handshake-fail experiment `handshakeFailExp`,
    * Groth16 and TDX-verifier soundness experiments
      `groth16Exp`, `tdxExp`,
    * the pointwise union bound at every `n`,
    * security (negligibility) of both component experiments,

    Then `handshakeFailExp.secure` holds.

    Mirrors the Step 6.0 `protocolFail_secure_of_groth16Sound_secure`
    pattern but with two summands instead of one. The proof reduces
    to `negligible_of_le` + `negligible_add`. -/
theorem handshakeFail_secure_of_dual_bundle_secure
    (handshakeFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (h_bound : ∀ n,
      handshakeFailExp.advantage n ≤ groth16Exp.advantage n + tdxExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure : tdxExp.secure) :
    handshakeFailExp.secure :=
  -- `SecurityExp.secure = negligible advantage`; combine the two
  -- summand-negligibilities via `negligible_add` then close by
  -- `negligible_of_le` (packaged as `secure_of_pointwise_bound`).
  SecurityExp.secure_of_pointwise_bound
    handshakeFailExp
    (fun n => groth16Exp.advantage n + tdxExp.advantage n)
    (negligible_add h_groth_secure h_tdx_secure)
    h_bound

/-- **Security-game reduction form**: the dual-bundle reduction
    expressed via `SecurityGame.secureAgainst`.

    Given a fixed reduction `reduce : HandshakeSoundAdv →
    Groth16SoundAdv × TdxVerifierSoundAdv` that preserves the
    `IsPPT` filter, and a pointwise sum bound, security of both
    component games (against `IsPPT`) implies security of the
    handshake-soundness game (against `IsPPT`).

    This is the standard reduction-with-game-hopping shape that
    Steps 6.2 / 6.3 will compose into the triple- and
    quadruple-bundle bounds.

    The proof is a direct invocation of `negligible_of_le` +
    `negligible_add`, generalised over the adversary class. -/
theorem handshakeSoundnessGame_secure_of_dual_bundle_secure
    {handshakeGame : SecurityGame HandshakeSoundAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame : SecurityGame TdxVerifierSoundAdv}
    (reduce : HandshakeSoundAdv → Groth16SoundAdv × TdxVerifierSoundAdv)
    (h_bound : ∀ A n,
      handshakeGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage  (reduce A).2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure : tdxGame.secureAgainst IsPPT) :
    handshakeGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (h_groth_secure (reduce A).1 (IsPPT_trivial _))
      (h_tdx_secure  (reduce A).2 (IsPPT_trivial _)))

/-! ## Outstanding follow-ups (Step 6.2 / 6.3 work)

* **Step 6.2 — triple-bundle lifts**. Three theorems from the
  Step 6.1 brief turned out to be triple-bundle (each carries an
  additional `commitHashE` dependency):

    - `handshake_binds_ecies_key`        (`tdxVerifier` +
      `groth16Verifier` + `commitHashE`)
    - `session_confidentiality`          (same)
    - `session_confidentiality_via_extractor` (same)

  Plus two cross-component theorems that surfaced as triple-bundle
  during Step 5's analysis:

    - `cross_component_transfers_conservation`
      (`tdxVerifier` + `groth16Verifier` + `commitHashBytesE`)
    - `cross_component_auction_winner_determinism` (same)

  All five require a three-summand union bound:

      handshake_fail ≤ groth16_forgery + tdx_forgery + commit_collision

  The composition pattern is the same as `handshake_sound_negl`
  here, plus one more `negligible_add` step.

* **Step 6.3 — quadruple-bundle lift**. The single load-bearing
  theorem `cross_component_session_bind` rides on all four
  bundles: `tdxVerifier` + `groth16Verifier` + `commitHashE` +
  `commitHashBytesE`. The union bound has four summands (or
  five if `groth16Verifier` decomposes into KS + circuit-eq).

* **Tightening `IsPPT`**. The current placeholder is `True`; swap
  for VCV-io's `PolyQueries` once adversaries take `OracleComp
  ProtocolSpec` access. This is reversibility-preserving — the
  swap is internal to the `def IsPPT` body and leaves all
  theorem statements unchanged.

* **Discharging the negligibility hypotheses**. Same external
  dependencies as Step 6.0: ArkLib Groth16 KS (currently absent),
  PCK-signature unforgeability reduction (requires a Lean DCAP
  verifier), and `[Fintype]` carrier refinement.
-/

end Specs.Quartz.Protocol.ProtocolVCVioDual
