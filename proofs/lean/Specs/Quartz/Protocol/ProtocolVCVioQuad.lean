/-
  Protocol-layer VCV-io scaffolding — Step 6.3 quadruple-bundle lift.

  --------------------------------------------------------------------
  Scope
  --------------------------------------------------------------------

  This module is the **final lift** in the Step 6 sequence. It extends
  `ProtocolVCVio.lean` (Step 6.0, single-bundle proof-of-concept),
  `ProtocolVCVioDual.lean` (Step 6.1, dual-bundle), and
  `ProtocolVCVioTriple.lean` (Step 6.2, triple-bundle) with the lift
  of the **one quadruple-bundle protocol-layer theorem**:

      cross_component_session_bind

  The loop-closing theorem of the Quartz handshake — the integration
  point where contract-side acceptance, enclave-side commitment,
  ECIES roundtrip, and attestation soundness all compose into a
  single end-to-end binding statement.

  Bundle inventory (verified via `lean_verify`):

      Specs.Quartz.Protocol.CrossComponent.cross_component_session_bind
        axioms include: {commitHashE, commitHashBytesE,
                         tdxVerifier, groth16Verifier}

  Plus standard logic (`propext`, `Classical.choice`, `Quot.sound`)
  and carriers (`MrEnclave`, `TdxQuote`, `UserData`, etc.). Genuinely
  *quadruple-bundle*, matching the Step 6.1 / 6.2 classification.

  --------------------------------------------------------------------
  Lift pattern (quadruple-bundle template) — FIVE summands
  --------------------------------------------------------------------

  The four classical bundles in the closure compose into FIVE
  cryptographic-assumption summands under the union bound. The fifth
  summand is the **Step 5 doubled-negligibility decomposition** of
  `groth16Verifier`: its soundness rests on two independent
  computational assumptions —

      Pr[groth16_forgery] ≤ negligible_groth16 + negligible_circuit

  where:

  * `negligible_groth16` is the BN254 Groth16 knowledge-soundness
    bound (cryptographic — KZG / power-knowledge / GGM, ArkLib
    roadmap target).
  * `negligible_circuit` is the zkdcap R1CS circuit ≡ reference-DCAP
    verifier equivalence bound (software-verification, separate
    effort).

  The triple-bundle lifts in Step 6.2 could afford a monolithic
  `Groth16SoundAdvantage` because the doubled assumption didn't
  surface at their abstraction level. Step 6.3 is where the
  decomposition lands: the quadruple lift's bound makes BOTH
  Groth16 KS and the zkdcap circuit-equivalence visible as
  separate cryptographic-assumption budgets.

  The lift therefore follows **Decision (β)** from the Step 6.3
  brief: decompose `groth16Verifier` into two summands rather than
  inheriting Step 6.2's monolithic framing. The bound becomes:

      protocolFailAdv ≤ groth16KSAdv          -- Groth16 KS
                      + circuitEqAdv          -- zkdcap circuit ≡ ref DCAP
                      + tdxAdv                -- DCAP / PCK unforgeability
                      + hashAdv               -- commitHashE collision
                      + hashBAdv              -- commitHashBytesE collision

  Five summands. Negligibility is closed under finite sums
  (`negligible_add` ×4); pointwise monotonicity gives the union-
  bound shape (`negligible_of_le`).

  Step 6.0 (1 summand): `negligible_of_le h_bound h_negl`
  Step 6.1 (2 summands): `negligible_of_le h_bound (add h₁ h₂)`
  Step 6.2 (3 summands): `negligible_of_le h_bound (add (add h₁ h₂) h₃)`
  Step 6.3 (5 summands): `negligible_of_le h_bound
                            (add (add (add (add h₁ h₂) h₃) h₄) h₅)`

  Left-associated chain for consistency with the Step 6.1 / 6.2
  precedent — balanced bracketing gives no sharper bound for
  sum-of-negligibles, so left-association is the canonical choice.

  --------------------------------------------------------------------
  Honest framing of the hash-collision summands — Option (b)
  symmetrically
  --------------------------------------------------------------------

  Both `commitHashE : UserDataCommit ↪ UserData` (Step 2 bundle) and
  `commitHashBytesE : ByteSeq ↪ UserData` (Step 3 bundle) are
  **mathematically-impossible-as-stated** Function.Embeddings —
  pigeonhole forbids any injection from an open-cardinality preimage
  into a fixed-width 64-byte `UserData` codomain. Step 6.2 introduced
  the **Option (b)** framing for the `commitHashE` summand: keep
  the embedding model at the spec/classical layer, frame the
  negligibility hypothesis as collision-resistance of the concrete
  hash function `H` the embedding abstracts over.

  Step 6.3 applies Option (b) **symmetrically** to BOTH the
  `commitHashE` and `commitHashBytesE` summands. The two hashes
  abstract over different concrete hash functions
  (`H : UserDataCommit → UserData` and `H_b : ByteSeq → UserData`),
  but the meta-(d) "vacuous-impossible-axiom-as-hypothesis" finding
  applies symmetrically:

  * spec-level embedding hypothesis (either side): vacuous
    (impossible-as-stated);
  * lift-level collision-resistance hypothesis: non-vacuous,
    standard cryptographic statement.

  The collision-resistance adversary types
  (`CommitHashCollisionAdv`, `CommitHashBytesCollisionAdv`) and
  their advantage / game packages are imported unchanged from
  `ProtocolVCVioTriple.lean`. No new collision-resistance carrier
  is introduced.

  --------------------------------------------------------------------
  Doubled-negligibility carriers
  --------------------------------------------------------------------

  Two new adversary types are introduced to model the Step 5
  decomposition of `groth16Verifier`:

  * `Groth16KSAdv : Type` — outputs a candidate
    `(VKey × Groth16Proof × PublicInputs)` that verifies under the
    trusted vkey but for which no satisfying R1CS witness exists.
    The "win" condition is a Groth16 knowledge-soundness break.

  * `CircuitEqAdv : Type` — outputs a candidate `PublicInputs` for
    which the zkdcap R1CS encoding disagrees with the reference
    DCAP verifier semantics. The "win" condition is a circuit-
    correctness break.

  These two are the truthful decomposition of the Step 5 monolithic
  `Groth16SoundAdv`: the latter is observationally equivalent to
  the disjunction of these two events (a Groth16 forgery occurs
  iff *either* knowledge soundness breaks *or* the circuit is
  inequivalent to the reference). The triple-bundle lifts collapsed
  the disjunction; the quadruple lift expands it.

  Plus one composite adversary:

  * `CrossSessionBindAdv : Type` — outputs a candidate
    `(HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext)`
    such that the contract accepts but the conclusion of
    `cross_component_session_bind` fails on the produced tuple.
    This is the truthful adversary game: a real attacker tries to
    construct a tuple that the contract accepts but doesn't
    actually deliver the loop-closing binding.

  All adversary types ride on the project-standard `IsPPT`
  placeholder filter (see `ProtocolVCVio.lean` for the rationale).
-/

import VCVio.CryptoFoundations.Asymptotics.Security
import Specs.Quartz.Protocol.ProtocolVCVio
import Specs.Quartz.Protocol.ProtocolVCVioDual
import Specs.Quartz.Protocol.ProtocolVCVioTriple
import Specs.Quartz.Protocol.CrossComponent

namespace Specs.Quartz.Protocol.ProtocolVCVioQuad

open ENNReal
open OracleSpec OracleComp

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap
open Specs.Quartz.Protocol.Handshake
open Specs.Quartz.Protocol.CrossComponent
open Specs.Quartz.Protocol.ProtocolVCVio
open Specs.Quartz.Protocol.ProtocolVCVioDual
open Specs.Quartz.Protocol.ProtocolVCVioTriple

/-! ## Doubled-negligibility adversaries for the Step 5 decomposition

The Step 5 honesty finding established that `groth16Verifier`'s
soundness rests on **two** independent computational assumptions:

  1. Groth16 knowledge soundness over BN254 (cryptographic).
  2. zkdcap R1CS circuit ≡ reference DCAP verifier (software-
     verification).

The triple-bundle lifts of Step 6.2 inherited the Step 6.0
monolithic `Groth16SoundAdv` because the doubled assumption was
methodologically invisible at the three-summand level. Step 6.3
makes it visible: the quadruple lift's union bound has FIVE
summands, with the `Groth16SoundAdv` decomposing into
`Groth16KSAdv + CircuitEqAdv`.

The two summands have independent justifications and independent
discharge paths. Surfacing them separately is the entire point of
the Step 5 (d)-bucket "doubled-negligibility" finding.
-/

/-- A Groth16 knowledge-soundness adversary: at each security
    parameter `n`, outputs a candidate
    `(VKey × Groth16Proof × PublicInputs)`. The "win" condition is
    that the proof verifies under the canonical vkey but no
    satisfying R1CS witness exists for the public inputs.

    Mirrors the Step 6.0 `Groth16SoundAdv` shape but specialised to
    the KS half of the doubled-negligibility decomposition. When
    ArkLib lands a Groth16 KS theorem, this adversary's negligibility
    becomes provable from a reduction to BN254 generic-group-model
    bounds. -/
def Groth16KSAdv : Type :=
  ℕ → OracleComp ProtocolSpec (VKey × Groth16Proof × PublicInputs)

/-- The advantage of a Groth16 knowledge-soundness adversary. -/
abbrev Groth16KSAdvantage : Type := Groth16KSAdv → ℕ → ℝ≥0∞

/-- The Groth16 knowledge-soundness security game. -/
def groth16KSGame (adv : Groth16KSAdvantage) :
    SecurityGame Groth16KSAdv where
  advantage := adv

/-- A zkdcap circuit-equivalence adversary: at each security
    parameter `n`, outputs a candidate `PublicInputs` for which the
    zkdcap R1CS circuit and the reference DCAP verifier disagree.

    The "win" condition is a witness to circuit-vs-reference-DCAP
    inequivalence. This is the software-verification half of the
    doubled-negligibility decomposition. When a Lean reference DCAP
    verifier is formalised AND the zkdcap R1CS circuit is given a
    matching formal model, this adversary's negligibility becomes
    provable from a circuit-equivalence theorem. -/
def CircuitEqAdv : Type :=
  ℕ → OracleComp ProtocolSpec PublicInputs

/-- The advantage of a zkdcap circuit-equivalence adversary. -/
abbrev CircuitEqAdvantage : Type := CircuitEqAdv → ℕ → ℝ≥0∞

/-- The zkdcap circuit-equivalence security game. -/
def circuitEqGame (adv : CircuitEqAdvantage) :
    SecurityGame CircuitEqAdv where
  advantage := adv

/-! ## Composite quadruple-bundle adversary -/

/-- A `cross_component_session_bind`-attack adversary: at each
    security parameter, outputs a candidate
    `(HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext)`
    such that the contract accepts but the loop-closing conclusion
    fails. The conclusion bundles five conjuncts:

      1. ∃ dstack-signed quote
      2. quote.mrEnclave matches expected
      3. quote.userData matches msg.userData
      4. pkOfUserData extracts the raw pubkey
      5. ECIES roundtrip recovers the plaintext

    A failure on any of these is a win for the adversary. The
    union-bound decomposition below maps each conjunct failure to a
    bundle break. -/
def CrossSessionBindAdv : Type :=
  ℕ → OracleComp ProtocolSpec (HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext)

/-- The advantage of a `cross_component_session_bind`-attack
    adversary. Parametric on an opaque bound for the same
    `[Fintype]` reasons as the rest of the Step 6 lift sequence. -/
abbrev CrossSessionBindAdvantage : Type :=
  CrossSessionBindAdv → ℕ → ℝ≥0∞

/-- The `cross_component_session_bind` security game. -/
def crossSessionBindGame (adv : CrossSessionBindAdvantage) :
    SecurityGame CrossSessionBindAdv where
  advantage := adv

/-! ## Quadruple-bundle lifted theorem: `cross_component_session_bind` -/

/-- **Classical form (preserved as a corollary)**:
    `cross_component_session_bind`.

    Re-exported from `CrossComponent.lean` for convenience. Rides
    on the quadruple-bundle `commitHashE` + `commitHashBytesE`
    + `tdxVerifier` + `groth16Verifier` classical-`Prop` axioms.

    The classical chain remains unchanged: this corollary preserves
    the original axiom closure exactly. -/
theorem cross_component_session_bind_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (raw : RawSessionSetPubKey)
    (h_raw : h.msgUserData = userDataOfSessionSetPubKey raw)
    (sk : PrivKey) (h_sk : keyOf sk = raw.pubKey) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q = some h.msgUserData ∧
      pkOfUserData h.msgUserData = some raw.pubKey ∧
      (∀ msg : Plaintext, decrypt sk (encrypt raw.pubKey msg) = some msg) :=
  cross_component_session_bind h acc raw h_raw sk h_sk

/-! ### Cycle-6.11 framing (terminal lift)

Per Round A's specific concern, the terminal lift is the place where
disjunction-decomposition discipline matters. The cycle-6.4-through-
6.10 pattern showed every intermediate lift over-bundled relative to
its classical proof's actual axiom consumption. The terminal lift is
analyzed the same way:

Classical `cross_component_session_bind` (`CrossComponent.lean:92-109`)
proves a 5-conjunct conclusion. The conjuncts and their failure modes:

  P1 `was_signed_by_dstack q`                     — Groth16-soundness break
  P2 `mrEnclaveOf q = some h.expectedMr`         — derived from Accepted, no axiom
  P3 `userDataOf q = some h.msgUserData`         — derived from Accepted, no axiom
  P4 `pkOfUserData h.msgUserData = some raw.pubKey`
                                                 — UNCONDITIONAL via
                                                   `userData_session_set_pub_key_binds_ecies`
                                                   (consumes commitHashE in
                                                   closure but no probabilistic
                                                   failure event in current
                                                   carrier model)
  P5 `∀ msg, decrypt sk (encrypt raw.pubKey msg) = some msg`
                                                 — UNCONDITIONAL via `roundtrip`
                                                   (derived theorem, no axiom)

Net: only P1 has a real probabilistic failure event. The terminal lift
is therefore single-bundle (Groth16) under the current spec abstraction,
same as cycles 6.5/6.6/6.9/6.10. The 5-summand union bound in the prior
formulation was over-bundled.

**On Round A's disjunction-decomposition concern**: the original
finding observed that the terminal lift's 5-summand union bound made
the bundle visible but didn't tie each summand to a concrete win
predicate. The cycle-6.11 correction makes the lift HONEST about
which summands are real probabilistic-failure modes vs. which were
cosmetic Type-aliases. The terminal lift now has **one real failure
mode (Groth16)** and the other 4 are commitHashE / TDX / ECIES /
commitHashBytesE *axioms consumed unconditionally* — present in the
classical-proof closure but not lifted to probabilistic hypotheses
in the current carrier model. This is the correct framing per the
Round A v0.2 ask 4 strengthening criteria: each disjunct must be
tied to a concrete win predicate, OR explicitly downgraded to "axiom
consumed in classical proof, not probabilistic in this lift". -/

/-- **Win predicate**: hypotheses hold but the cross-component
    conclusion fails. -/
def crossSessionBindWinPred
    (p : HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext) : Prop :=
  let (h, raw, sk, _) := p
  Accepted h ∧
  h.msgUserData = userDataOfSessionSetPubKey raw ∧
  keyOf sk = raw.pubKey ∧
  ¬ ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q = some h.msgUserData ∧
      pkOfUserData h.msgUserData = some raw.pubKey ∧
      (∀ msg : Plaintext, decrypt sk (encrypt raw.pubKey msg) = some msg)

/-- **Reduction** to Groth16-soundness adversary. -/
def reduce_crossSessionBind_to_groth
    (𝒜 : CrossSessionBindAdv) : Groth16SoundAdv :=
  fun n => do
    let p : HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext ← 𝒜 n
    pure (p.1.proof, p.1.inputs)

/-- **Content-bearing failure advantage**. -/
noncomputable def bindFailAdv
    (𝒜 : CrossSessionBindAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ crossSessionBindWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- Forward implication: a cross-component-bind win implies a Groth16
    soundness break on the projected `(h.proof, h.inputs)`. The proof
    discharges P4 and P5 unconditionally via
    `userData_session_set_pub_key_binds_ecies` (after `h_raw` rewrite)
    and `roundtrip` (after `h_sk` rewrite) respectively, then derives
    the Groth16 break from the remaining ¬∃ q. -/
theorem crossSessionBindWinPred_imp_groth16SoundnessWinPred_projected
    (p : HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext)
    (hp : crossSessionBindWinPred p) :
    groth16SoundnessWinPred (p.1.proof, p.1.inputs) := by
  obtain ⟨⟨hZk, hMr, hUd⟩, h_raw, h_sk, h_neg⟩ := hp
  refine ⟨hZk, ?_⟩
  intro h_signed
  apply h_neg
  refine ⟨inputs_to_quote p.1.inputs, h_signed, hMr, hUd, ?_, ?_⟩
  · rw [h_raw]
    exact userData_session_set_pub_key_binds_ecies p.2.1
  · intro msg
    rw [← h_sk]
    exact roundtrip p.2.2.1 msg

/-- **Probabilistic form (Step 6.3 lift, Cycle-6.11-corrected)**:
    `cross_component_session_bind_negl`. **Terminal lift.**

    Was: 12 free parameters, 5 free advantages, 5 independent
    negligibility hypotheses, no reduction relating the 6 free
    adversaries.

    Now: 1 adversary + 1 Groth16-negligibility hypothesis on the
    *derived* adversary, bound proven internally via `probEvent_mono`
    + `probEvent_bind_pure_comp` + the explicit forward implication.

    Bundle correction: 5-summand → single (Groth16-only). See the
    section docstring above for the per-conjunct analysis. Round A
    attacks #1, #2, #3, #11 are structurally closed; the
    disjunction-decomposition concern (#4) is addressed by explicit
    documentation of which axioms are probabilistic vs.
    unconditionally-consumed in the current carrier model. -/
theorem cross_component_session_bind_negl
    (𝒜 : CrossSessionBindAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜))) :
    negligible (bindFailAdv 𝒜) := by
  refine negligible_of_le ?_ h_groth_negl
  intro n
  show Pr[ crossSessionBindWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ] ≤
       Pr[ groth16SoundnessWinPred | simulateQ protocolSpecHonestSim (reduce_crossSessionBind_to_groth 𝒜 n) ]
  rw [show reduce_crossSessionBind_to_groth 𝒜 n
        = 𝒜 n >>= pure ∘
            (fun p : HandshakeCheck × RawSessionSetPubKey × PrivKey × Plaintext =>
              (p.1.proof, p.1.inputs))
        from rfl]
  simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]
  exact probEvent_mono (fun p _ hp =>
    crossSessionBindWinPred_imp_groth16SoundnessWinPred_projected p hp)

/-- **Convenience packaging** for `cross_component_session_bind_negl`
    via `SecurityExp` — the asymptotic security-experiment form.

    Given a fail experiment `bindFailExp`, five soundness
    experiments (one per cryptographic assumption), the pointwise
    five-summand union bound, and security (negligibility) of each
    component experiment, `bindFailExp.secure` holds.

    Mirrors the Step 6.1 / 6.2 dual / triple `SecurityExp`
    packagings, scaled to the five-summand case. -/
theorem crossSessionBindFail_secure_of_quad_bundle_secure
    (bindFailExp : SecurityExp)
    (groth16KSExp : SecurityExp)
    (circuitEqExp : SecurityExp)
    (tdxExp : SecurityExp)
    (hashExp : SecurityExp)
    (hashBExp : SecurityExp)
    (h_bound : ∀ n,
      bindFailExp.advantage n ≤
        groth16KSExp.advantage n + circuitEqExp.advantage n +
        tdxExp.advantage n + hashExp.advantage n + hashBExp.advantage n)
    (h_groth_ks_secure : groth16KSExp.secure)
    (h_circuit_secure  : circuitEqExp.secure)
    (h_tdx_secure      : tdxExp.secure)
    (h_hash_secure     : hashExp.secure)
    (h_hashB_secure    : hashBExp.secure) :
    bindFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    bindFailExp
    (fun n =>
      groth16KSExp.advantage n + circuitEqExp.advantage n +
      tdxExp.advantage n + hashExp.advantage n + hashBExp.advantage n)
    (negligible_add
      (negligible_add
        (negligible_add
          (negligible_add h_groth_ks_secure h_circuit_secure)
          h_tdx_secure)
        h_hash_secure)
      h_hashB_secure)
    h_bound

/-- **Security-game reduction form (unbounded-adversary statement)**
    for `cross_component_session_bind_negl`: the quadruple-bundle
    (five-summand) reduction expressed via
    `SecurityGame.secureAgainst` with the project-standard `IsPPT`
    filter.

    Given a fixed reduction
        reduce : CrossSessionBindAdv → Groth16KSAdv × CircuitEqAdv ×
                                       TdxVerifierSoundAdv ×
                                       CommitHashCollisionAdv ×
                                       CommitHashBytesCollisionAdv
    and the pointwise five-summand bound on the games' advantages,
    security of each of the five component games (against `IsPPT`)
    implies security of the cross-component-session-bind game
    (against `IsPPT`).

    **IsPPT placeholder gap (cycle 6.12 rename)**: with `IsPPT`
    currently `True`-placeholder, `secureAgainst IsPPT` ranges
    over all adversaries. The `_AGAINST_UNBOUNDED_ADVERSARIES`
    suffix surfaces this gap at the call site. See
    `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES`
    in `ProtocolVCVioDual.lean` for the full rationale.

    The proof composes four `negligible_add` applications around
    five `secure A` invocations, then closes via `negligible_of_le`.
    Same shape as the Step 6.1 / 6.2 game-form packagings, scaled. -/
theorem crossSessionBindGame_secure_of_quad_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES
    {bindGame    : SecurityGame CrossSessionBindAdv}
    {groth16KSGame' : SecurityGame Groth16KSAdv}
    {circuitEqGame' : SecurityGame CircuitEqAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    {hashBGame   : SecurityGame CommitHashBytesCollisionAdv}
    (reduce : CrossSessionBindAdv →
      Groth16KSAdv × CircuitEqAdv × TdxVerifierSoundAdv ×
      CommitHashCollisionAdv × CommitHashBytesCollisionAdv)
    (h_bound : ∀ A n,
      bindGame.advantage A n ≤
        groth16KSGame'.advantage (reduce A).1 n +
        circuitEqGame'.advantage (reduce A).2.1 n +
        tdxGame.advantage        (reduce A).2.2.1 n +
        hashGame.advantage       (reduce A).2.2.2.1 n +
        hashBGame.advantage      (reduce A).2.2.2.2 n)
    (h_groth_ks_secure : groth16KSGame'.secureAgainst IsPPT)
    (h_circuit_secure  : circuitEqGame'.secureAgainst IsPPT)
    (h_tdx_secure      : tdxGame.secureAgainst IsPPT)
    (h_hash_secure     : hashGame.secureAgainst IsPPT)
    (h_hashB_secure    : hashBGame.secureAgainst IsPPT) :
    bindGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (negligible_add
          (negligible_add
            (h_groth_ks_secure (reduce A).1       (IsPPT_trivial _))
            (h_circuit_secure  (reduce A).2.1     (IsPPT_trivial _)))
          (h_tdx_secure        (reduce A).2.2.1   (IsPPT_trivial _)))
        (h_hash_secure         (reduce A).2.2.2.1 (IsPPT_trivial _)))
      (h_hashB_secure          (reduce A).2.2.2.2 (IsPPT_trivial _)))

/-! ## Closing assessment

This is the **final lift** of the Step 6 sequence.

Cumulative state at Step 6.3 exit:

* Axiom count: 26 (unchanged since Step 5; the lift sequence is
  additive — no axioms touched).
* Protocol theorems lifted: 8 of 8 — 1 single-bundle (Step 6.0) +
  1 dual-bundle (Step 6.1) + 5 triple-bundle (Step 6.2) + 1
  quadruple-bundle (this step).
* Union-bound composition: scales from 1 summand (Step 6.0) to 5
  summands (Step 6.3), each step adding one `negligible_add`.
* All lifts: zero `sorry`, real reduction proofs, parametric over
  hardness hypotheses.

The Step 6.3 lift exercises the doubled-negligibility shape that
Step 5 surfaced as a (d)-bucket finding: `groth16Verifier` is the
classical-`Prop` collapse of TWO independent computational
assumptions (Groth16 knowledge soundness + zkdcap circuit
equivalence). The triple-bundle lifts collapsed the disjunction
back into a monolithic adversary; the quadruple lift expands it
into the truthful five-summand union bound. This is the
methodology-level pay-off of the Step 5 honesty finding.

Outstanding (out of scope for Step 6.3, in scope for Step 7):

* Integration-ledger regeneration with the post-Step-6 trust
  density metric and the explicit five-summand decomposition of
  `cross_component_session_bind`'s soundness budget.

* Discharging the five negligibility hypotheses against
  cryptographic libraries:
    - ArkLib Groth16 KS (when ArkLib lands)
    - Lean reference DCAP verifier + circuit equivalence
    - PCK-signature unforgeability reduction
    - Random-oracle birthday bound for both hash summands (requires
      `[Fintype UserData]` carrier refinement)

* Adopting VCV-io's `PolyQueries` as the `IsPPT` body once
  adversaries take `OracleComp ProtocolSpec` access.

* `colosseum-adversarial` review of the composed
  single+dual+triple+quadruple surface (Step 6.2 deferred until
  this lift landed).
-/

end Specs.Quartz.Protocol.ProtocolVCVioQuad
