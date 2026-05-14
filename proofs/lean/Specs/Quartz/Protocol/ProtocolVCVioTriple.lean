/-
  Protocol-layer VCV-io scaffolding — Step 6.2 triple-bundle lifts.

  --------------------------------------------------------------------
  Scope
  --------------------------------------------------------------------

  This module extends `ProtocolVCVio.lean` (Step 6.0, single-bundle
  proof-of-concept) and `ProtocolVCVioDual.lean` (Step 6.1,
  dual-bundle lift of `handshake_sound`) with the **five
  triple-bundle protocol-layer theorems**:

    1. `handshake_binds_ecies_key`
    2. `session_confidentiality`
    3. `session_confidentiality_via_extractor`
    4. `cross_component_transfers_conservation`
    5. `cross_component_auction_winner_determinism`

  Each of the five rides on the dual-bundle baseline
  (`tdxVerifier` + `groth16Verifier`) plus one *hash-collision*
  bundle:

  - **Theorems 1–3** consume `commitHashE : UserDataCommit ↪ UserData`
    (Step 2 bundle — the structured-domain commitment hash).
  - **Theorems 4–5** consume `commitHashBytesE : ByteSeq ↪ UserData`
    (Step 3 bundle — the byte-domain serialization hash).

  Confirmed via `lean_verify` before lift:

      handshake_binds_ecies_key,
      session_confidentiality,
      session_confidentiality_via_extractor
        axioms include: {tdxVerifier, groth16Verifier, commitHashE}

      cross_component_transfers_conservation,
      cross_component_auction_winner_determinism
        axioms include: {tdxVerifier, groth16Verifier, commitHashBytesE}

  Plus standard logic and carriers; no other bundles. Each is
  therefore genuinely *triple-bundle*, consistent with the Step 6.1
  classification table.

  --------------------------------------------------------------------
  Lift pattern (triple-bundle template)
  --------------------------------------------------------------------

  The Step 6.0 single-bundle pattern reduced to `negligible_of_le`;
  Step 6.1's dual-bundle case composed it with one `negligible_add`
  step (`negligible_of_le ∘ negligible_add`). The triple-bundle case
  composes one additional `negligible_add` step:

      negligible_of_le h_bound
        (negligible_add h_groth_negl
          (negligible_add h_tdx_negl h_hash_negl))

  Concretely the protocol-fail advantage is bounded by the *sum* of
  the three underlying soundness advantages, each of which is
  assumed negligible:

      protocolFailAdv ≤ groth16SoundAdv + tdxVerifierSoundAdv + hashCollisionAdv

  Negligibility is closed under finite sums (`negligible_add`);
  pointwise bound monotonicity gives the union-bound shape
  (`negligible_of_le`).

  --------------------------------------------------------------------
  Honest framing of the hash-collision summand
  --------------------------------------------------------------------

  The bundled `commitHashE : UserDataCommit ↪ UserData` and
  `commitHashBytesE : ByteSeq ↪ UserData` are
  **mathematically-impossible-as-stated** Function.Embeddings —
  pigeonhole forbids any injection from an open-cardinality preimage
  into a fixed-width 64-byte `UserData` codomain. The companion
  modules `UserDataCommitVCVio.lean` and `RawMessagesVCVio.lean`
  document this finding explicitly; both flag that the *truthful*
  statement is collision negligibility under a random-oracle model.

  The framing chosen for this module is **Option (b)**: keep the
  embedding model at the spec/classical layer, and frame the
  Step 6.2 negligibility hypothesis as the **collision-resistance
  advantage of a hypothetical concrete hash function `H` that the
  embedding-axiom abstracts over**.

  The hypothesis `negligible (commitHashCollAdv 𝒜_h)` is the
  standard cryptographic statement on a hash `H : UserDataCommit →
  UserData`. Under the spec-level pigeonhole impossibility, this
  hypothesis is *strictly weaker* than (and hence implied by) the
  embedding axiom — the lifted theorems are honest about depending
  on collision resistance of the *real* hash function, not on the
  literally-impossible embedding-side injectivity claim.

  The two other options considered:

  - **(a) Replace `commitHashE` with a concrete `H` carrier axiom.**
    Would touch every dependent classical theorem, fragment the
    spec-vs-impl boundary, and require carrier refinement for
    `UserData`. Out of scope for Step 6.2 (and Step 6.3).

  - **(c) Add a parallel "concrete hash carrier" axiom alongside the
    embedding.** Doubles the axiom surface. Cleaner semantically but
    no methodology gain over Option (b) — the hypothesis lives in
    the same place either way.

  Option (b) is the lighter-touch and matches the precedent set in
  Step 6.0 / 6.1 (parametric hypotheses for negligibility budgets
  that the spec layer cannot yet discharge). The change record
  documents the call explicitly under "Critical honesty question
  for commitHashE".

  --------------------------------------------------------------------
  Carrier of adversary types
  --------------------------------------------------------------------

  Two new adversary types are introduced:

  - `CommitHashCollisionAdv : Type` — outputs a candidate pair
    `(uc₁, uc₂) : UserDataCommit × UserDataCommit` with `uc₁ ≠ uc₂`
    such that `commitHash uc₁ = commitHash uc₂` (a collision under
    the concrete hash function `H` the embedding `commitHashE`
    abstracts over).

  - `CommitHashBytesCollisionAdv : Type` — analogous, with the
    `ByteSeq × ByteSeq` domain instead of `UserDataCommit ×
    UserDataCommit`.

  All adversary types ride on the project-standard `IsPPT`
  placeholder filter (see `ProtocolVCVio.lean` for the rationale
  on the placeholder body).

  The handshake-soundness adversary `HandshakeSoundAdv` is
  imported unchanged from `ProtocolVCVioDual.lean`; the
  cross-component theorems introduce two new wrapper adversaries:

  - `TransfersConservationAdv : Type` — outputs a candidate
    `(HandshakeCheck × TransferRequest)` such that the contract
    accepts but the conservation invariant fails to propagate.

  - `AuctionDeterminismAdv : Type` — outputs a candidate
    `(HandshakeCheck × AuctionRound × ResolveMessage)` such that
    the contract accepts but the claimed winner does not match the
    canonical Vickrey resolution.
-/

import VCVio.CryptoFoundations.Asymptotics.Security
import Specs.Quartz.Protocol.ProtocolVCVio
import Specs.Quartz.Protocol.ProtocolVCVioDual
import Specs.Quartz.Protocol.Confidentiality
import Specs.Quartz.Protocol.Conservation
import Specs.Quartz.Protocol.AuctionDeterminism

namespace Specs.Quartz.Protocol.ProtocolVCVioTriple

open ENNReal
open OracleSpec OracleComp

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap
open Specs.Quartz.Protocol.Handshake
open Specs.Quartz.Protocol.Confidentiality
open Specs.Quartz.Protocol.Conservation
open Specs.Quartz.Protocol.AuctionDeterminism
open Specs.Quartz.Protocol.ProtocolVCVio
open Specs.Quartz.Protocol.ProtocolVCVioDual

/-! ## Collision-resistance adversaries for the bundled hash axioms

The Step 2 / Step 3 bundled axioms `commitHashE` and `commitHashBytesE`
are spec-level placeholders for concrete hash functions
`H : UserDataCommit → UserData` and `H_b : ByteSeq → UserData`. The
truthful statement (per the companion-module commentary) is that
these hashes are **collision-resistant** — no PPT adversary can
produce a colliding pre-image pair except with negligible probability.

The adversaries below are the standard collision-finder shape: at each
security parameter `n` produce a pair `(x₁, x₂)` and claim they
collide. The advantage is the probability the pair is a genuine
collision (`x₁ ≠ x₂ ∧ H x₁ = H x₂`).
-/

/-- A `commitHash` collision-finder adversary: at each security
    parameter `n`, outputs a candidate pair of `UserDataCommit`
    values. The "win" condition is that the pair is a collision:
    distinct inputs with equal hashes.

    Currently no-oracle-access, matching the Step 6.0 / 6.1
    pattern. When carriers refine and adversaries gain
    `OracleComp ProtocolSpec` access, this will be lifted to an
    `OracleComp`-valued adversary and the placeholder `IsPPT`
    swapped for `PolyQueries`. -/
def CommitHashCollisionAdv : Type :=
  ℕ → ProbComp (UserDataCommit × UserDataCommit)

/-- The advantage of a `commitHash` collision-finder at security
    parameter `n`, parametrised on an opaque bound.

    Conceptually:

        Pr[uc₁ ≠ uc₂ ∧ commitHash uc₁ = commitHash uc₂
          | (uc₁, uc₂) ← 𝒜 n]

    The same `[Fintype]` blocker that prevents concrete computation
    of `Groth16SoundAdvantage` and `TdxVerifierSoundAdvantage`
    applies here (`UserDataCommit` lacks a `Fintype` instance, and
    `UserData` is fully abstract). The advantage is therefore
    parametric. -/
abbrev CommitHashCollisionAdvantage : Type :=
  CommitHashCollisionAdv → ℕ → ℝ≥0∞

/-- The `commitHash` collision-resistance security game. -/
def commitHashCollisionGame (adv : CommitHashCollisionAdvantage) :
    SecurityGame CommitHashCollisionAdv where
  advantage := adv

/-- A `commitHashBytes` collision-finder adversary: at each security
    parameter `n`, outputs a candidate pair of `ByteSeq` values. The
    "win" condition is that the pair is a collision under the
    byte-domain hash. -/
def CommitHashBytesCollisionAdv : Type :=
  ℕ → ProbComp (ByteSeq × ByteSeq)

/-- The advantage of a `commitHashBytes` collision-finder at security
    parameter `n`. Parametric on an opaque bound for the same
    `[Fintype]` reasons as `CommitHashCollisionAdvantage`. -/
abbrev CommitHashBytesCollisionAdvantage : Type :=
  CommitHashBytesCollisionAdv → ℕ → ℝ≥0∞

/-- The `commitHashBytes` collision-resistance security game. -/
def commitHashBytesCollisionGame (adv : CommitHashBytesCollisionAdvantage) :
    SecurityGame CommitHashBytesCollisionAdv where
  advantage := adv

/-! ## Composite triple-bundle adversaries -/

/-- A `handshake_binds_ecies_key`-attack adversary: at each security
    parameter, outputs a candidate
    `(HandshakeCheck × UserDataCommit × PrivKey × Plaintext)` such
    that the contract accepts but the three-pronged conclusion
    (signed-quote-existence ∧ pubkey-extraction ∧ ECIES roundtrip)
    fails. -/
def HandshakeBindsAdv : Type :=
  ℕ → ProbComp (HandshakeCheck × UserDataCommit × PrivKey × Plaintext)

/-- The advantage of a `handshake_binds_ecies_key`-attack adversary. -/
abbrev HandshakeBindsAdvantage : Type :=
  HandshakeBindsAdv → ℕ → ℝ≥0∞

/-- A `session_confidentiality`-attack adversary: at each security
    parameter, outputs a candidate
    `(HandshakeCheck × UserDataCommit × PrivKey × Plaintext)` such
    that the contract accepts but ECIES decryption fails to
    recover the plaintext. -/
def SessionConfidentialityAdv : Type :=
  ℕ → ProbComp (HandshakeCheck × UserDataCommit × PrivKey × Plaintext)

/-- The advantage of a `session_confidentiality`-attack adversary. -/
abbrev SessionConfidentialityAdvantage : Type :=
  SessionConfidentialityAdv → ℕ → ℝ≥0∞

/-- A `session_confidentiality_via_extractor`-attack adversary. Same
    shape as `SessionConfidentialityAdv`; the difference is the
    win-condition formulation (extractor-mediated). -/
def SessionConfidentialityExtractorAdv : Type :=
  ℕ → ProbComp (HandshakeCheck × UserDataCommit × PrivKey × Plaintext)

/-- The advantage of a `session_confidentiality_via_extractor`-attack
    adversary. -/
abbrev SessionConfidentialityExtractorAdvantage : Type :=
  SessionConfidentialityExtractorAdv → ℕ → ℝ≥0∞

/-- A `cross_component_transfers_conservation`-attack adversary: at
    each security parameter, outputs a candidate
    `(HandshakeCheck × TransferRequest)` such that the contract
    accepts but the conservation invariant fails to propagate. -/
def TransfersConservationAdv : Type :=
  ℕ → ProbComp (HandshakeCheck × TransferRequest)

/-- The advantage of a `cross_component_transfers_conservation`-attack
    adversary. -/
abbrev TransfersConservationAdvantage : Type :=
  TransfersConservationAdv → ℕ → ℝ≥0∞

/-- A `cross_component_auction_winner_determinism`-attack adversary:
    at each security parameter, outputs a candidate
    `(HandshakeCheck × AuctionRound × ResolveMessage)` such that the
    contract accepts but the claimed winner does not match the
    canonical Vickrey resolution. -/
def AuctionDeterminismAdv : Type :=
  ℕ → ProbComp (HandshakeCheck × AuctionRound × ResolveMessage)

/-- The advantage of a `cross_component_auction_winner_determinism`-
    attack adversary. -/
abbrev AuctionDeterminismAdvantage : Type :=
  AuctionDeterminismAdv → ℕ → ℝ≥0∞

/-! ## Content-bearing advantage definitions (Cycle 6.6 — Round A fix)

Replicates the cycle-6.4/6.5 def-tying pattern on `handshake_binds_ecies_key_negl`.

**Bundling correction (continuation of cycle 6.5's pattern)**: tracing
the classical `handshake_binds_ecies_key` proof's conclusion parts:

- **P1** (`∃ q, was_signed_by_dstack q ∧ userDataOf q = some h.msgUserData`):
  failure event is a Groth16-soundness break (forward direction).
- **P2** (`pkOfUserData h.msgUserData = some c.eciesPubkey`):
  `pkOfUserData_commitHash` is an *unconditional theorem* in the classical
  chain (it derives from `commitHash_inj`, which projects from the bundled
  `commitHashE`). No probabilistic failure event in the current carrier
  model.
- **P3** (`decrypt sk (encrypt c.eciesPubkey pt) = some pt`):
  `roundtrip` is an *unconditional axiomatic equality* given the
  `keyOf sk = c.eciesPubkey` hypothesis. No probabilistic failure event.

The lift's probabilistic failure event is therefore *only* the P1 failure
mode — single-bundle (Groth16-only). The prior triple-bundle decomposition
included `tdxAdv` and `hashAdv` summands that were not load-bearing
relative to the actual axiom consumption. `commitHashE` and ECIES axioms
remain in the classical closure of this proof (because `pkOfUserData_commitHash`
and `roundtrip` are consumed), but their probabilistic refinement is a
separate concern queued for a later cycle (would move P2's failure event
behind a collision-resistance hypothesis on the concrete hash).
-/

/-- **Win predicate for the handshake-binds-ECIES-key game**: the
    hypotheses hold (contract accepts; user_data is the structured
    commit; the private key matches the committed ECIES pubkey), but
    the three-conjunct conclusion fails. Per the analysis above, the
    only realisable failure mode is the P1 (signed-quote-existence)
    failure — P2 and P3 are unconditional in the current carrier model. -/
def handshakeBindsWinPred
    (p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext) : Prop :=
  let (h, c, sk, pt) := p
  Accepted h ∧
  h.msgUserData = commitHash c ∧
  keyOf sk = c.eciesPubkey ∧
  ¬ ( (∃ q, was_signed_by_dstack q ∧ userDataOf q = some h.msgUserData) ∧
      pkOfUserData h.msgUserData = some c.eciesPubkey ∧
      decrypt sk (encrypt c.eciesPubkey pt) = some pt )

/-- **Reduction**: from a binds-attack adversary, construct a
    Groth16-soundness adversary by projecting the candidate's
    `(proof, inputs)` pair. -/
def reduce_binds_to_groth (𝒜 : HandshakeBindsAdv) : Groth16SoundAdv :=
  fun n => do let p ← 𝒜 n; pure (p.1.proof, p.1.inputs)

/-- **Content-bearing advantage** for the handshake-binds game. -/
noncomputable def bindsFailAdv (𝒜 : HandshakeBindsAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ handshakeBindsWinPred | 𝒜 n ]

/-- Forward implication: a binds-attack win on `(h, c, sk, pt)` implies
    a Groth16-soundness win on the projected `(h.proof, h.inputs)`.
    The proof uses `pkOfUserData_commitHash` and `roundtrip` to eliminate
    the P2 and P3 failure cases, leaving only the P1 (Groth16) break. -/
theorem handshakeBindsWinPred_imp_groth16SoundnessWinPred_projected
    (p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext)
    (hp : handshakeBindsWinPred p) :
    groth16SoundnessWinPred (p.1.proof, p.1.inputs) := by
  obtain ⟨⟨hZk, hMr, hUd⟩, h_commit, h_sk, h_neg⟩ := hp
  refine ⟨hZk, ?_⟩
  intro h_signed
  apply h_neg
  refine ⟨⟨inputs_to_quote p.1.inputs, h_signed, hUd⟩, ?_, ?_⟩
  · rw [h_commit]; exact pkOfUserData_commitHash p.2.1
  · rw [← h_sk]; exact roundtrip p.2.2.1 p.2.2.2

/-! ## Triple-bundle lifted theorem 1: `handshake_binds_ecies_key` -/

/-- **Classical form (preserved as a corollary)**: `handshake_binds_ecies_key`.

    Re-exported from `Handshake.lean` for convenience. Rides on the
    triple-bundle `tdxVerifier` (Step 4) + `groth16Verifier`
    (Step 5) + `commitHashE` (Step 2) classical-`Prop` axioms.

    The classical chain remains unchanged: this corollary preserves
    the original axiom closure. -/
theorem handshake_binds_ecies_key_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (c : UserDataCommit)
    (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey)
    (h_sk : keyOf sk = c.eciesPubkey)
    (pt : Plaintext) :
    (∃ q, was_signed_by_dstack q ∧ userDataOf q = some h.msgUserData) ∧
    pkOfUserData h.msgUserData = some c.eciesPubkey ∧
    decrypt sk (encrypt c.eciesPubkey pt) = some pt :=
  handshake_binds_ecies_key h acc c h_commit sk h_sk pt

/-- **Probabilistic form (Step 6.2 lift, Cycle-6.6-corrected)**:
    `handshake_binds_ecies_key_negl`.

    Given a handshake-binds adversary `𝒜` and a Groth16-soundness
    negligibility hypothesis on the projected adversary, the binds
    failure advantage is negligible.

    **Cycle 6.6 correction notes**: see the Content-bearing definitions
    section above. The bundling is reduced from triple to single
    (Groth16-only) to match the actual axiom consumption of the
    classical proof. `commitHashE` and ECIES axioms remain in the
    closure (consumed by `pkOfUserData_commitHash` and `roundtrip`
    respectively), but they do not contribute probabilistic failure
    summands in the current carrier model. Round A attacks #1, #2, #3,
    #11 are structurally closed for this lift. -/
theorem handshake_binds_ecies_key_negl
    (𝒜 : HandshakeBindsAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_binds_to_groth 𝒜))) :
    negligible (bindsFailAdv 𝒜) := by
  refine negligible_of_le ?_ h_groth_negl
  intro n
  show Pr[ handshakeBindsWinPred | 𝒜 n ] ≤
       Pr[ groth16SoundnessWinPred | reduce_binds_to_groth 𝒜 n ]
  rw [show reduce_binds_to_groth 𝒜 n
        = 𝒜 n >>= pure ∘
            (fun p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext =>
              (p.1.proof, p.1.inputs))
        from rfl,
      probEvent_bind_pure_comp]
  exact probEvent_mono (fun p _ hp =>
    handshakeBindsWinPred_imp_groth16SoundnessWinPred_projected p hp)

/-- **Convenience packaging** for `handshake_binds_ecies_key_negl`
    via `SecurityExp`. -/
theorem handshakeBindsFail_secure_of_triple_bundle_secure
    (bindsFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (hashExp : SecurityExp)
    (h_bound : ∀ n,
      bindsFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n + hashExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure)
    (h_hash_secure  : hashExp.secure) :
    bindsFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    bindsFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n + hashExp.advantage n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      h_hash_secure)
    h_bound

/-- **Security-game reduction form** for
    `handshake_binds_ecies_key_negl`: the triple-bundle reduction
    expressed via `SecurityGame.secureAgainst` with the project-
    standard `IsPPT` filter. -/
theorem handshakeBindsGame_secure_of_triple_bundle_secure
    {bindsGame   : SecurityGame HandshakeBindsAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    (reduce : HandshakeBindsAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashCollisionAdv)
    (h_bound : ∀ A n,
      bindsGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashGame.advantage    (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT)
    (h_hash_secure  : hashGame.secureAgainst IsPPT) :
    bindsGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (IsPPT_trivial _))
        (h_tdx_secure   (reduce A).2.1   (IsPPT_trivial _)))
      (h_hash_secure  (reduce A).2.2     (IsPPT_trivial _)))

/-! ## Triple-bundle lifted theorem 2: `session_confidentiality` -/

/-- **Classical form (preserved as a corollary)**: `session_confidentiality`. -/
theorem session_confidentiality_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (c : UserDataCommit) (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey) (h_sk : keyOf sk = c.eciesPubkey)
    (msg : Plaintext) :
    decrypt sk (encrypt c.eciesPubkey msg) = some msg :=
  session_confidentiality h acc c h_commit sk h_sk msg

/-- **Probabilistic form (Step 6.2 triple-bundle lift)**:
    `session_confidentiality_negl`.

    Three-summand union bound identical in shape to
    `handshake_binds_ecies_key_negl`. The `session_confidentiality`
    classical proof rides on the same three bundles (and is in fact
    a downstream of `handshake_binds_ecies_key`); the lifted form
    shares the same hypothesis discipline. -/
theorem session_confidentiality_negl
    (𝒜 : SessionConfidentialityAdv)
    (𝒜_groth : Groth16SoundAdv)
    (𝒜_tdx : TdxVerifierSoundAdv)
    (𝒜_hash : CommitHashCollisionAdv)
    (confFailAdv : SessionConfidentialityAdv → ℕ → ℝ≥0∞)
    (groth16Adv : Groth16SoundAdvantage)
    (tdxAdv : TdxVerifierSoundAdvantage)
    (hashAdv : CommitHashCollisionAdvantage)
    (h_bound : ∀ n,
      confFailAdv 𝒜 n ≤
        groth16Adv 𝒜_groth n + tdxAdv 𝒜_tdx n + hashAdv 𝒜_hash n)
    (h_groth_negl : negligible (groth16Adv 𝒜_groth))
    (h_tdx_negl : negligible (tdxAdv 𝒜_tdx))
    (h_hash_negl : negligible (hashAdv 𝒜_hash)) :
    negligible (confFailAdv 𝒜) :=
  negligible_of_le h_bound
    (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hash_negl)

/-- **Convenience packaging** for `session_confidentiality_negl`
    via `SecurityExp`. -/
theorem sessionConfFail_secure_of_triple_bundle_secure
    (confFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (hashExp : SecurityExp)
    (h_bound : ∀ n,
      confFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n + hashExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure)
    (h_hash_secure  : hashExp.secure) :
    confFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    confFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n + hashExp.advantage n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      h_hash_secure)
    h_bound

/-- **Security-game reduction form** for `session_confidentiality_negl`. -/
theorem sessionConfGame_secure_of_triple_bundle_secure
    {confGame    : SecurityGame SessionConfidentialityAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    (reduce : SessionConfidentialityAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashCollisionAdv)
    (h_bound : ∀ A n,
      confGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashGame.advantage    (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT)
    (h_hash_secure  : hashGame.secureAgainst IsPPT) :
    confGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (IsPPT_trivial _))
        (h_tdx_secure   (reduce A).2.1   (IsPPT_trivial _)))
      (h_hash_secure  (reduce A).2.2     (IsPPT_trivial _)))

/-! ## Triple-bundle lifted theorem 3: `session_confidentiality_via_extractor` -/

/-- **Classical form (preserved as a corollary)**:
    `session_confidentiality_via_extractor`. -/
theorem session_confidentiality_via_extractor_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (c : UserDataCommit) (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey) (h_sk : keyOf sk = c.eciesPubkey)
    (msg : Plaintext) :
    ∃ pk, pkOfUserData h.msgUserData = some pk ∧
          decrypt sk (encrypt pk msg) = some msg :=
  session_confidentiality_via_extractor h acc c h_commit sk h_sk msg

/-- **Probabilistic form (Step 6.2 triple-bundle lift)**:
    `session_confidentiality_via_extractor_negl`. Same union-bound
    shape as the previous two. -/
theorem session_confidentiality_via_extractor_negl
    (𝒜 : SessionConfidentialityExtractorAdv)
    (𝒜_groth : Groth16SoundAdv)
    (𝒜_tdx : TdxVerifierSoundAdv)
    (𝒜_hash : CommitHashCollisionAdv)
    (extFailAdv : SessionConfidentialityExtractorAdv → ℕ → ℝ≥0∞)
    (groth16Adv : Groth16SoundAdvantage)
    (tdxAdv : TdxVerifierSoundAdvantage)
    (hashAdv : CommitHashCollisionAdvantage)
    (h_bound : ∀ n,
      extFailAdv 𝒜 n ≤
        groth16Adv 𝒜_groth n + tdxAdv 𝒜_tdx n + hashAdv 𝒜_hash n)
    (h_groth_negl : negligible (groth16Adv 𝒜_groth))
    (h_tdx_negl : negligible (tdxAdv 𝒜_tdx))
    (h_hash_negl : negligible (hashAdv 𝒜_hash)) :
    negligible (extFailAdv 𝒜) :=
  negligible_of_le h_bound
    (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hash_negl)

/-- **Convenience packaging** for `session_confidentiality_via_extractor_negl`
    via `SecurityExp`. -/
theorem sessionConfExtractorFail_secure_of_triple_bundle_secure
    (extFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (hashExp : SecurityExp)
    (h_bound : ∀ n,
      extFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n + hashExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure)
    (h_hash_secure  : hashExp.secure) :
    extFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    extFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n + hashExp.advantage n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      h_hash_secure)
    h_bound

/-- **Security-game reduction form** for `session_confidentiality_via_extractor_negl`. -/
theorem sessionConfExtractorGame_secure_of_triple_bundle_secure
    {extGame     : SecurityGame SessionConfidentialityExtractorAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    (reduce : SessionConfidentialityExtractorAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashCollisionAdv)
    (h_bound : ∀ A n,
      extGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashGame.advantage    (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT)
    (h_hash_secure  : hashGame.secureAgainst IsPPT) :
    extGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (IsPPT_trivial _))
        (h_tdx_secure   (reduce A).2.1   (IsPPT_trivial _)))
      (h_hash_secure  (reduce A).2.2     (IsPPT_trivial _)))

/-! ## Triple-bundle lifted theorem 4: `cross_component_transfers_conservation`

The fourth and fifth theorems substitute `commitHashBytesE`
(byte-domain hash, Step 3 bundle) for `commitHashE`
(structured-domain hash, Step 2 bundle) in the third union-bound
summand. Otherwise the union-bound pattern is identical.
-/

/-- **Classical form (preserved as a corollary)**:
    `cross_component_transfers_conservation`. -/
theorem cross_component_transfers_conservation_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (req : TransferRequest)
    (h_raw : h.msgUserData = userDataOfTransferRequest req)
    (b : EnclaveBalances)
    (hInv : conservationInvariant b)
    (b' : EnclaveBalances)
    (hApp : applyTransferRequest b req = some b') :
    (∃ q : TdxQuote,
        was_signed_by_dstack q ∧
        mrEnclaveOf q = some h.expectedMr ∧
        userDataOf q  = some (userDataOfTransferRequest req)) ∧
    conservationInvariant b' :=
  cross_component_transfers_conservation h acc req h_raw b hInv b' hApp

/-- **Probabilistic form (Step 6.2 triple-bundle lift)**:
    `cross_component_transfers_conservation_negl`.

    Three-summand union bound substituting
    `CommitHashBytesCollisionAdvantage` for the third summand
    (relative to theorems 1–3). The shape is otherwise identical.
-/
theorem cross_component_transfers_conservation_negl
    (𝒜 : TransfersConservationAdv)
    (𝒜_groth : Groth16SoundAdv)
    (𝒜_tdx : TdxVerifierSoundAdv)
    (𝒜_hashB : CommitHashBytesCollisionAdv)
    (consFailAdv : TransfersConservationAdv → ℕ → ℝ≥0∞)
    (groth16Adv : Groth16SoundAdvantage)
    (tdxAdv : TdxVerifierSoundAdvantage)
    (hashBAdv : CommitHashBytesCollisionAdvantage)
    (h_bound : ∀ n,
      consFailAdv 𝒜 n ≤
        groth16Adv 𝒜_groth n + tdxAdv 𝒜_tdx n + hashBAdv 𝒜_hashB n)
    (h_groth_negl : negligible (groth16Adv 𝒜_groth))
    (h_tdx_negl : negligible (tdxAdv 𝒜_tdx))
    (h_hashB_negl : negligible (hashBAdv 𝒜_hashB)) :
    negligible (consFailAdv 𝒜) :=
  negligible_of_le h_bound
    (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hashB_negl)

/-- **Convenience packaging** for `cross_component_transfers_conservation_negl`
    via `SecurityExp`. -/
theorem transfersConsFail_secure_of_triple_bundle_secure
    (consFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (hashBExp : SecurityExp)
    (h_bound : ∀ n,
      consFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n + hashBExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure)
    (h_hashB_secure : hashBExp.secure) :
    consFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    consFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n + hashBExp.advantage n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      h_hashB_secure)
    h_bound

/-- **Security-game reduction form** for
    `cross_component_transfers_conservation_negl`. -/
theorem transfersConsGame_secure_of_triple_bundle_secure
    {consGame    : SecurityGame TransfersConservationAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashBGame   : SecurityGame CommitHashBytesCollisionAdv}
    (reduce : TransfersConservationAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashBytesCollisionAdv)
    (h_bound : ∀ A n,
      consGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashBGame.advantage   (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT)
    (h_hashB_secure : hashBGame.secureAgainst IsPPT) :
    consGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (IsPPT_trivial _))
        (h_tdx_secure   (reduce A).2.1   (IsPPT_trivial _)))
      (h_hashB_secure  (reduce A).2.2     (IsPPT_trivial _)))

/-! ## Triple-bundle lifted theorem 5: `cross_component_auction_winner_determinism` -/

/-- **Classical form (preserved as a corollary)**:
    `cross_component_auction_winner_determinism`. -/
theorem cross_component_auction_winner_determinism_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (round : AuctionRound)
    (claimed : ResolveMessage)
    (h_raw : h.msgUserData = userDataOfResolveMessage claimed)
    (h_round : claimed.roundId = round.roundId)
    (h_canon : claimed = resolveAuction round) :
    claimed.winner = (resolveAuction round).winner ∧
    claimed.price  = (resolveAuction round).price ∧
    (∃ q : TdxQuote,
        was_signed_by_dstack q ∧
        mrEnclaveOf q = some h.expectedMr ∧
        userDataOf q  = some (userDataOfResolveMessage claimed)) :=
  cross_component_auction_winner_determinism h acc round claimed h_raw h_round h_canon

/-- **Probabilistic form (Step 6.2 triple-bundle lift)**:
    `cross_component_auction_winner_determinism_negl`.

    Three-summand union bound identical to the conservation theorem
    (theorem 4), with `commitHashBytesE` as the third summand. -/
theorem cross_component_auction_winner_determinism_negl
    (𝒜 : AuctionDeterminismAdv)
    (𝒜_groth : Groth16SoundAdv)
    (𝒜_tdx : TdxVerifierSoundAdv)
    (𝒜_hashB : CommitHashBytesCollisionAdv)
    (auctFailAdv : AuctionDeterminismAdv → ℕ → ℝ≥0∞)
    (groth16Adv : Groth16SoundAdvantage)
    (tdxAdv : TdxVerifierSoundAdvantage)
    (hashBAdv : CommitHashBytesCollisionAdvantage)
    (h_bound : ∀ n,
      auctFailAdv 𝒜 n ≤
        groth16Adv 𝒜_groth n + tdxAdv 𝒜_tdx n + hashBAdv 𝒜_hashB n)
    (h_groth_negl : negligible (groth16Adv 𝒜_groth))
    (h_tdx_negl : negligible (tdxAdv 𝒜_tdx))
    (h_hashB_negl : negligible (hashBAdv 𝒜_hashB)) :
    negligible (auctFailAdv 𝒜) :=
  negligible_of_le h_bound
    (negligible_add (negligible_add h_groth_negl h_tdx_negl) h_hashB_negl)

/-- **Convenience packaging** for
    `cross_component_auction_winner_determinism_negl` via `SecurityExp`. -/
theorem auctionDetermFail_secure_of_triple_bundle_secure
    (auctFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (hashBExp : SecurityExp)
    (h_bound : ∀ n,
      auctFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n + hashBExp.advantage n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure)
    (h_hashB_secure : hashBExp.secure) :
    auctFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    auctFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n + hashBExp.advantage n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      h_hashB_secure)
    h_bound

/-- **Security-game reduction form** for
    `cross_component_auction_winner_determinism_negl`. -/
theorem auctionDetermGame_secure_of_triple_bundle_secure
    {auctGame    : SecurityGame AuctionDeterminismAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashBGame   : SecurityGame CommitHashBytesCollisionAdv}
    (reduce : AuctionDeterminismAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashBytesCollisionAdv)
    (h_bound : ∀ A n,
      auctGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashBGame.advantage   (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT)
    (h_hashB_secure : hashBGame.secureAgainst IsPPT) :
    auctGame.secureAgainst IsPPT := fun A _hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (IsPPT_trivial _))
        (h_tdx_secure   (reduce A).2.1   (IsPPT_trivial _)))
      (h_hashB_secure  (reduce A).2.2     (IsPPT_trivial _)))

/-! ## Outstanding follow-ups (Step 6.3 work)

* **Step 6.3 — quadruple-bundle lift**. The single load-bearing
  theorem `cross_component_session_bind` rides on all four
  bundles: `tdxVerifier` + `groth16Verifier` + `commitHashE` +
  `commitHashBytesE`. The union bound has four summands (or five
  if `groth16Verifier` decomposes into KS + circuit-eq).

* **Tightening `IsPPT`**. Inherited from Step 6.0/6.1: swap the
  placeholder body for VCV-io's `PolyQueries` once adversaries
  take `OracleComp ProtocolSpec` access.

* **Discharging the negligibility hypotheses**. Same external
  dependencies as Steps 6.0/6.1, plus the hash-collision side:
  ArkLib Groth16 KS, PCK-signature unforgeability reduction,
  `[Fintype]` carriers, and a concrete hash function with proven
  collision resistance (VCV-io's `randomOracle` + birthday bound).
-/

end Specs.Quartz.Protocol.ProtocolVCVioTriple
