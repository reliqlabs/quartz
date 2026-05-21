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
  ℕ → OracleComp ProtocolSpec (UserDataCommit × UserDataCommit)

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
  ℕ → OracleComp ProtocolSpec (ByteSeq × ByteSeq)

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
  ℕ → OracleComp ProtocolSpec (HandshakeCheck × UserDataCommit × PrivKey × Plaintext)

/-- The advantage of a `handshake_binds_ecies_key`-attack adversary. -/
abbrev HandshakeBindsAdvantage : Type :=
  HandshakeBindsAdv → ℕ → ℝ≥0∞

/-- A `session_confidentiality`-attack adversary: at each security
    parameter, outputs a candidate
    `(HandshakeCheck × UserDataCommit × PrivKey × Plaintext)` such
    that the contract accepts but ECIES decryption fails to
    recover the plaintext. -/
def SessionConfidentialityAdv : Type :=
  ℕ → OracleComp ProtocolSpec (HandshakeCheck × UserDataCommit × PrivKey × Plaintext)

/-- The advantage of a `session_confidentiality`-attack adversary. -/
abbrev SessionConfidentialityAdvantage : Type :=
  SessionConfidentialityAdv → ℕ → ℝ≥0∞

/-- A `session_confidentiality_via_extractor`-attack adversary. Same
    shape as `SessionConfidentialityAdv`; the difference is the
    win-condition formulation (extractor-mediated). -/
def SessionConfidentialityExtractorAdv : Type :=
  ℕ → OracleComp ProtocolSpec (HandshakeCheck × UserDataCommit × PrivKey × Plaintext)

/-- The advantage of a `session_confidentiality_via_extractor`-attack
    adversary. -/
abbrev SessionConfidentialityExtractorAdvantage : Type :=
  SessionConfidentialityExtractorAdv → ℕ → ℝ≥0∞

/-- A `cross_component_transfers_conservation`-attack adversary: at
    each security parameter, outputs a candidate
    `(HandshakeCheck × TransferRequest)` such that the contract
    accepts but the conservation invariant fails to propagate. -/
def TransfersConservationAdv : Type :=
  ℕ → OracleComp ProtocolSpec (HandshakeCheck × TransferRequest)

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
  ℕ → OracleComp ProtocolSpec (HandshakeCheck × AuctionRound × ResolveMessage)

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
  fun n => do
    let p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext ← 𝒜 n
    pure (p.1.proof, p.1.inputs)

/-- **Cycle 6.14.b — `IsPPT_proper`-preservation under
    `reduce_binds_to_groth`**. Same structure as
    `reduce_handshake_to_groth_preserves_IsPPT_proper`. -/
theorem reduce_binds_to_groth_preserves_IsPPT_proper
    (𝒜 : HandshakeBindsAdv) (h : IsPPT_proper 𝒜) :
    IsPPT_proper (reduce_binds_to_groth 𝒜) :=
  IsPPT_proper_of_bind_pure_comp 𝒜
    (fun p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext =>
      (p.1.proof, p.1.inputs)) h

/-- **Content-bearing advantage** for the handshake-binds game. -/
noncomputable def bindsFailAdv (𝒜 : HandshakeBindsAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ handshakeBindsWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

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
  show Pr[ handshakeBindsWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ] ≤
       Pr[ groth16SoundnessWinPred | simulateQ protocolSpecHonestSim (reduce_binds_to_groth 𝒜 n) ]
  rw [show reduce_binds_to_groth 𝒜 n
        = 𝒜 n >>= pure ∘
            (fun p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext =>
              (p.1.proof, p.1.inputs))
        from rfl]
  simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]
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

/-- **Security-game reduction form (unbounded-adversary statement)**
    for `handshake_binds_ecies_key_negl`: the triple-bundle
    reduction expressed via `SecurityGame.secureAgainst` with the
    project-standard `IsPPT` filter.

    **IsPPT placeholder gap (cycle 6.12 rename)**: with `IsPPT`
    currently `True`-placeholder, `secureAgainst IsPPT` ranges
    over all adversaries. The `_AGAINST_UNBOUNDED_ADVERSARIES`
    suffix surfaces this gap at the call site. See
    `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES`
    in `ProtocolVCVioDual.lean` for the full rationale. -/
theorem handshakeBindsGame_secure_of_triple_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES
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

/-- **Cycle 6.14.c** parallel PPT-bounded packaging. See the
    Dual file's `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_PPT_ADVERSARIES`
    for the design rationale and honesty caveat. -/
theorem handshakeBindsGame_secure_of_triple_bundle_secure_AGAINST_PPT_ADVERSARIES
    {bindsGame   : SecurityGame HandshakeBindsAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    (reduce : HandshakeBindsAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashCollisionAdv)
    (reduce_preserves_ppt : ∀ A, IsPPT_proper A →
      IsPPT_proper (reduce A).1 ∧ IsPPT_proper (reduce A).2.1 ∧
        IsPPT_proper (reduce A).2.2)
    (h_bound : ∀ A n,
      bindsGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashGame.advantage    (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT_proper)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT_proper)
    (h_hash_secure  : hashGame.secureAgainst IsPPT_proper) :
    bindsGame.secureAgainst IsPPT_proper := fun A hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (reduce_preserves_ppt A hA).1)
        (h_tdx_secure   (reduce A).2.1   (reduce_preserves_ppt A hA).2.1))
      (h_hash_secure  (reduce A).2.2     (reduce_preserves_ppt A hA).2.2))

/-! ## Triple-bundle lifted theorem 2: `session_confidentiality`

**Cycle 6.7 framing (Round A response)**: under the spec's current
ECIES abstraction (`roundtrip` is a derived theorem in `Ecies.lean`,
not a probabilistic axiom), the session-confidentiality failure event
is **unconditionally impossible** given the hypotheses. The lift
therefore proves the strict claim "`confFailAdv 𝒜 = 0`", from which
negligibility follows immediately. No bundle hypothesis is required.

This is honest about a real limitation: the lift only captures the
*deterministic-roundtrip* failure mode, not chosen-plaintext-attack
(IND-CPA) security. The latter would require modelling ECIES as a
probabilistic encryption scheme with an adversary that observes
oracle outputs — a separate refactor that adds a CPA-style win event
parameterised on an ECIES IND-CPA hypothesis. The current cycle does
NOT make that claim; it makes the strictly weaker (and honestly
true) claim that the spec's deterministic-roundtrip failure event
has probability zero.
-/

/-- **Classical form (preserved as a corollary)**: `session_confidentiality`. -/
theorem session_confidentiality_classical
    (h : HandshakeCheck) (acc : Accepted h)
    (c : UserDataCommit) (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey) (h_sk : keyOf sk = c.eciesPubkey)
    (msg : Plaintext) :
    decrypt sk (encrypt c.eciesPubkey msg) = some msg :=
  session_confidentiality h acc c h_commit sk h_sk msg

/-- **Win predicate**: hypotheses hold but the ECIES roundtrip fails. -/
def sessionConfWinPred
    (p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext) : Prop :=
  let (h, c, sk, msg) := p
  Accepted h ∧
  h.msgUserData = commitHash c ∧
  keyOf sk = c.eciesPubkey ∧
  ¬ decrypt sk (encrypt c.eciesPubkey msg) = some msg

/-- The win predicate is unconditionally false. Given `keyOf sk =
    c.eciesPubkey`, the ECIES roundtrip `decrypt sk (encrypt
    c.eciesPubkey msg) = some msg` holds (rewriting via `h_sk` and
    applying `roundtrip sk msg`). -/
theorem sessionConfWinPred_false
    (p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext)
    (hp : sessionConfWinPred p) : False := by
  obtain ⟨_, _, h_sk, h_neg⟩ := hp
  apply h_neg
  rw [← h_sk]
  exact roundtrip p.2.2.1 p.2.2.2

/-- **Content-bearing failure advantage** for the session-confidentiality
    game. Identically zero under the current spec abstraction. -/
noncomputable def confFailAdv
    (𝒜 : SessionConfidentialityAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ sessionConfWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- **Probabilistic form (Step 6.2 lift, Cycle-6.7-corrected)**:
    `session_confidentiality_negl`.

    Under the spec's deterministic-roundtrip abstraction, the failure
    advantage is identically zero, so negligibility is immediate.
    Compare cycle 6.6: in `handshake_binds_ecies_key_negl`, the P1
    (Groth16-soundness) failure mode survives the lift as a real
    probabilistic event; here, the only failure event captured by
    the classical spec is the (unconditionally-impossible) roundtrip
    failure. -/
theorem session_confidentiality_negl
    (𝒜 : SessionConfidentialityAdv) :
    negligible (confFailAdv 𝒜) := by
  -- `confFailAdv 𝒜 n ≤ Pr[ fun _ => False | simulateQ protocolSpecHonestSim (𝒜 n) ] = 0`
  have h_zero : ∀ n, confFailAdv 𝒜 n = 0 := by
    intro n
    refine le_antisymm ?_ (zero_le _)
    calc Pr[ sessionConfWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]
        ≤ Pr[ fun _ => False | simulateQ protocolSpecHonestSim (𝒜 n) ] := by
          exact probEvent_mono (fun p _ hp => sessionConfWinPred_false p hp)
      _ = 0 := probEvent_False _
  have h_fun_zero : confFailAdv 𝒜 = 0 := by
    funext n; exact h_zero n
  rw [h_fun_zero]
  exact negligible_zero

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

/-- **Security-game reduction form (unbounded-adversary statement)**
    for `session_confidentiality_negl`.

    **IsPPT placeholder gap (cycle 6.12 rename)**: with `IsPPT`
    currently `True`-placeholder, `secureAgainst IsPPT` ranges
    over all adversaries. The `_AGAINST_UNBOUNDED_ADVERSARIES`
    suffix surfaces this gap at the call site. See
    `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES`
    in `ProtocolVCVioDual.lean` for the full rationale.

    Note: the underlying `session_confidentiality_negl` is
    a *degenerate-zero* lift (advantage is identically zero),
    so the conclusion of this packaging is trivially stronger
    than even the PPT statement would be — see
    cycle-6.7's framing for that separate honesty point. -/
theorem sessionConfGame_secure_of_triple_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES
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

/-- **Cycle 6.14.c** parallel PPT-bounded packaging. -/
theorem sessionConfGame_secure_of_triple_bundle_secure_AGAINST_PPT_ADVERSARIES
    {confGame    : SecurityGame SessionConfidentialityAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    (reduce : SessionConfidentialityAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashCollisionAdv)
    (reduce_preserves_ppt : ∀ A, IsPPT_proper A →
      IsPPT_proper (reduce A).1 ∧ IsPPT_proper (reduce A).2.1 ∧
        IsPPT_proper (reduce A).2.2)
    (h_bound : ∀ A n,
      confGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashGame.advantage    (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT_proper)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT_proper)
    (h_hash_secure  : hashGame.secureAgainst IsPPT_proper) :
    confGame.secureAgainst IsPPT_proper := fun A hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (reduce_preserves_ppt A hA).1)
        (h_tdx_secure   (reduce A).2.1   (reduce_preserves_ppt A hA).2.1))
      (h_hash_secure  (reduce A).2.2     (reduce_preserves_ppt A hA).2.2))

/-! ## Triple-bundle lifted theorem 3: `session_confidentiality_via_extractor`

**Cycle 6.8 framing**: same degenerate-zero-advantage pattern as
cycle 6.7. The classical `session_confidentiality_via_extractor`
proof witnesses the conclusion's `∃ pk` with `pk := c.eciesPubkey`,
then discharges the two conjuncts via `pkOfUserData_commitHash` and
`session_confidentiality` (which transitively uses `roundtrip`).
Both conjuncts are unconditional theorems given the hypotheses, so
the failure event is unconditionally impossible.
-/

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

/-- **Win predicate**: hypotheses hold but no `pk` exists witnessing
    the `∃ pk, pkOfUserData = some pk ∧ decrypt = some msg`
    conclusion. -/
def sessionConfExtractorWinPred
    (p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext) : Prop :=
  let (h, c, sk, msg) := p
  Accepted h ∧
  h.msgUserData = commitHash c ∧
  keyOf sk = c.eciesPubkey ∧
  ¬ ∃ pk, pkOfUserData h.msgUserData = some pk ∧
          decrypt sk (encrypt pk msg) = some msg

/-- The win predicate is unconditionally false. Witness `pk :=
    c.eciesPubkey`; both conjuncts hold by `pkOfUserData_commitHash`
    (after rewriting via `h_commit`) and `roundtrip` (after rewriting
    via `h_sk`). -/
theorem sessionConfExtractorWinPred_false
    (p : HandshakeCheck × UserDataCommit × PrivKey × Plaintext)
    (hp : sessionConfExtractorWinPred p) : False := by
  obtain ⟨_, h_commit, h_sk, h_neg⟩ := hp
  apply h_neg
  refine ⟨p.2.1.eciesPubkey, ?_, ?_⟩
  · rw [h_commit]; exact pkOfUserData_commitHash p.2.1
  · rw [← h_sk]; exact roundtrip p.2.2.1 p.2.2.2

/-- **Content-bearing failure advantage**, identically zero. -/
noncomputable def extFailAdv
    (𝒜 : SessionConfidentialityExtractorAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ sessionConfExtractorWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- **Probabilistic form (Step 6.2 lift, Cycle-6.8-corrected)**:
    `session_confidentiality_via_extractor_negl`. Degenerate
    zero-advantage case, same as cycle 6.7. -/
theorem session_confidentiality_via_extractor_negl
    (𝒜 : SessionConfidentialityExtractorAdv) :
    negligible (extFailAdv 𝒜) := by
  have h_zero : ∀ n, extFailAdv 𝒜 n = 0 := by
    intro n
    refine le_antisymm ?_ (zero_le _)
    calc Pr[ sessionConfExtractorWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]
        ≤ Pr[ fun _ => False | simulateQ protocolSpecHonestSim (𝒜 n) ] := by
          exact probEvent_mono (fun p _ hp =>
            sessionConfExtractorWinPred_false p hp)
      _ = 0 := probEvent_False _
  have h_fun_zero : extFailAdv 𝒜 = 0 := by funext n; exact h_zero n
  rw [h_fun_zero]
  exact negligible_zero

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

/-- **Security-game reduction form (unbounded-adversary statement)**
    for `session_confidentiality_via_extractor_negl`.

    **IsPPT placeholder gap (cycle 6.12 rename)**: with `IsPPT`
    currently `True`-placeholder, `secureAgainst IsPPT` ranges
    over all adversaries. The `_AGAINST_UNBOUNDED_ADVERSARIES`
    suffix surfaces this gap at the call site. See
    `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES`
    in `ProtocolVCVioDual.lean` for the full rationale.

    Note: degenerate-zero lift (same as cycle 6.7); see
    cycle-6.8's framing for that separate honesty point. -/
theorem sessionConfExtractorGame_secure_of_triple_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES
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

/-- **Cycle 6.14.c** parallel PPT-bounded packaging. -/
theorem sessionConfExtractorGame_secure_of_triple_bundle_secure_AGAINST_PPT_ADVERSARIES
    {extGame     : SecurityGame SessionConfidentialityExtractorAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashGame    : SecurityGame CommitHashCollisionAdv}
    (reduce : SessionConfidentialityExtractorAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashCollisionAdv)
    (reduce_preserves_ppt : ∀ A, IsPPT_proper A →
      IsPPT_proper (reduce A).1 ∧ IsPPT_proper (reduce A).2.1 ∧
        IsPPT_proper (reduce A).2.2)
    (h_bound : ∀ A n,
      extGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashGame.advantage    (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT_proper)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT_proper)
    (h_hash_secure  : hashGame.secureAgainst IsPPT_proper) :
    extGame.secureAgainst IsPPT_proper := fun A hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (reduce_preserves_ppt A hA).1)
        (h_tdx_secure   (reduce A).2.1   (reduce_preserves_ppt A hA).2.1))
      (h_hash_secure  (reduce A).2.2     (reduce_preserves_ppt A hA).2.2))

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

/-! ### Cycle-6.9 framing

Single-bundle (Groth16-only) lift. The classical proof's two
conclusion parts:

  * **Part 1** (`∃ q signed ∧ mrEnclaveOf q = some h.expectedMr ∧
    userDataOf q = some (userDataOfTransferRequest req)`):
    failure event is a Groth16-soundness break (the same shape as
    `handshake_sound`'s, modulo the h_raw rewrite substituting
    `userDataOfTransferRequest req` for `h.msgUserData`).
  * **Part 2** (`conservationInvariant b'`): unconditional via
    `applyTransferRequest_preserves_conservation` (a derived
    theorem, no axiom).

Adversary output is `(HandshakeCheck × TransferRequest)` — the `b`,
`b'`, `hInv`, `hApp` of the classical theorem are universally
quantified inside the win predicate and elided from the win event
because Part 2 cannot fail. Reduction is identical in shape to
cycle 6.6's `reduce_binds_to_groth`. -/

/-- **Win predicate**: contract accepts and msgUserData binds to the
    transfer-request user_data, but no signed quote witnesses the
    binding. Part 2 (conservation) is omitted from the win event
    because it cannot fail. -/
def transfersConsWinPred
    (p : HandshakeCheck × TransferRequest) : Prop :=
  let (h, req) := p
  Accepted h ∧
  h.msgUserData = userDataOfTransferRequest req ∧
  ¬ ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q  = some (userDataOfTransferRequest req)

/-- **Reduction** to Groth16-soundness adversary by projecting
    `(h.proof, h.inputs)`. -/
def reduce_transfers_to_groth
    (𝒜 : TransfersConservationAdv) : Groth16SoundAdv :=
  fun n => do
    let p : HandshakeCheck × TransferRequest ← 𝒜 n
    pure (p.1.proof, p.1.inputs)

/-- **Cycle 6.14.b — `IsPPT_proper`-preservation under
    `reduce_transfers_to_groth`**. -/
theorem reduce_transfers_to_groth_preserves_IsPPT_proper
    (𝒜 : TransfersConservationAdv) (h : IsPPT_proper 𝒜) :
    IsPPT_proper (reduce_transfers_to_groth 𝒜) :=
  IsPPT_proper_of_bind_pure_comp 𝒜
    (fun p : HandshakeCheck × TransferRequest => (p.1.proof, p.1.inputs)) h

/-- **Content-bearing failure advantage**. -/
noncomputable def consFailAdv
    (𝒜 : TransfersConservationAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ transfersConsWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- Forward implication: a transfers-conservation win on `(h, req)`
    implies a Groth16-soundness win on the projected
    `(h.proof, h.inputs)`. -/
theorem transfersConsWinPred_imp_groth16SoundnessWinPred_projected
    (p : HandshakeCheck × TransferRequest)
    (hp : transfersConsWinPred p) :
    groth16SoundnessWinPred (p.1.proof, p.1.inputs) := by
  obtain ⟨⟨hZk, hMr, hUd⟩, h_raw, h_neg⟩ := hp
  refine ⟨hZk, ?_⟩
  intro h_signed
  apply h_neg
  refine ⟨inputs_to_quote p.1.inputs, h_signed, hMr, ?_⟩
  rw [hUd, h_raw]

/-- **Probabilistic form (Step 6.2 lift, Cycle-6.9-corrected)**:
    `cross_component_transfers_conservation_negl`. -/
theorem cross_component_transfers_conservation_negl
    (𝒜 : TransfersConservationAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_transfers_to_groth 𝒜))) :
    negligible (consFailAdv 𝒜) := by
  refine negligible_of_le ?_ h_groth_negl
  intro n
  show Pr[ transfersConsWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ] ≤
       Pr[ groth16SoundnessWinPred | simulateQ protocolSpecHonestSim (reduce_transfers_to_groth 𝒜 n) ]
  rw [show reduce_transfers_to_groth 𝒜 n
        = 𝒜 n >>= pure ∘
            (fun p : HandshakeCheck × TransferRequest =>
              (p.1.proof, p.1.inputs))
        from rfl]
  simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]
  exact probEvent_mono (fun p _ hp =>
    transfersConsWinPred_imp_groth16SoundnessWinPred_projected p hp)

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

/-- **Security-game reduction form (unbounded-adversary statement)**
    for `cross_component_transfers_conservation_negl`.

    **IsPPT placeholder gap (cycle 6.12 rename)**: with `IsPPT`
    currently `True`-placeholder, `secureAgainst IsPPT` ranges
    over all adversaries. The `_AGAINST_UNBOUNDED_ADVERSARIES`
    suffix surfaces this gap at the call site. See
    `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES`
    in `ProtocolVCVioDual.lean` for the full rationale. -/
theorem transfersConsGame_secure_of_triple_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES
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

/-- **Cycle 6.14.c** parallel PPT-bounded packaging. -/
theorem transfersConsGame_secure_of_triple_bundle_secure_AGAINST_PPT_ADVERSARIES
    {consGame    : SecurityGame TransfersConservationAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashBGame   : SecurityGame CommitHashBytesCollisionAdv}
    (reduce : TransfersConservationAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashBytesCollisionAdv)
    (reduce_preserves_ppt : ∀ A, IsPPT_proper A →
      IsPPT_proper (reduce A).1 ∧ IsPPT_proper (reduce A).2.1 ∧
        IsPPT_proper (reduce A).2.2)
    (h_bound : ∀ A n,
      consGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashBGame.advantage   (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT_proper)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT_proper)
    (h_hashB_secure : hashBGame.secureAgainst IsPPT_proper) :
    consGame.secureAgainst IsPPT_proper := fun A hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (reduce_preserves_ppt A hA).1)
        (h_tdx_secure   (reduce A).2.1   (reduce_preserves_ppt A hA).2.1))
      (h_hashB_secure  (reduce A).2.2     (reduce_preserves_ppt A hA).2.2))

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

/-! ### Cycle-6.10 framing

Single-bundle (Groth16-only). Conclusion parts:

  * Parts 1 & 2 (`winner = (resolveAuction round).winner`, `price =
    ...`): unconditional via `h_canon : claimed = resolveAuction round`
    (by congruence — derived facts, no axiom).
  * Part 3 (`∃ q signed ∧ ...`): Groth16-soundness failure mode.

Same shape as cycle 6.9. -/

/-- **Win predicate**: hypotheses hold but the conclusion fails. -/
def auctionDetermWinPred
    (p : HandshakeCheck × AuctionRound × ResolveMessage) : Prop :=
  let (h, round, claimed) := p
  Accepted h ∧
  h.msgUserData = userDataOfResolveMessage claimed ∧
  claimed.roundId = round.roundId ∧
  claimed = resolveAuction round ∧
  ¬ ( claimed.winner = (resolveAuction round).winner ∧
      claimed.price  = (resolveAuction round).price ∧
      ∃ q : TdxQuote,
        was_signed_by_dstack q ∧
        mrEnclaveOf q = some h.expectedMr ∧
        userDataOf q  = some (userDataOfResolveMessage claimed) )

/-- **Reduction** to Groth16-soundness adversary. -/
def reduce_auctionDeterm_to_groth
    (𝒜 : AuctionDeterminismAdv) : Groth16SoundAdv :=
  fun n => do
    let p : HandshakeCheck × AuctionRound × ResolveMessage ← 𝒜 n
    pure (p.1.proof, p.1.inputs)

/-- **Cycle 6.14.b — `IsPPT_proper`-preservation under
    `reduce_auctionDeterm_to_groth`**. -/
theorem reduce_auctionDeterm_to_groth_preserves_IsPPT_proper
    (𝒜 : AuctionDeterminismAdv) (h : IsPPT_proper 𝒜) :
    IsPPT_proper (reduce_auctionDeterm_to_groth 𝒜) :=
  IsPPT_proper_of_bind_pure_comp 𝒜
    (fun p : HandshakeCheck × AuctionRound × ResolveMessage =>
      (p.1.proof, p.1.inputs)) h

/-- **Content-bearing failure advantage**. -/
noncomputable def auctFailAdv
    (𝒜 : AuctionDeterminismAdv) (n : ℕ) : ℝ≥0∞ :=
  Pr[ auctionDetermWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ]

/-- Forward implication: hypotheses + ¬conclusion implies a
    Groth16-soundness break on the projected `(h.proof, h.inputs)`.
    Parts 1 & 2 of the conclusion are forced by `h_canon`; the only
    real failure mode is Part 3. -/
theorem auctionDetermWinPred_imp_groth16SoundnessWinPred_projected
    (p : HandshakeCheck × AuctionRound × ResolveMessage)
    (hp : auctionDetermWinPred p) :
    groth16SoundnessWinPred (p.1.proof, p.1.inputs) := by
  obtain ⟨⟨hZk, hMr, hUd⟩, h_raw, _, h_canon, h_neg⟩ := hp
  refine ⟨hZk, ?_⟩
  intro h_signed
  apply h_neg
  refine ⟨?_, ?_, ?_⟩
  · rw [h_canon]
  · rw [h_canon]
  · refine ⟨inputs_to_quote p.1.inputs, h_signed, hMr, ?_⟩
    rw [hUd, h_raw]

/-- **Probabilistic form (Step 6.2 lift, Cycle-6.10-corrected)**:
    `cross_component_auction_winner_determinism_negl`. -/
theorem cross_component_auction_winner_determinism_negl
    (𝒜 : AuctionDeterminismAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_auctionDeterm_to_groth 𝒜))) :
    negligible (auctFailAdv 𝒜) := by
  refine negligible_of_le ?_ h_groth_negl
  intro n
  show Pr[ auctionDetermWinPred | simulateQ protocolSpecHonestSim (𝒜 n) ] ≤
       Pr[ groth16SoundnessWinPred | simulateQ protocolSpecHonestSim (reduce_auctionDeterm_to_groth 𝒜 n) ]
  rw [show reduce_auctionDeterm_to_groth 𝒜 n
        = 𝒜 n >>= pure ∘
            (fun p : HandshakeCheck × AuctionRound × ResolveMessage =>
              (p.1.proof, p.1.inputs))
        from rfl]
  simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]
  exact probEvent_mono (fun p _ hp =>
    auctionDetermWinPred_imp_groth16SoundnessWinPred_projected p hp)

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

/-- **Security-game reduction form (unbounded-adversary statement)**
    for `cross_component_auction_winner_determinism_negl`.

    **IsPPT placeholder gap (cycle 6.12 rename)**: with `IsPPT`
    currently `True`-placeholder, `secureAgainst IsPPT` ranges
    over all adversaries. The `_AGAINST_UNBOUNDED_ADVERSARIES`
    suffix surfaces this gap at the call site. See
    `handshakeSoundnessGame_secure_of_dual_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES`
    in `ProtocolVCVioDual.lean` for the full rationale. -/
theorem auctionDetermGame_secure_of_triple_bundle_secure_AGAINST_UNBOUNDED_ADVERSARIES
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

/-- **Cycle 6.14.c** parallel PPT-bounded packaging. -/
theorem auctionDetermGame_secure_of_triple_bundle_secure_AGAINST_PPT_ADVERSARIES
    {auctGame    : SecurityGame AuctionDeterminismAdv}
    {groth16Game : SecurityGame Groth16SoundAdv}
    {tdxGame     : SecurityGame TdxVerifierSoundAdv}
    {hashBGame   : SecurityGame CommitHashBytesCollisionAdv}
    (reduce : AuctionDeterminismAdv →
      Groth16SoundAdv × TdxVerifierSoundAdv × CommitHashBytesCollisionAdv)
    (reduce_preserves_ppt : ∀ A, IsPPT_proper A →
      IsPPT_proper (reduce A).1 ∧ IsPPT_proper (reduce A).2.1 ∧
        IsPPT_proper (reduce A).2.2)
    (h_bound : ∀ A n,
      auctGame.advantage A n ≤
        groth16Game.advantage (reduce A).1 n +
        tdxGame.advantage     (reduce A).2.1 n +
        hashBGame.advantage   (reduce A).2.2 n)
    (h_groth_secure : groth16Game.secureAgainst IsPPT_proper)
    (h_tdx_secure   : tdxGame.secureAgainst IsPPT_proper)
    (h_hashB_secure : hashBGame.secureAgainst IsPPT_proper) :
    auctGame.secureAgainst IsPPT_proper := fun A hA =>
  negligible_of_le (h_bound A)
    (negligible_add
      (negligible_add
        (h_groth_secure (reduce A).1     (reduce_preserves_ppt A hA).1)
        (h_tdx_secure   (reduce A).2.1   (reduce_preserves_ppt A hA).2.1))
      (h_hashB_secure  (reduce A).2.2     (reduce_preserves_ppt A hA).2.2))

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
