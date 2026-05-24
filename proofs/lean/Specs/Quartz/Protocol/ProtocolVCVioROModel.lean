/-
Copyright (c) 2026 Quartz authors. All rights reserved.
Released under Apache 2.0 license.
-/

import VCVio.OracleComp.QueryTracking.RandomOracle
import VCVio.OracleComp.QueryTracking.LoggingOracle
import VCVio.OracleComp.QueryTracking.Birthday
import VCVio.OracleComp.Constructions.BitVec
import VCVio.CryptoFoundations.Asymptotics.Negligible
import VCVio.CryptoFoundations.Asymptotics.Security
import Specs.Quartz.Protocol.ProtocolVCVio
import Specs.Quartz.Protocol.ProtocolVCVioTriple
import Specs.Quartz.Protocol.ProtocolVCVioQuad
import Mathlib.Analysis.SpecificLimits.Normed

/-!
# Random-oracle model for commit-hash primitives (Cycle 6.22, consolidated post-d.3)

After cycle 6.22.d.3 (wholesale parameterisation of `UserData` and the
hash specs by the security parameter `n`), this module unifies the
prior cycle-6.22.a-c (fixed-size) and cycle-6.22.d.1/.2 (parameterised)
work into a single file. The cycle-6.22 hash carriers are now natively
indexed by `n`, so the "fixed-size" form is just the instantiation at
`n = 512` (the deployed dstack `report_data` width).

## What this module provides

* Typeclass instances on `CommitHashSpec n` / `CommitHashBytesSpec n`
  (`OracleSpec.{DecidableEq, Fintype, Inhabited}`, `Inhabited UserDataCommit`,
  `Inhabited ByteSeq`, `SampleableType (BitVec n)` lifts to the spec ranges).
* Log-collision birthday bound `commitHash_logCollision_birthday_bound`
  parametric in `n`: any `OracleComp (CommitHashSpec n) α` issuing at
  most `qb` queries has log-collision probability `≤ qb²/(2·2^n)`.
* Parallel byte-domain bound `commitHashBytes_logCollision_birthday_bound`.
* RO-shape adversary types `CommitHashCollisionAdvRO` /
  `CommitHashBytesCollisionAdvRO`: families of oracle computations
  indexed by the security parameter.
* RO advantages `commitHashCollisionAdvRO` / `commitHashBytesCollisionAdvRO`:
  the probability the loggingOracle trace contains a log collision.
* Bound theorems `*CollisionAdvRO_le_birthday_bound`.
* Asymptotic negligibility infrastructure: `negligible_inv_two_pow`
  (lifted from Mathlib's `tendsto_pow_const_div_const_pow_of_one_lt`)
  and `*CollisionAdvRO_negligible_of_constant_qb`.
* Four RO-form packagings that *can* discharge collision-resistance
  internally via the cycle-6.22 birthday bound — when invoked with a
  real query-bounded `CommitHashCollisionAdvRO` adversary. The packaging
  signature requires the caller to supply the adversary and the query
  budget; negligibility comes from the proven birthday bound.
* Four connection theorems (`*_secure_via_RO_packaging`) demonstrating
  *type-shape compatibility* between the existing protocol-layer lifts
  and the new RO packagings. The connection theorems supply a trivial
  zero-query hash adversary (`qb := 0`) and zero-advantage TDX /
  circuit-equivalence experiments, so the RO machinery does not exercise
  the birthday bound on real adversaries — they are documentation-grade
  demonstrations that the type shapes align, not substantive cryptographic
  reductions. See the connection-theorem docstrings for the precise
  framing.

  **Cycle 6.22.d.4 adversarial-review caveat (findings #4/#5/#17/#22/#26)**:
  the protocol-layer lifts (`bindsFailAdv`, `confFailAdv`, etc.) evaluate
  the adversary under `simulateQ (protocolSpecHonestSim n)` (axiomatic
  deterministic `commitHash`), while the RO packagings evaluate
  `CommitHashCollisionAdvRO` adversaries under `simulateQ loggingOracle`
  (uniformly-sampled fresh values per query). These are *different*
  probability spaces; the connection theorems do not transport bounds
  from one to the other. Genuine wiring between the lift and RO bounds
  requires either (a) unifying the simulators (rewrite lifts to use
  `randomOracle`), or (b) a separate reduction lemma. Neither is in this
  module.
-/

namespace Specs.Quartz.Protocol.ProtocolVCVioROModel

open ENNReal
open Filter Topology
open OracleSpec OracleComp
open Specs.Quartz.Crypto
open Specs.Quartz.Crypto.UserDataCommitVCVio
open Specs.Quartz.Crypto.RawMessagesVCVio
open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Protocol.Handshake
open Specs.Quartz.Protocol.ProtocolVCVio
open Specs.Quartz.Protocol.ProtocolVCVioTriple
open Specs.Quartz.Protocol.ProtocolVCVioQuad

/-! ## Index-side instances (Inhabited / DecidableEq on the spec domains) -/

instance instInhabitedUserDataCommit : Inhabited UserDataCommit where
  default := { domainSep := [], eciesPubkey := 0, contractAddr := "", nonce := 0 }

instance instInhabitedByteSeqRO : Inhabited ByteSeq where
  default := []

noncomputable instance instDecidableEqUserDataCommitRO :
    DecidableEq UserDataCommit := Classical.decEq _

noncomputable instance instDecidableEqByteSeqRO :
    DecidableEq ByteSeq := Classical.decEq _

/-! ## Spec-level instances parametric in the security parameter -/

noncomputable instance instCommitHashSpecDecidableEq (n : Nat) :
    (CommitHashSpec n).DecidableEq where
  decidableEq_A := instDecidableEqUserDataCommitRO
  decidableEq_B _ := inferInstanceAs (DecidableEq (BitVec n))

instance instCommitHashSpecFintype (n : Nat) : (CommitHashSpec n).Fintype where
  fintype_B _ := inferInstanceAs (Fintype (BitVec n))

instance instCommitHashSpecInhabited (n : Nat) : (CommitHashSpec n).Inhabited where
  inhabited_B _ := inferInstanceAs (Inhabited (BitVec n))

instance instSampleableTypeCommitHashRange (n : Nat) :
    ∀ t : (CommitHashSpec n).Domain, SampleableType ((CommitHashSpec n).Range t) :=
  fun _ => inferInstanceAs (SampleableType (BitVec n))

noncomputable instance instCommitHashBytesSpecDecidableEq (n : Nat) :
    (CommitHashBytesSpec n).DecidableEq where
  decidableEq_A := instDecidableEqByteSeqRO
  decidableEq_B _ := inferInstanceAs (DecidableEq (BitVec n))

instance instCommitHashBytesSpecFintype (n : Nat) : (CommitHashBytesSpec n).Fintype where
  fintype_B _ := inferInstanceAs (Fintype (BitVec n))

instance instCommitHashBytesSpecInhabited (n : Nat) : (CommitHashBytesSpec n).Inhabited where
  inhabited_B _ := inferInstanceAs (Inhabited (BitVec n))

instance instSampleableTypeCommitHashBytesRange (n : Nat) :
    ∀ t : (CommitHashBytesSpec n).Domain, SampleableType ((CommitHashBytesSpec n).Range t) :=
  fun _ => inferInstanceAs (SampleableType (BitVec n))

/-! ## Random-oracle simulators -/

noncomputable def commitHashROSim (n : Nat) :
    QueryImpl (CommitHashSpec n) (StateT (CommitHashSpec n).QueryCache ProbComp) :=
  randomOracle

noncomputable def commitHashBytesROSim (n : Nat) :
    QueryImpl (CommitHashBytesSpec n) (StateT (CommitHashBytesSpec n).QueryCache ProbComp) :=
  randomOracle

/-! ## Log-collision birthday bound -/

/-- **Birthday bound for `CommitHashSpec n` log-collisions**: for any
    `OracleComp (CommitHashSpec n) α` issuing at most `qb` queries, the
    probability that the `loggingOracle` trace contains two distinct
    queries with equal outputs is at most `qb²/(2·2^n)`.

    Direct instantiation of VCV-io's
    `probEvent_logCollision_le_birthday_total` at
    `|Range| = |BitVec n| = 2^n`. -/
theorem commitHash_logCollision_birthday_bound {α : Type} (n : Nat)
    (oa : OracleComp (CommitHashSpec n) α)
    (qb : ℕ) (hbound : IsTotalQueryBound oa qb) :
    Pr[fun z => LogHasCollision z.2 |
        (simulateQ loggingOracle oa).run] ≤
      (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ n) := by
  have hcard : Fintype.card ((CommitHashSpec n).Range default) = 2 ^ n :=
    card_bitVec n
  have hC_pos : 0 < Fintype.card ((CommitHashSpec n).Range default) := by
    rw [hcard]; exact Nat.pos_of_ne_zero (Nat.pos_iff_ne_zero.mp (Nat.two_pow_pos n))
  have hrange : ∀ t, Fintype.card ((CommitHashSpec n).Range default) ≤
      Fintype.card ((CommitHashSpec n).Range t) := fun _ => le_refl _
  have h := probEvent_logCollision_le_birthday_total oa qb hbound hC_pos hrange
  refine h.trans (le_of_eq ?_)
  rw [hcard]; push_cast; rfl

/-- Byte-domain analogue of `commitHash_logCollision_birthday_bound`. -/
theorem commitHashBytes_logCollision_birthday_bound {α : Type} (n : Nat)
    (oa : OracleComp (CommitHashBytesSpec n) α)
    (qb : ℕ) (hbound : IsTotalQueryBound oa qb) :
    Pr[fun z => LogHasCollision z.2 |
        (simulateQ loggingOracle oa).run] ≤
      (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ n) := by
  have hcard : Fintype.card ((CommitHashBytesSpec n).Range default) = 2 ^ n :=
    card_bitVec n
  have hC_pos : 0 < Fintype.card ((CommitHashBytesSpec n).Range default) := by
    rw [hcard]; exact Nat.pos_of_ne_zero (Nat.pos_iff_ne_zero.mp (Nat.two_pow_pos n))
  have hrange : ∀ t, Fintype.card ((CommitHashBytesSpec n).Range default) ≤
      Fintype.card ((CommitHashBytesSpec n).Range t) := fun _ => le_refl _
  have h := probEvent_logCollision_le_birthday_total oa qb hbound hC_pos hrange
  refine h.trans (le_of_eq ?_)
  rw [hcard]; push_cast; rfl

/-! ## RO-shape collision-finder adversaries and advantages -/

/-- A security-parameter-indexed RO-shape commit-hash collision-finder
    adversary: an oracle computation over `CommitHashSpec n`. -/
def CommitHashCollisionAdvRO : Type :=
  (n : Nat) → OracleComp (CommitHashSpec n) Unit

/-- The RO-shape advantage of a `commitHash` collision-finder: the
    probability that the `loggingOracle` trace contains two distinct
    queries with equal outputs. -/
noncomputable def commitHashCollisionAdvRO
    (𝒜 : CommitHashCollisionAdvRO) (n : Nat) : ℝ≥0∞ :=
  Pr[fun z => LogHasCollision z.2 |
      (simulateQ loggingOracle (𝒜 n)).run]

/-- **Birthday bound on the RO-shape commit-hash collision advantage**.
    Direct consequence of `commitHash_logCollision_birthday_bound`. -/
theorem commitHashCollisionAdvRO_le_birthday_bound
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) (n : Nat) :
    commitHashCollisionAdvRO 𝒜 n ≤ (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ n) :=
  commitHash_logCollision_birthday_bound n (𝒜 n) qb (hbound n)

/-- A security-parameter-indexed RO-shape commit-hash-bytes
    collision-finder adversary. -/
def CommitHashBytesCollisionAdvRO : Type :=
  (n : Nat) → OracleComp (CommitHashBytesSpec n) Unit

/-- The RO-shape advantage of a `commitHashBytes` collision-finder. -/
noncomputable def commitHashBytesCollisionAdvRO
    (𝒜 : CommitHashBytesCollisionAdvRO) (n : Nat) : ℝ≥0∞ :=
  Pr[fun z => LogHasCollision z.2 |
      (simulateQ loggingOracle (𝒜 n)).run]

/-- Byte-domain analogue of `commitHashCollisionAdvRO_le_birthday_bound`. -/
theorem commitHashBytesCollisionAdvRO_le_birthday_bound
    (𝒜 : CommitHashBytesCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) (n : Nat) :
    commitHashBytesCollisionAdvRO 𝒜 n ≤ (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ n) :=
  commitHashBytes_logCollision_birthday_bound n (𝒜 n) qb (hbound n)

/-! ## Asymptotic negligibility -/

/-- **Auxiliary**: `n^k / 2^n → 0` in ℝ≥0∞. Lifted from Mathlib's
    ℝ-valued `tendsto_pow_const_div_const_pow_of_one_lt`. -/
private lemma tendsto_pow_div_two_pow_atTop_zero (k : ℕ) :
    Tendsto (fun n : ℕ => (n : ℝ≥0∞) ^ k * ((2 : ℝ≥0∞) ^ n)⁻¹)
      atTop (nhds 0) := by
  have hR : Tendsto (fun n : ℕ => ((n : ℝ) ^ k / (2 : ℝ) ^ n)) atTop (nhds 0) :=
    tendsto_pow_const_div_const_pow_of_one_lt k (by norm_num)
  have h := (ENNReal.continuous_ofReal.tendsto 0).comp hR
  simp at h
  refine h.congr' ?_
  filter_upwards with n
  simp only [Function.comp_apply]
  rw [ENNReal.ofReal_div_of_pos (by positivity)]
  rw [ENNReal.ofReal_pow (by positivity)]
  rw [ENNReal.ofReal_pow (by positivity)]
  rw [show ENNReal.ofReal (2 : ℝ) = (2 : ℝ≥0∞) from by
    rw [show (2 : ℝ) = ((2 : ℕ) : ℝ) by norm_num]
    rw [ENNReal.ofReal_natCast]; rfl]
  rw [show ENNReal.ofReal (n : ℝ) = (n : ℝ≥0∞) from ENNReal.ofReal_natCast n]
  rw [ENNReal.div_eq_inv_mul, mul_comm]

/-- **Negligibility of `1/2^n`**: a foundational lemma the project
    didn't previously have. Used to discharge the birthday-bound
    asymptotic for the parameterised RO advantage. -/
theorem negligible_inv_two_pow :
    negligible (fun n : ℕ => ((2 : ℝ≥0∞) ^ n)⁻¹) := by
  intro k
  exact tendsto_pow_div_two_pow_atTop_zero k

/-- **The cryptographically meaningful statement**: for any constant
    query budget `qb`, the RO advantage is negligible in the security
    parameter. -/
theorem commitHashCollisionAdvRO_negligible_of_constant_qb
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) :
    negligible (commitHashCollisionAdvRO 𝒜) := by
  refine negligible_of_le
    (fun n => commitHashCollisionAdvRO_le_birthday_bound 𝒜 qb hbound n) ?_
  refine negligible_of_le
    (g := fun n => ((qb : ℝ≥0∞) ^ 2 / 2) * ((2 : ℝ≥0∞) ^ n)⁻¹) ?_ ?_
  · intro n
    have hinv : ((2 : ℝ≥0∞) * 2 ^ n)⁻¹ = (2 : ℝ≥0∞)⁻¹ * (2 ^ n)⁻¹ := by
      apply ENNReal.mul_inv (Or.inl (by norm_num))
      exact Or.inl (by norm_num)
    rw [div_eq_mul_inv, div_eq_mul_inv, hinv, ← mul_assoc]
  · apply negligible_const_mul negligible_inv_two_pow
    apply ENNReal.div_ne_top
    · exact ENNReal.pow_ne_top (ENNReal.natCast_ne_top qb)
    · norm_num

/-- Byte-domain analogue of
    `commitHashCollisionAdvRO_negligible_of_constant_qb`. -/
theorem commitHashBytesCollisionAdvRO_negligible_of_constant_qb
    (𝒜 : CommitHashBytesCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) :
    negligible (commitHashBytesCollisionAdvRO 𝒜) := by
  refine negligible_of_le
    (fun n => commitHashBytesCollisionAdvRO_le_birthday_bound 𝒜 qb hbound n) ?_
  refine negligible_of_le
    (g := fun n => ((qb : ℝ≥0∞) ^ 2 / 2) * ((2 : ℝ≥0∞) ^ n)⁻¹) ?_ ?_
  · intro n
    have hinv : ((2 : ℝ≥0∞) * 2 ^ n)⁻¹ = (2 : ℝ≥0∞)⁻¹ * (2 ^ n)⁻¹ := by
      apply ENNReal.mul_inv (Or.inl (by norm_num))
      exact Or.inl (by norm_num)
    rw [div_eq_mul_inv, div_eq_mul_inv, hinv, ← mul_assoc]
  · apply negligible_const_mul negligible_inv_two_pow
    apply ENNReal.div_ne_top
    · exact ENNReal.pow_ne_top (ENNReal.natCast_ne_top qb)
    · norm_num

/-! ## RO-form packagings discharging collision-resistance internally

These are the first packagings in the project that derive
collision-resistance from the cycle-6.22 birthday bound rather than
assuming it via an external `h_hash_secure` hypothesis. -/

theorem handshakeBindsFail_secure_of_triple_bundle_secure_RO
    (bindsFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound_𝒜 : ∀ n, IsTotalQueryBound (𝒜 n) qb)
    (h_bound : ∀ n,
      bindsFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n +
        commitHashCollisionAdvRO 𝒜 n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure) :
    bindsFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    bindsFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n +
      commitHashCollisionAdvRO 𝒜 n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      (commitHashCollisionAdvRO_negligible_of_constant_qb 𝒜 qb hbound_𝒜))
    h_bound

theorem sessionConfFail_secure_of_triple_bundle_secure_RO
    (confFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound_𝒜 : ∀ n, IsTotalQueryBound (𝒜 n) qb)
    (h_bound : ∀ n,
      confFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n +
        commitHashCollisionAdvRO 𝒜 n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure) :
    confFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    confFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n +
      commitHashCollisionAdvRO 𝒜 n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      (commitHashCollisionAdvRO_negligible_of_constant_qb 𝒜 qb hbound_𝒜))
    h_bound

theorem sessionConfExtractor_secure_of_triple_bundle_secure_RO
    (extractorFailExp : SecurityExp)
    (groth16Exp : SecurityExp)
    (tdxExp : SecurityExp)
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound_𝒜 : ∀ n, IsTotalQueryBound (𝒜 n) qb)
    (h_bound : ∀ n,
      extractorFailExp.advantage n ≤
        groth16Exp.advantage n + tdxExp.advantage n +
        commitHashCollisionAdvRO 𝒜 n)
    (h_groth_secure : groth16Exp.secure)
    (h_tdx_secure   : tdxExp.secure) :
    extractorFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    extractorFailExp
    (fun n =>
      groth16Exp.advantage n + tdxExp.advantage n +
      commitHashCollisionAdvRO 𝒜 n)
    (negligible_add
      (negligible_add h_groth_secure h_tdx_secure)
      (commitHashCollisionAdvRO_negligible_of_constant_qb 𝒜 qb hbound_𝒜))
    h_bound

theorem crossSessionBindFail_secure_of_quad_bundle_secure_RO
    (bindFailExp : SecurityExp)
    (groth16KSExp : SecurityExp)
    (circuitEqExp : SecurityExp)
    (tdxExp : SecurityExp)
    (𝒜h : CommitHashCollisionAdvRO) (qbh : ℕ)
    (hbound_𝒜h : ∀ n, IsTotalQueryBound (𝒜h n) qbh)
    (𝒜hB : CommitHashBytesCollisionAdvRO) (qbhB : ℕ)
    (hbound_𝒜hB : ∀ n, IsTotalQueryBound (𝒜hB n) qbhB)
    (h_bound : ∀ n,
      bindFailExp.advantage n ≤
        groth16KSExp.advantage n + circuitEqExp.advantage n +
        tdxExp.advantage n +
        commitHashCollisionAdvRO 𝒜h n +
        commitHashBytesCollisionAdvRO 𝒜hB n)
    (h_groth_ks_secure : groth16KSExp.secure)
    (h_circuit_secure  : circuitEqExp.secure)
    (h_tdx_secure      : tdxExp.secure) :
    bindFailExp.secure :=
  SecurityExp.secure_of_pointwise_bound
    bindFailExp
    (fun n =>
      groth16KSExp.advantage n + circuitEqExp.advantage n +
      tdxExp.advantage n +
      commitHashCollisionAdvRO 𝒜h n +
      commitHashBytesCollisionAdvRO 𝒜hB n)
    (negligible_add
      (negligible_add
        (negligible_add
          (negligible_add h_groth_ks_secure h_circuit_secure)
          h_tdx_secure)
        (commitHashCollisionAdvRO_negligible_of_constant_qb 𝒜h qbh hbound_𝒜h))
      (commitHashBytesCollisionAdvRO_negligible_of_constant_qb 𝒜hB qbhB hbound_𝒜hB))
    h_bound

/-! ## Connection theorems — type-shape compatibility demonstrations

These four theorems re-derive each lift's conclusion through the
corresponding RO-form packaging by supplying *trivial* hash adversaries
(`qb := 0`, advantage identically 0) and zero-advantage TDX /
circuit-equivalence experiments. They demonstrate that the type shape
of the existing lift's conclusion fits the RO packaging's hypothesis
schema, but they do **not** exercise the cycle-6.22 birthday bound
on any real adversary, and they do **not** transport bounds between
the lift's probability space (`simulateQ (protocolSpecHonestSim n)`,
deterministic `commitHash`) and the RO packaging's probability space
(`simulateQ loggingOracle`, fresh uniform samples). The two semantic
spaces are incompatible without a separate reduction lemma; the
connection theorems are documentation-grade, not load-bearing
cryptographic content.

Cycle 6.22.d.4 adversarial review findings #4/#5/#17/#22/#26 are the
basis for this honest framing — see the module-level docstring above. -/

/-- Re-derive `handshake_binds_ecies_key_negl`'s conclusion through the
    RO-form triple-bundle packaging. -/
theorem handshakeBindsFail_secure_via_RO_packaging
    (𝒜 : HandshakeBindsAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_binds_to_groth 𝒜))) :
    ({ advantage := bindsFailAdv 𝒜 } : SecurityExp).secure := by
  let 𝒜hash : CommitHashCollisionAdvRO := fun _ => return ()
  have hbound_𝒜hash : ∀ n, IsTotalQueryBound (𝒜hash n) 0 := fun _ => trivial
  apply handshakeBindsFail_secure_of_triple_bundle_secure_RO
    (bindsFailExp := { advantage := bindsFailAdv 𝒜 })
    (groth16Exp := { advantage := groth16SoundnessAdv (reduce_binds_to_groth 𝒜) })
    (tdxExp := { advantage := fun _ => 0 })
    (𝒜 := 𝒜hash) (qb := 0)
    (hbound_𝒜 := hbound_𝒜hash)
  · intro n
    have hp : bindsFailAdv 𝒜 n ≤
        groth16SoundnessAdv (reduce_binds_to_groth 𝒜) n := by
      show Pr[ handshakeBindsWinPred | simulateQ (protocolSpecHonestSim n) (𝒜 n) ] ≤
           Pr[ groth16SoundnessWinPred | simulateQ (protocolSpecHonestSim n)
                  (reduce_binds_to_groth 𝒜 n) ]
      rw [show reduce_binds_to_groth 𝒜 n
            = 𝒜 n >>= pure ∘
                (fun p : HandshakeCheck n × UserDataCommit × PrivKey × Plaintext =>
                  (p.1.proof, p.1.inputs))
            from rfl]
      simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]
      exact probEvent_mono (fun p _ hp =>
        handshakeBindsWinPred_imp_groth16SoundnessWinPred_projected p hp)
    calc bindsFailAdv 𝒜 n
        ≤ groth16SoundnessAdv (reduce_binds_to_groth 𝒜) n := hp
      _ = groth16SoundnessAdv (reduce_binds_to_groth 𝒜) n + 0 + 0 := by ring
      _ ≤ groth16SoundnessAdv (reduce_binds_to_groth 𝒜) n + 0 +
            commitHashCollisionAdvRO 𝒜hash n := by
          exact add_le_add le_rfl (zero_le _)
  · exact h_groth_negl
  · exact negligible_of_zero (fun _ => rfl)

theorem sessionConfFail_secure_via_RO_packaging
    (𝒜 : SessionConfidentialityAdv) :
    ({ advantage := confFailAdv 𝒜 } : SecurityExp).secure := by
  let 𝒜hash : CommitHashCollisionAdvRO := fun _ => return ()
  have hbound_𝒜hash : ∀ n, IsTotalQueryBound (𝒜hash n) 0 := fun _ => trivial
  apply sessionConfFail_secure_of_triple_bundle_secure_RO
    (confFailExp := { advantage := confFailAdv 𝒜 })
    (groth16Exp := { advantage := fun _ => 0 })
    (tdxExp := { advantage := fun _ => 0 })
    (𝒜 := 𝒜hash) (qb := 0)
    (hbound_𝒜 := hbound_𝒜hash)
  · intro n
    have hzero : confFailAdv 𝒜 n = 0 := by
      have : confFailAdv 𝒜 = 0 := by
        funext m
        refine le_antisymm ?_ (zero_le _)
        calc Pr[ sessionConfWinPred | simulateQ (protocolSpecHonestSim m) (𝒜 m) ]
            ≤ Pr[ fun _ => False | simulateQ (protocolSpecHonestSim m) (𝒜 m) ] := by
              exact probEvent_mono (fun p _ hp => sessionConfWinPred_false p hp)
          _ = 0 := probEvent_False _
      exact congr_fun this n
    show confFailAdv 𝒜 n ≤ 0 + 0 + commitHashCollisionAdvRO 𝒜hash n
    rw [hzero]; exact zero_le _
  · exact negligible_of_zero (fun _ => rfl)
  · exact negligible_of_zero (fun _ => rfl)

theorem sessionConfExtractor_secure_via_RO_packaging
    (𝒜 : SessionConfidentialityExtractorAdv) :
    ({ advantage := extFailAdv 𝒜 } : SecurityExp).secure := by
  let 𝒜hash : CommitHashCollisionAdvRO := fun _ => return ()
  have hbound_𝒜hash : ∀ n, IsTotalQueryBound (𝒜hash n) 0 := fun _ => trivial
  apply sessionConfExtractor_secure_of_triple_bundle_secure_RO
    (extractorFailExp := { advantage := extFailAdv 𝒜 })
    (groth16Exp := { advantage := fun _ => 0 })
    (tdxExp := { advantage := fun _ => 0 })
    (𝒜 := 𝒜hash) (qb := 0)
    (hbound_𝒜 := hbound_𝒜hash)
  · intro n
    have hzero : extFailAdv 𝒜 n = 0 := by
      have : extFailAdv 𝒜 = 0 := by
        funext m
        refine le_antisymm ?_ (zero_le _)
        calc Pr[ sessionConfExtractorWinPred | simulateQ (protocolSpecHonestSim m) (𝒜 m) ]
            ≤ Pr[ fun _ => False | simulateQ (protocolSpecHonestSim m) (𝒜 m) ] := by
              exact probEvent_mono (fun p _ hp =>
                sessionConfExtractorWinPred_false p hp)
          _ = 0 := probEvent_False _
      exact congr_fun this n
    show extFailAdv 𝒜 n ≤ 0 + 0 + commitHashCollisionAdvRO 𝒜hash n
    rw [hzero]; exact zero_le _
  · exact negligible_of_zero (fun _ => rfl)
  · exact negligible_of_zero (fun _ => rfl)

theorem crossSessionBindFail_secure_via_RO_packaging
    (𝒜 : CrossSessionBindAdv)
    (h_groth_negl :
      negligible (groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜))) :
    ({ advantage := bindFailAdv 𝒜 } : SecurityExp).secure := by
  let 𝒜h  : CommitHashCollisionAdvRO      := fun _ => return ()
  let 𝒜hB : CommitHashBytesCollisionAdvRO := fun _ => return ()
  have hbound_𝒜h  : ∀ n, IsTotalQueryBound (𝒜h n)  0 := fun _ => trivial
  have hbound_𝒜hB : ∀ n, IsTotalQueryBound (𝒜hB n) 0 := fun _ => trivial
  apply crossSessionBindFail_secure_of_quad_bundle_secure_RO
    (bindFailExp := { advantage := bindFailAdv 𝒜 })
    (groth16KSExp := { advantage := groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜) })
    (circuitEqExp := { advantage := fun _ => 0 })
    (tdxExp := { advantage := fun _ => 0 })
    (𝒜h := 𝒜h) (qbh := 0)
    (hbound_𝒜h := hbound_𝒜h)
    (𝒜hB := 𝒜hB) (qbhB := 0)
    (hbound_𝒜hB := hbound_𝒜hB)
  · intro n
    have hp : bindFailAdv 𝒜 n ≤
        groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜) n := by
      show Pr[ crossSessionBindWinPred | simulateQ (protocolSpecHonestSim n) (𝒜 n) ] ≤
           Pr[ groth16SoundnessWinPred | simulateQ (protocolSpecHonestSim n)
                  (reduce_crossSessionBind_to_groth 𝒜 n) ]
      rw [show reduce_crossSessionBind_to_groth 𝒜 n
            = 𝒜 n >>= pure ∘
                (fun p : HandshakeCheck n × RawSessionSetPubKey × PrivKey × Plaintext =>
                  (p.1.proof, p.1.inputs))
            from rfl]
      simp only [← map_eq_bind_pure_comp, simulateQ_map, probEvent_map]
      exact probEvent_mono (fun p _ hp =>
        crossSessionBindWinPred_imp_groth16SoundnessWinPred_projected p hp)
    calc bindFailAdv 𝒜 n
        ≤ groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜) n := hp
      _ = groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜) n + 0 + 0 + 0 + 0 := by ring
      _ ≤ groth16SoundnessAdv (reduce_crossSessionBind_to_groth 𝒜) n + 0 + 0 +
            commitHashCollisionAdvRO 𝒜h n +
            commitHashBytesCollisionAdvRO 𝒜hB n := by
          gcongr <;> exact zero_le _
  · exact h_groth_negl
  · exact negligible_of_zero (fun _ => rfl)
  · exact negligible_of_zero (fun _ => rfl)

/-! ## Deployment-size concrete corollaries

The deployed dstack TDX quote has a 64-byte (512-bit) `report_data`
field, so the production-side instantiation is `n = 512`. The
parameterised bound `qb²/(2·2^n)` evaluates at `n = 512` to
`qb²/(2·2^512)` — concrete numbers for any deployment-side audit.

These corollaries make the deployment-size bound directly callable
without re-derivation. They are the cycle-6.22-final form of what was
the cycle-6.22.b standalone bound (now subsumed by the parameterised
version with explicit `n = 512` instantiation). -/

/-- **Deployment-size birthday bound**: at the deployed `n = 512`
    (dstack TDX `report_data` width), the commit-hash log-collision
    probability is at most `qb²/(2·2^512)`. -/
theorem commitHash_logCollision_birthday_bound_deployed
    {α : Type} (oa : OracleComp (CommitHashSpec 512) α)
    (qb : ℕ) (hbound : IsTotalQueryBound oa qb) :
    Pr[fun z => LogHasCollision z.2 |
        (simulateQ loggingOracle oa).run] ≤
      (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) :=
  commitHash_logCollision_birthday_bound 512 oa qb hbound

/-- Byte-domain analogue at `n = 512`. -/
theorem commitHashBytes_logCollision_birthday_bound_deployed
    {α : Type} (oa : OracleComp (CommitHashBytesSpec 512) α)
    (qb : ℕ) (hbound : IsTotalQueryBound oa qb) :
    Pr[fun z => LogHasCollision z.2 |
        (simulateQ loggingOracle oa).run] ≤
      (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) :=
  commitHashBytes_logCollision_birthday_bound 512 oa qb hbound

/-- **Deployment-size bound at `n = 512`**: parametric inequality
    `commitHashCollisionAdvRO 𝒜 512 ≤ qb²/(2·2^512)` for any
    commit-hash collision-finder with query budget `qb`. Direct
    instantiation of the parameterised bound at the deployed width.

    **No claim about negligibility envelope is made here**: the bound
    is informative only when `qb² ≪ 2^512` (i.e. `qb ≪ 2^256`). At
    `qb ≥ 2^256` the RHS exceeds 1 and the bound is vacuous. Deployment-
    side audits must supply a concrete `qb` budget (derived from the
    adversary's runtime envelope on the dstack TEE) to interpret the
    bound numerically.

    Cycle 6.22.d.4 adversarial-review finding #9: the previous docstring
    asserted "well within the negligibility envelope under any standard
    security definition" without a `qb` bound. Retracted. -/
theorem commitHashCollisionAdvRO_deployed_bound
    (𝒜 : CommitHashCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) :
    commitHashCollisionAdvRO 𝒜 512 ≤ (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) :=
  commitHashCollisionAdvRO_le_birthday_bound 𝒜 qb hbound 512

/-- Byte-domain analogue at `n = 512`. -/
theorem commitHashBytesCollisionAdvRO_deployed_bound
    (𝒜 : CommitHashBytesCollisionAdvRO) (qb : ℕ)
    (hbound : ∀ n, IsTotalQueryBound (𝒜 n) qb) :
    commitHashBytesCollisionAdvRO 𝒜 512 ≤ (qb ^ 2 : ℝ≥0∞) / (2 * 2 ^ 512) :=
  commitHashBytesCollisionAdvRO_le_birthday_bound 𝒜 qb hbound 512

end Specs.Quartz.Protocol.ProtocolVCVioROModel
