# Refactor plan: Quartz Lean crypto axioms → VCVio oracle models

- Drafted: 2026-05-13
- Author context: this document is the orchestrator's plan, not the work itself
- Trigger: VCV-io (Tuma et al., [eprint 2026/899](https://eprint.iacr.org/2026/899)) provides a foundational Lean 4 framework that can mechanically discharge the bulk of Quartz's current cryptographic-trust-boundary axioms

## Status quo

Per the [integration ledger](./ledger.md), the Lean tree at `proofs/lean/` contains **16 theorems** proven on top of **40 axioms**. The crypto + attestation axioms (33 of 40) are uninterpreted stubs that the protocol-layer theorems ride on:

| Module | Axioms | Theorems |
|---|---|---|
| `Specs/Quartz/Crypto/Ecies.lean` | 8 | 2 |
| `Specs/Quartz/Crypto/UserDataCommit.lean` | 5 | 1 |
| `Specs/Quartz/Crypto/RawMessages.lean` | 12 | 6 |
| `Specs/Quartz/Attestation/Dstack.lean` | 8 | 1 |
| `Specs/Quartz/Attestation/Zkdcap.lean` | 7 | 1 |
| `Specs/Quartz/Protocol/*.lean` | **0** | 5 |

The protocol layer is structurally clean (0 axioms, 5 theorems including the load-bearing `cross_component_session_bind`). The trust boundary is the crypto + attestation axioms. **Reducing that axiom set is the highest-leverage move available for tightening the methodology's verified surface.**

## Why VCV-io

VCV-io's `OracleComp` framework models cryptographic primitives as **queries against oracle specifications**, not as uninterpreted functions. Concretely:

- An axiomatic `encrypt : PubKey → Plaintext → Ciphertext` becomes a `query` against an encryption oracle whose semantics are made explicit by a handler.
- The axiom `roundtrip : decrypt sk (encrypt (keyOf sk) pt) = some pt` becomes a *theorem* about the joint distribution `OracleComp.simulate` produces — provable from the handler's definition, not asserted on faith.
- Adversarial / reduction proofs (e.g. `verifyTdxQuote_sound`) get the right shape: a reduction from breaking the protocol to breaking the underlying primitive, where "breaking" is concretely an `OracleComp` returning a bad output.

The methodology principle that fits: **axioms are trust claims that must be justified**. VCV-io lets us *demote* most of these axioms from "asserted" to "derived from an oracle handler", which moves their justification from "the team trusts this" to "the handler's structure implies it".

## Refactor scope: per-module sketches

### `Ecies.lean` — 8 axioms → ~2 (defining instance + injection from real primitive)

**Current** (8 axioms):

```
axiom PrivKey, PubKey, Ciphertext, Plaintext : Type
axiom keyOf : PrivKey → PubKey
axiom encrypt : PubKey → Plaintext → Ciphertext
axiom decrypt : PrivKey → Ciphertext → Option Plaintext
axiom roundtrip (sk, pt) : decrypt sk (encrypt (keyOf sk) pt) = some pt
```

**Refactored** (VCV-io OracleComp):

```
import VCVio.OracleComp

namespace Ecies

-- Oracle specification: enc/dec/keygen as three indexed queries
inductive OracleQuery
  | KeyGen
  | Enc (pk : PubKey) (pt : Plaintext)
  | Dec (sk : PrivKey) (ct : Ciphertext)

instance : OracleSpec OracleQuery where
  range
    | .KeyGen => PrivKey × PubKey
    | .Enc _ _ => Ciphertext
    | .Dec _ _ => Option Plaintext

-- The roundtrip property as a theorem over the joint distribution,
-- proven from a handler that models honest ECIES execution.
theorem roundtrip
    (sk : PrivKey) (pt : Plaintext) :
    ∀ pk ∈ Pr[pk | keyOf sk],
    ∀ ct ∈ Pr[ct | encrypt pk pt],
    Pr[= some pt | decrypt sk ct] = 1 := by
  -- handler is honest ECIES; this becomes mechanical
  ...
```

**Net effect**: 8 axioms → 1 (just the type `PrivKey × PubKey × Ciphertext × Plaintext`, an opaque parameter family — and even that could potentially be filled with `BitVec n` or `Vec UInt8 n` from mathlib). Roundtrip becomes a theorem.

### `UserDataCommit.lean` — 5 axioms → ~1

`commitHash` is exactly a random-oracle query. VCV-io has `QueryCacheOracle` for ROs out of the box. `commitHash_inj` becomes a *conditional* theorem (collisions are negligible-probability, not impossible — which is *more accurate* than the current absolute-injectivity axiom).

```
def commitHash (uc : UserDataCommit) : OracleComp ROSpec UserData :=
  query .commitHash uc

-- The current `commitHash_inj` axiom is over-strong; VCV-io lets us
-- state the truth: collisions exist but are negligible.
theorem commitHash_collision_negl :
    ∀ uc₁ uc₂, uc₁ ≠ uc₂ →
    Pr[h | (commitHash uc₁ >>= fun h₁ => commitHash uc₂ >>= fun h₂ => pure (h₁ = h₂))]
    ≤ negligible
```

This is one of those places where the axiom *was lying* (full injectivity of a hash is impossible); VCV-io gives the truthful statement.

### `RawMessages.lean` — 12 axioms → ~3

The 12 axioms are mostly serialization plus the same `commitHash_inj` shape. Serialization injectivity (`serializeRawSessionCreate_inj`) is a real injectivity claim — that one stays an axiom (or is discharged by case analysis on the concrete byte layout if we ever extract from Rust). The named-constant axioms (`rawDomainSep`, `rawBoundContract`, `rawPlaceholderPubKey`) become `def`s with concrete values. Net: 12 → ~3 axioms.

### `Dstack.lean` — 8 axioms → ~3

`verifyTdxQuote` is a verification oracle. Soundness and completeness become joint-distribution claims over the oracle + adversary. `was_signed_by_dstack` is a predicate; in VCV-io it becomes a witness predicate the oracle handler can produce. Net: 8 → ~3 axioms (the irreducible trust: that real-world dstack actually signs what we model it as signing).

### `Zkdcap.lean` — 7 axioms → ~3

`verifyGroth16` is a verification oracle. `verifyGroth16_sound` is exactly the knowledge-soundness shape ArkLib formalizes — but ArkLib doesn't yet cover Groth16, so for now we still axiomatize Groth16 soundness. Net: 7 → ~3 axioms.

## Aggregate effect

| Module | Before | After | Reduction |
|---|---|---|---|
| Ecies | 8 | 1 | -7 |
| UserDataCommit | 5 | 1 | -4 |
| RawMessages | 12 | 3 | -9 |
| Dstack | 8 | 3 | -5 |
| Zkdcap | 7 | 3 | -4 |
| **Total crypto + attestation** | **40** | **~11** | **-29** |

The integration ledger's axiom inventory shrinks from 40 to ~11. The remaining ~11 are genuine trust claims about external systems: ECIES primitive type definitions, hash collision negligibility constants, serialization injectivity bytes-level, Groth16 soundness (until ArkLib covers Groth16), dstack signing behavior. Each is irreducibly axiomatic given current ZK / TEE state of the art; each can be argued for individually.

The protocol-layer theorems (`cross_component_session_bind`, `handshake_sound`, etc.) do not need to change. They re-prove cleanly on the new substrate because the public API of each Crypto/Attestation module stays the same — only its implementation moves from axiom-based to oracle-handler-based.

## Refactor sequencing

Recommended order, minimizing breakage:

1. **Add VCV-io to `lakefile.lean`**, run `lake update && lake build` to confirm dependency resolution. (Single commit, no theorem changes.)
2. **Migrate `Ecies.lean`** first — smallest module, most contained primitive. Re-prove `exists_decrypt` and `decrypt_isSome` from the new `roundtrip` theorem. (One commit per module.)
3. **Migrate `UserDataCommit.lean`** — gain the collision-negligibility refinement. The downstream `pkOfUserData_commitHash` theorem may need a probability-bound qualifier.
4. **Migrate `RawMessages.lean`** — largest axiom reduction; most theorem-side rework.
5. **Migrate `Dstack.lean` and `Zkdcap.lean`** — attestation layer; these touch external-system trust the most.
6. **Re-prove protocol layer** (`cross_component_session_bind` et al.) on the new substrate. Expect minimal changes since public APIs are preserved.
7. **Regenerate the integration ledger** via `colosseum-compose`. The axiom inventory should drop from 40 to ~11, with each remaining axiom carrying a clearer justification line.

Each step is a self-contained `colosseum-change` cycle: triage → intent (no change needed) → impact analysis → spec revisions (Lean only) → re-verify (`lake build`) → composition re-check → ledger delta. The methodology validates itself by running cleanly on this refactor.

## Step 0: Toolchain alignment (added 2026-05-13)

VCV-io's latest tag is `v4.29.0`; the Quartz Lean tree was on `leanprover/lean4:v4.30.0-rc2`. The orchestrator chose Option 1 (downgrade Quartz to match VCV-io) conditional on a clean v4.30-feature scan.

### v4.30-only feature scan result

Swept the Lean tree (`rg -no` across all tactics and syntax indicators) for v4.30-only features:

- No `grind`, `bv_decide`, `bv_omega`, `simp_arith`, `simp_all_arith`, `decide!`, `native_decide`, `nofun`, `fail_if_success`
- No new structure-projection or anonymous-constructor syntax that landed in v4.30
- Mathlib usage limited to `Mathlib.Logic.Function.Basic` (used by 4 files for `Function.Injective`)
- Tactic histogram: classical only — `exact`, `refine`, `obtain`, `rw`, `intro`, `have`, `cases`, `apply`, `show`, `constructor`, `use`, `simp`, `rfl`

Verdict: **clean.** No v4.30-specific features in use; downgrade is structurally safe.

### Toolchain choice

- `proofs/lean/lean-toolchain`: `leanprover/lean4:v4.30.0-rc2` → `leanprover/lean4:v4.29.0`
- `proofs/lean/lakefile.lean`: mathlib pin `master` → `v4.29.0`
- VCV-io added at tag `v4.29.0`

### Downgrade verification

Pre-downgrade baseline at v4.30.0-rc2: `lake build` green (104 jobs).
Post-downgrade at v4.29.0 (before VCV-io added): `lake build` green (104 jobs).
Post VCV-io require: `lake build` green (2638 jobs — VCV-io itself adds 2534 transitive build targets).

No breakages encountered during the downgrade. The 16 existing theorems re-proved cleanly.

### Upstream VCV-io issue

Not filed — local `gh` CLI is not authenticated to GitHub. Open todo: file an issue titled "Toolchain: any plans to bump to v4.30?" at https://github.com/Verified-zkEVM/VCV-io/issues so we can track upstream's v4.30 plans before we end up wanting v4.30 features.

### Methodology note: VCV-io is heavy

VCV-io's lakefile is substantial — it transitively pulls Hax (Rust verification frontend), Loom2 (Lean WP-triple foundation), PolyFun, and triggers C FFI builds for mlkem-native, mldsa-native, c-fn-dsa. When required as a dependency, lake only clones the Lean library tree (Hax/Loom2/PolyFun do not get pulled because the v4.29.0 tag's lakefile-imports for them are conditional on the `Interop` library being a build target — which it is for VCV-io's own build, but not when consumed externally). However, the `lake build` time grows from 104 jobs → 2638 jobs (a 25x increase), and the build now warns about ~10 `sorry`s inside VCV-io's advanced modules (Fischlin, FiatShamir, KEMDEM, FujisakiOkamoto.*). Those sorries are not in modules we use (`OracleComp`, `AsymmEncAlg.Defs`), so they do not affect Quartz's verified surface — but they do bloat the build and the `lake env lean --print-axioms` surface. **Open methodology question**: is requiring all of VCV-io the right granularity, or should Quartz vendor only the `OracleComp` + `AsymmEncAlg.Defs` subset it actually uses? Deferred decision; current path is the simpler one.

## Step 6 detail: OracleComp lift of the protocol layer (added 2026-05-13)

Drafted after Step 2 surfaced the load-bearing methodology finding: **5 downstream protocol theorems silently depend on a mathematically impossible axiom** (`commitHashE : UserDataCommit ↪ UserData` — pigeonhole rules it out). Step 3 is expected to surface the same shape with `commitHashBytes_inj`. Step 6 is where this gets fixed.

### Goal

Lift the protocol-layer theorems from `Prop`-only statements over impossible axioms to `OracleComp`-resident probabilistic claims over the random-oracle model. Replace the `_inj` axioms with `_collision_negl` theorems proven over the OracleSpec handlers established in the companion modules.

This is the substantive methodology win — the axiom-count reductions of Steps 1-5 are *form* progress; Step 6 is the *content* progress. After Step 6, the protocol theorems become honest claims about what real ECIES + SHA-256 + serialization actually guarantee, with explicit probability bounds, rather than absolute statements over impossible assumptions.

### Expected state at Step 6 entry

After Steps 3–5 complete, the impossible-axiom inventory will be:

| Axiom | Module | Shape | Downstream dependents |
|---|---|---|---|
| `commitHashE` | UserDataCommit | injection from open-cardinality UDC to 64-byte UD | 5 theorems (verified Step 2) |
| `commitHashBytes_inj` | RawMessages | injection from open-cardinality ByteSeq to UD | TBD (Step 3 will verify) |
| Possible Dstack/Zkdcap analogs | Attestation | verification soundness/completeness as classical Prop | TBD (Steps 4–5 will verify) |

Each is mathematically impossible as stated, true under random-oracle / computational-soundness assumptions in reality.

### Structural change to protocol theorems

The pattern below is the canonical lift. `session_confidentiality` is the worked example; the rest of the protocol layer follows by analogy.

**Before** (current state at Step 5 exit):

```lean
theorem session_confidentiality
    (h : HandshakeCheck) (acc : Accepted h)
    (c : UserDataCommit) (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey) (h_sk : keyOf sk = c.eciesPubkey)
    (msg : Plaintext) :
    decrypt sk (encrypt c.eciesPubkey msg) = some msg := by
  -- proven from commitHashE (impossible) + Ecies.roundtrip
```

**After** (Step 6 target):

```lean
theorem session_confidentiality_negl
    (h : HandshakeCheckGame) (acc : Pr[Accepted | h.run] ≥ 1 - negligible)
    (c : UserDataCommit) (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey) (h_sk : keyOf sk = c.eciesPubkey)
    (msg : Plaintext) :
    Pr[some msg | (decrypt sk <$> encrypt c.eciesPubkey msg)] ≥ 1 - negligible := by
  -- proven via VCV-io's relational logic; collision-prob bound inherited
  -- from commitHash_collision_negl (the new truthful axiom shape)
```

The theorem still says "the legitimate sk-holder recovers msg" but now does so as a high-probability event over the random-oracle handler, not as an absolute Prop. The bound is explicit. The reader can audit which negligibility assumptions ride along.

### Sequencing within Step 6

1. **Activate the companion modules.** `EciesVCVio.lean`, `UserDataCommitVCVio.lean`, `RawMessagesVCVio.lean` (and any from Steps 4–5) become load-bearing. Each provides the `OracleSpec` + `OracleComp` interpretation for its primitive plus a `_collision_negl` theorem replacing the impossible `_inj` axiom.

2. **Establish a project-wide negligibility framework.** Pick concrete vs asymptotic. Recommendation: asymptotic (`negligible : ℕ → ℝ≥0`) over a security parameter `n`, with concrete instantiations at `n = 128` or `n = 256` as `def`s. VCV-io has `Negligible` infrastructure to reuse; don't roll our own.

3. **Define the adversary games.** For each protocol theorem, name the security game it represents:
   - `session_confidentiality` → recoverability-under-honest-keys game (NOT confidentiality in the IND-CPA sense; see honesty note below)
   - `handshake_binds_ecies_key` → pubkey-binding game over the random-oracle commitment
   - `cross_component_session_bind` → composition of the above with attestation soundness games
   - `userData_session_set_pub_key_binds_ecies` → ditto for the SetPubKey flow

4. **Rewrite each theorem as a bound over the corresponding game.** Use VCV-io's `Pr[event | comp]` notation. The proof obligations become VCV-io's relational logic (`by_equiv`, `rvcstep`, `game_trans`).

5. **Compose the bounds.** `cross_component_session_bind`'s bound is the union (or sum) of the bounds from its dependencies: `Pr[bind_fails] ≤ Pr[commit_collision] + Pr[serialize_collision] + Pr[attest_unsound]`. VCV-io's `game_trans` tactic handles the boilerplate.

6. **Update the integration ledger.** The axiom inventory drops from ~11 (Step 5 exit) to ~6 (Step 6 exit) — the remaining axioms are the genuine externally-supplied trust (carrier types, `keyOf`, `verifyTdxQuote` external soundness, `verifyGroth16` external soundness, etc.). Each becomes a *concrete* negligibility-budget contributor rather than an absolute claim.

### Honesty notes that survive Step 6

Even after Step 6, the protocol layer does **not** prove IND-CPA-style confidentiality:

- `session_confidentiality_negl` says "the legitimate sk-holder recovers msg with high probability". It does NOT say "an adversary cannot learn msg".
- A real confidentiality claim requires modelling an adversary that may receive ciphertexts adaptively, has bounded computational power, etc. VCV-io supports this via the `AsymmEncAlg` IND-CPA game in `EciesVCVio.lean`'s sketch, but the protocol theorems would need a separate IND-CPA-resident formulation.
- **Methodology decision for Step 6**: either rename the protocol theorems to reflect what they actually prove (e.g. `session_recoverability_negl` instead of `session_confidentiality_negl`), or extend the proof to actually establish IND-CPA against the composed game. The first is honest and cheap; the second is the substantive claim the theorem name implies.

This is a separate finding from the impossible-axiom one. The impossible-axiom issue is fixed in Step 6; the name-vs-body issue requires an explicit decision.

### Open questions to resolve during Step 6 execution

1. **`Fintype` on abstract carriers.** VCV-io's `Pr[...]` notation requires the range type to support a measure. Can we instantiate with abstract `UserData` as long as the oracle's output distribution is well-defined? Or do we need to commit to a concrete representation (`BitVec 512` or `Fin (2^512)`)? VCV-io's `LatticeCrypto` examples do the latter; check whether the same pattern works for our abstract types or requires their concretization.

2. **Negligibility composition discipline.** When `cross_component_session_bind` rides on three primitives' bounds, is the sum bound tight enough to be useful, or do we need explicit reductions (e.g. "the cross-component bind fails with probability at most 2 × the commitment collision probability")? Empirical question; VCV-io's `rvcstep` should produce tight bounds when the proofs are well-structured.

3. **Backward compatibility.** Downstream consumers (whatever code in `crates/contracts/core/` or `crates/enclave/core/` invokes these protocol theorems abstractly) may want both the absolute-Prop and the negligibility-bound forms. Option: keep the old theorem names with the new bound-bearing bodies, where the bound is implicit (`negligible`-bounded recovery is "definitely recovers" for engineering purposes). Risk: bound erasure looks like the original false claim.

4. **Is the OracleComp lift itself an adversarial target?** Yes. Per the methodology, run `colosseum-adversarial` against the migrated theorems before declaring Step 6 complete. The new formulation is more complex than the old impossible-but-simple one; complexity hides bugs. Expected attacks: (a) the negligibility bound is too loose to be meaningful, (b) the oracle handler doesn't faithfully model the real primitive, (c) the composition is missing a quantifier scope, (d) name-vs-body gaps that didn't exist in the simpler formulation.

### Estimated effort

Step 6 is the largest single step. It rewrites every protocol-layer theorem (currently 5 + corollaries) and depends on every companion module being load-bearing. Sequence within: one protocol theorem at a time, smallest dependency cone first (`session_confidentiality_negl` likely first since it touches only Ecies + UserDataCommit; `cross_component_session_bind_negl` last since it touches everything).

Each protocol-theorem migration is itself a `colosseum-change` cycle. Total: ~5 sub-cycles for the 5 named theorems plus corollaries.

### Success criteria for Step 6 exit

- [ ] All `_inj` axioms with impossible-injectivity shape are replaced with `_collision_negl` theorems
- [ ] Every protocol theorem either has a negligibility-bound formulation or is explicitly marked as "engineering-only, acknowledged not honest"
- [ ] `lake build` green; `lean_verify` shows no protocol theorem depends on a mathematically impossible axiom
- [ ] Integration ledger regenerated; axiom count is the post-Step-6 number (~6, target)
- [ ] `colosseum-adversarial` round against the migrated protocol layer surfaces ≤ 2 serious findings, and they're either accepted-with-acknowledgement or actually addressed in a follow-up
- [ ] The methodology emits a "trust density" metric per the open methodology question: post-Step-6 axiom-to-theorem ratio for Quartz's full Lean tree

## Open methodology questions surfaced by this plan

1. **What is the right axiom-to-derived-theorem ratio for a Colosseum project?** The current Quartz tree is 40:16 (~2.5 axioms per theorem). Post-refactor it would be ~11:16 (~0.7 axioms per theorem). The methodology should probably emit this ratio as part of `colosseum-compose`'s ledger output — a "trust density" metric.

2. **When does an axiom indicate a missing dependency vs an irreducible trust claim?** ECIES roundtrip *was* an irreducible-feeling axiom; VCV-io reveals it was actually a missing-substrate problem. `verifyGroth16_sound` *looks* irreducible today; ArkLib roadmap suggests it may not be in 12 months. The methodology should treat "looks irreducible" as a temporal claim and queue periodic reviews.

3. **Is this refactor itself an adversarial target?** The new `OracleComp` formulation is more complex than the axiomatic stubs. An adversary should attack it for the same `temporal_state_mismatch`-shape pitfalls — does the oracle handler actually capture what ECIES does, or has the complexity moved the bug rather than removed it? Worth running `colosseum-adversarial` against the migrated modules before declaring victory.

## Estimated effort and scope

This is multi-day work, not a single-session refactor. Sequence is per-module; each migration is independently shippable. The first module (Ecies) is the smallest and the right place to validate the approach before committing to the full series.

Net: the refactor is **worth doing** because it converts 29 axioms (~72% of the crypto trust boundary) from "trust on faith" to "trust on derivation". That's a methodology-level upgrade for any project using Quartz's Lean tree as a model.
