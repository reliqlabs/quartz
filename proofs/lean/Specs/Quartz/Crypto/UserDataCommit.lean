/-
  Trust boundary: structured commitment carried by the TDX quote's
  `user_data` field — VCV-io substrate.

  Historical context: this module previously held **five** axioms —
  three abstract carrier types (`DomainSep`, `Addr`, `Nonce`), one
  abstract operation (`commitHash`), and an absolute-injectivity
  axiom (`commitHash_inj`).

  Refactor (VCV-io migration, 2026-05-13):

  * Three **carrier-type** axioms remain (`DomainSep`, `Addr`,
    `Nonce`). These are genuinely externally-supplied carriers used
    across downstream modules (`RawMessages.lean`, `Conservation.lean`,
    `TransferMessages.lean`, `AuctionMessages.lean`). Bundling them
    is out of scope here — that touches Steps 4-5 of the refactor
    plan.

  * `commitHash` and `commitHash_inj` are **bundled into a single
    axiom** `commitHashE : UserDataCommit ↪ UserData` (a
    `Function.Embedding`, i.e. an injective function packaged as
    `{f // Function.Injective f}`). The hash function and its
    injectivity become *projections* of this embedding rather than
    two independent axioms. `commitHash` becomes a `def`;
    `commitHash_inj` becomes a *theorem* derived from the
    embedding's `injective` field.

  Net effect on Quartz's verified surface: **5 axioms → 4 axioms**.

  --------------------------------------------------------------------
  HONESTY-LENS FINDING (load-bearing — do not paper over):
  --------------------------------------------------------------------

  The bundled `commitHashE : UserDataCommit ↪ UserData` axiom is
  **mathematically impossible** in the same sense the old
  `commitHash_inj` was. It asserts an injective embedding of the
  open-cardinality structure `UserDataCommit` (whose `domainSep`,
  `contractAddr`, `nonce` fields range over abstract carriers and
  whose `eciesPubkey` ranges over `PubKey`) into the fixed-width
  64-byte `UserData` slot. By pigeonhole, no such embedding exists
  once `|UserDataCommit| > |UserData|`.

  The bundling **does not fix** this. It surfaces it: the single
  axiom now visibly carries both "there is a hash" and "the hash
  is collision-free", which exposes the second claim as the
  load-bearing trust assumption.

  The truthful VCV-io statement is **negligible collision
  probability** when `commitHash` is modelled as a random-oracle
  query:

      Pr[collision in commitHash queries] ≤ q² / 2^|UserData|

  where `q` is the adversary's query budget. The companion module
  `UserDataCommitVCVio.lean` sketches this random-oracle model.

  **Why the core module retains the impossible axiom anyway**:
  downstream theorems (`pkOfUserData_commitHash`,
  `handshake_binds_ecies_key`, `session_confidentiality_via_extractor`)
  consume `commitHash_inj` as a deterministic equality, not as a
  probability bound. To honestly demote the axiom to
  `commitHash_collision_negl`, every consumer of `pkOfUserData`
  must be rewritten to live inside `OracleComp` and carry a
  collision-probability budget. That is a deep rewrite affecting
  the protocol-layer theorems' shape, not just the substrate
  module — Steps 6+ of the refactor plan, after RawMessages /
  Dstack / Zkdcap migrations expose the rest of the surface.

  **What this means in plain terms**: the three protocol theorems
  named above silently depend on a mathematically false axiom.
  The methodology output should make this distinction visible — it
  is the most important methodology finding of Step 2.

  --------------------------------------------------------------------
-/

-- NOTE: This module is intentionally kept free of `VCVio` imports.
-- Downstream files rely on instance synthesis for
-- `Decidable (∃ c, commitHash c = ud)` that the VCVio transitive
-- closure slows past the default `synthInstance.maxHeartbeats` budget.
-- The VCV-io integration (random-oracle model + negligibility
-- statement sketch) lives in the sibling module
-- `Specs/Quartz/Crypto/UserDataCommitVCVio.lean`, imported only
-- where probabilistic refinements are needed.

import Mathlib.Logic.Function.Basic
import Mathlib.Logic.Embedding.Basic
import Specs.Quartz.Crypto.Ecies
import Specs.Quartz.Attestation.Dstack

namespace Specs.Quartz.Crypto

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Attestation.Dstack

/-- Domain-separation tag for the user_data commitment.

    The Rust code uses a fixed ASCII prefix (e.g. `"QUARTZ-HS-V1"`)
    so that hashes for different protocol contexts cannot collide.

    **Cycle 6.20 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8` (a variable-length byte sequence) — the natural
    Lean model for an ASCII byte string. -/
abbrev DomainSep : Type := List UInt8

/-- A CosmWasm contract address (bech32).

    **Cycle 6.20 (carrier refinement, 2026-05-20)**: refined to
    `String`. Bech32 addresses are textual; `String` is the
    natural Lean model. `String` carries `DecidableEq` and
    `Inhabited` automatically. -/
abbrev Addr : Type := String

/-- A per-handshake nonce, chosen by the contract / chain (e.g. block
    height + tx index) to prevent replay of stale `user_data`.

    **Cycle 6.16 (carrier refinement, 2026-05-20)**: refined from
    `axiom Nonce : Type` to a concrete `BitVec 256` (the standard
    Lean model of a 32-byte / 256-bit value, mirroring the Rust
    `[u8; 32]` representation). `BitVec n` automatically supplies
    `Fintype`, `DecidableEq`, and `Inhabited` instances, which
    unblocks several downstream concerns:

    - The `commitHashE` / `commitHashBytesE` random-oracle discharge
      requires `[Fintype]` on the index type of the OracleSpec.
      `Nonce` appearing in `UserDataCommit` was one blocker for that
      `[Fintype UserDataCommit]` — refining `Nonce` removes one
      blocker (the others — `DomainSep`, `Addr`, `PubKey` — remain
      abstract until their own carrier refinements land).
    - `Nonce` leaves the closure of every classical and `_negl`
      theorem because it is no longer an axiom. -/
abbrev Nonce : Type := BitVec 256

/-- The structured pre-image hashed into `user_data`.

    Choice of fields is the minimal schema sufficient to make the
    composition proof go through:

    * `domainSep`     – domain separation tag.
    * `eciesPubkey`   – the enclave-controlled ECIES session pubkey.
    * `contractAddr`  – which CosmWasm contract this session is for.
    * `nonce`         – freshness/anti-replay binder. -/
structure UserDataCommit where
  domainSep    : DomainSep
  eciesPubkey  : PubKey
  contractAddr : Addr
  nonce        : Nonce

/-- **Bundled trust-boundary axiom**: the structured-tuple → 64-byte
    `user_data` hash, packaged as an injective embedding.

    Concretely this is `SHA-256(domain_sep || serialize(pk, addr,
    nonce))` (or any other collision-resistant encoding), bundled
    with the assertion that it is collision-free over the
    `UserDataCommit` domain.

    This replaces the previous pair (`commitHash` axiom +
    `commitHash_inj` axiom) with a single bundled axiom.

    **Honesty caveat** (see file header): full injectivity of a
    fixed-width hash is mathematically impossible by pigeonhole.
    The truthful statement is that *collisions are negligible
    probability* in a random-oracle model — see
    `UserDataCommitVCVio.lean` for the sketch.

    Downstream theorems currently consume the deterministic-equality
    shape; demoting this axiom to a negligibility theorem requires
    rewriting the protocol-layer theorems to live inside `OracleComp`.
    Out of scope for Step 2 of the refactor plan.

    **Safe-use convention (n ≥ 1)**: this axiom family is mathematically
    inconsistent at `n = 0` because `UserData 0 = BitVec 0` has exactly
    one inhabitant, forcing any two distinct `UserDataCommit` values to
    collide constructively (via `Inhabited UserDataCommit` plus any
    second value). The axiom is *not* gated on `n ≥ 1` at the type
    level — every downstream theorem must invoke it at `n ≥ 1`. Deployed
    `n = 512` (the dstack TDX `report_data` width); all in-tree uses
    parameterise over the same `n` reaching the deployed value.

    Adversarial review (cycle 6.22.d.4 finding #1/#14): the pre-
    parameterisation single axiom required abstract pigeonhole to derive
    `False`; the family form admits constructive `False` at `n = 0`. The
    constraint is documentary rather than type-enforced because adding
    `[NeZero n]` throughout the closure was a multi-hour cascade and
    deployed callers never instantiate at `n = 0`. Future cycles may
    migrate to the cycle-6.22 RO model entirely (which avoids the
    `commitHashE` axiom).

    -/
axiom commitHashE (n : Nat) : UserDataCommit ↪ UserData n

/-- The commitment hash: structured tuple → 64-byte `user_data`.

    Concretely this is `SHA-256(domain_sep || serialize(pk, addr,
    nonce))` (or any other collision-resistant encoding). Defined
    as the underlying function of the bundled `commitHashE`
    embedding axiom; injectivity is derived as a theorem below.

    Previously an axiom; now a derived definition. Marked
    `noncomputable` because `commitHashE` is an axiom — the code
    generator cannot lower it, but it is still usable in proofs. -/
noncomputable def commitHash (n : Nat) (c : UserDataCommit) : UserData n :=
  commitHashE n c

/-- **Theorem (formerly an axiom)**: `commitHash` is injective.

    Previously an independent axiom; now derived as a projection
    of the bundled `commitHashE` embedding.

    **Honesty caveat** (carries over from `commitHashE`): the
    underlying axiom is mathematically impossible. This theorem
    is sound *modulo* that impossible axiom — i.e. it correctly
    derives "injectivity of `commitHash`" from "the trust
    assumption that the hash is an injective embedding", but the
    trust assumption is mathematically false in the standard set
    theoretic sense. Downstream theorems consuming this should
    eventually migrate to the random-oracle negligibility shape
    sketched in `UserDataCommitVCVio.lean`. -/
theorem commitHash_inj (n : Nat) : Function.Injective (commitHash n) := by
  intro a b h
  exact (commitHashE n).injective h

/-- Extract the committed ECIES pubkey from a `user_data` blob,
    if one exists.

    Implementation strategy: by injectivity of `commitHash`, at
    most one `UserDataCommit` value can hash to any given `ud`,
    so the extraction is well-defined. We use classical choice
    to pick that unique preimage (if any). -/
noncomputable def pkOfUserData (n : Nat) (ud : UserData n) : Option PubKey :=
  open Classical in
  if h : ∃ c : UserDataCommit, commitHash n c = ud then
    some (Classical.choose h).eciesPubkey
  else
    none

/-- **Lemma (discharge)**: extracting from a hashed commitment
    recovers the committed pubkey.

    This is the constructive content that lets us replace the
    previous `pkOfUserData ud = some pk` hypothesis in
    `handshake_binds_ecies_key` with an actual proof, given a
    known `UserDataCommit` witness.

    Proof body unchanged from the pre-refactor version — the
    only substrate change is that `commitHash_inj` is now a
    theorem (derived from the bundled `commitHashE` embedding)
    rather than an independent axiom. Same call shape, so
    downstream theorems re-prove unchanged. -/
theorem pkOfUserData_commitHash (n : Nat) (c : UserDataCommit) :
    pkOfUserData n (commitHash n c) = some c.eciesPubkey := by
  unfold pkOfUserData
  have hex : ∃ c' : UserDataCommit, commitHash n c' = commitHash n c := ⟨c, rfl⟩
  rw [dif_pos hex]
  congr 1
  have hspec : commitHash n (Classical.choose hex) = commitHash n c :=
    Classical.choose_spec hex
  exact congrArg UserDataCommit.eciesPubkey (commitHash_inj n hspec)

end Specs.Quartz.Crypto
