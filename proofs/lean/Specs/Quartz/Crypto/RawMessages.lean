/-
  Trust boundary: bridge from abstract `UserDataCommit` to the
  concrete Rust struct layouts that Quartz hashes into `user_data` —
  VCV-io substrate.

  In Rust (`crates/contracts/core/src/msg/execute/session_create.rs`
  and `session_set_pub_key.rs`), `user_data` is computed as

      Sha256(serde_json::to_string(&RawSessionCreate::from(self)))

  on a concrete struct layout:

      RawSessionCreate    { nonce: HexBinary, contract: String   }
      RawSessionSetPubKey { nonce: HexBinary, pub_key: HexBinary }

  At the spec level we do NOT model serde_json byte-for-byte.
  Instead, we model the Raw structs as Lean records (so we get
  `injEq` on field equality for free) and treat the JSON serializer
  + SHA-256 composition as NAMED collision-resistance assumptions
  via bundled trust-boundary embedding axioms:

    * `serializeRawSessionCreateE`     — serde_json is an injective
                                         embedding on `RawSessionCreate`.
    * `serializeRawSessionSetPubKeyE`  — same, on `RawSessionSetPubKey`.
    * `commitHashBytesE`               — SHA-256-based byte-hash is an
                                         injective embedding from
                                         `ByteSeq` to `UserData`.

  The resulting `userDataOf…` functions then inherit injectivity by
  composition, which is exactly what closes the spec-level fidelity
  gap from abstract `UserDataCommit` to the on-the-wire Rust types.

  --------------------------------------------------------------------
  Historical context: this module previously held **12** axioms.
  --------------------------------------------------------------------

  Refactor (VCV-io migration, 2026-05-13, Step 3):

  * `ByteSeq : Type` remains as an opaque carrier axiom.
  * `serializeRawSessionCreate`+`serializeRawSessionCreate_inj` are
    **bundled** into a single embedding axiom
    `serializeRawSessionCreateE : RawSessionCreate ↪ ByteSeq`. The
    serialization function and its injectivity become projections.
  * `serializeRawSessionSetPubKey`+`serializeRawSessionSetPubKey_inj`
    are bundled the same way into `serializeRawSessionSetPubKeyE`.
  * `commitHashBytes`+`commitHashBytes_inj` are bundled into
    `commitHashBytesE : ByteSeq ↪ UserData`. `commitHashBytes` is
    now a `def` and `commitHashBytes_inj` is a derived theorem.
    Public API names preserved so downstream files
    (`TransferMessages.lean`, `AuctionMessages.lean`) re-build
    unchanged.
  * The three **named-constant witness axioms** (`rawDomainSep`,
    `rawBoundContract`, `rawPlaceholderPubKey`) remain as axioms.
    Each names a specific witness value of an abstract carrier
    type (`DomainSep`, `Addr`, `PubKey`) defined in upstream
    modules. The refactor plan proposed demoting these to `def`s
    with concrete values, but no concrete value is available
    without modifying the upstream carrier types — those are
    frozen for this step (Steps 1/2 closed). Honest stance:
    these are existence witnesses into abstract carriers; they
    are irreducibly axiomatic at this layer until the carrier
    types are refined (Steps 4-5+ when `DomainSep`/`Addr`/`PubKey`
    become concrete byte-shaped definitions).
  * The two **hash-domain bridge axioms** (`…_eq_commitHash`)
    remain. They are genuine equality claims that the
    byte-hash and structured-hash routes produce the same
    `user_data`; discharging them requires a constructive
    byte-level model of `serde_json` + `SHA-256`, out of scope.

  Net effect on Quartz's verified surface: **12 axioms → 9 axioms**.

  --------------------------------------------------------------------
  HONESTY-LENS FINDING (load-bearing — do not paper over):
  --------------------------------------------------------------------

  The bundled `commitHashBytesE : ByteSeq ↪ UserData` axiom is
  **mathematically impossible** in the same sense Step 2's
  `commitHashE : UserDataCommit ↪ UserData` was. It asserts an
  injective embedding from the open-cardinality carrier `ByteSeq`
  (an opaque byte-sequence type with no size bound) into the
  fixed-width 64-byte `UserData` slot. By pigeonhole, no such
  embedding exists once `|ByteSeq| > |UserData|`.

  Bundling `commitHashBytes` + `commitHashBytes_inj` into one
  embedding axiom **does not fix this**. It surfaces it: the
  single axiom now visibly carries both "there is a byte-hash"
  and "the byte-hash is collision-free", which exposes the
  second claim as the load-bearing impossible trust assumption.

  The two `serialize…E` embedding axioms are **NOT impossible**:
  serde_json's encoding of a fixed struct schema is plausibly
  injective in the cryptographic sense (deterministic encoding
  + unique field tags per schema), and the carriers `ByteSeq`
  on the codomain side are open-cardinality. Those are honest
  trust-boundary claims that will eventually be discharged by
  modelling the serde_json grammar.

  The truthful VCV-io statement for `commitHashBytes` is
  **negligible collision probability** when the byte-hash is
  modelled as a random-oracle query:

      Pr[collision in commitHashBytes queries] ≤ q² / 2^|UserData|

  where `q` is the adversary's query budget. The companion module
  `RawMessagesVCVio.lean` sketches this random-oracle model.

  **Downstream theorems silently relying on the impossible axiom**:

    Verified via `lean_verify` to have `commitHashBytesE` (i.e.
    the old `commitHashBytes` + `commitHashBytes_inj` pair) in
    their axiom closure:

    1. `Specs.Quartz.Crypto.distinct_raw_session_create_gives_distinct_user_data`
    2. `Specs.Quartz.Crypto.distinct_raw_session_set_pub_key_gives_distinct_user_data`
    3. `Specs.Quartz.Crypto.userDataOfSessionCreate_inj`
    4. `Specs.Quartz.Crypto.userDataOfSessionSetPubKey_inj`
    5. `Specs.Quartz.Crypto.distinct_transfer_request_gives_distinct_user_data`
      (downstream — `TransferMessages.lean`)
    6. `Specs.Quartz.Crypto.userDataOfTransferRequest_inj`
      (downstream — `TransferMessages.lean`)
    7. `Specs.Quartz.Crypto.distinct_resolve_message_gives_distinct_user_data`
      (downstream — `AuctionMessages.lean`)
    8. `Specs.Quartz.Crypto.userDataOfResolveMessage_inj`
      (downstream — `AuctionMessages.lean`)

  NOTE: the two **bridge theorems** in this module
  (`userData_session_set_pub_key_binds_ecies` and
  `userData_session_create_extracts_placeholder`) do NOT depend
  on `commitHashBytesE`; they depend on Step 2's `commitHashE`
  (via `pkOfUserData_commitHash`) and on the two bridge axioms.
  The two impossible-axiom dependencies are distinct.

  **Why the core module retains the impossible axiom anyway**:
  same reason as Step 2 — downstream consumers ride on
  deterministic injectivity, not a probability bound. Migrating
  them requires lifting the protocol-layer (and inter-module)
  theorems into `OracleComp` with a collision-probability
  budget. That is a deep rewrite affecting theorem statements,
  belongs to Step 6+ of the refactor plan.

  **What this means in plain terms**: the eight theorems named
  above (4 here + 4 downstream) silently depend on a
  mathematically false axiom. The methodology output should
  make this distinction visible — it is the second
  impossible-axiom surfacing of the refactor (after Step 2's
  `commitHashE`), and it lands in exactly the parallel place
  the change record for Step 2 predicted.

  --------------------------------------------------------------------
-/

-- NOTE: This module is intentionally kept free of `VCVio` imports.
-- Downstream files rely on instance synthesis for
-- `Decidable (∃ c, commitHash c = ud)` that the VCVio transitive
-- closure slows past the default `synthInstance.maxHeartbeats` budget.
-- The VCV-io integration (random-oracle model of `commitHashBytes`
-- + negligibility statement sketch) lives in the sibling module
-- `Specs/Quartz/Crypto/RawMessagesVCVio.lean`, imported only where
-- probabilistic refinements are needed.

import Mathlib.Logic.Function.Basic
import Mathlib.Logic.Embedding.Basic
import Specs.Quartz.Crypto.Ecies
import Specs.Quartz.Crypto.UserDataCommit
import Specs.Quartz.Attestation.Dstack

namespace Specs.Quartz.Crypto

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Attestation.Dstack

/-- Opaque byte sequence — the output of `serde_json::to_string`
    seen abstractly.

    **Cycle 6.20 (carrier refinement, 2026-05-20)**: refined to
    `List UInt8`. JSON byte output is a variable-length byte
    sequence; `List UInt8` is the natural Lean model. The JSON byte
    layout itself remains out of scope at this spec level — what
    we now make concrete is the *type* of the byte sequence, not
    the byte mapping from a `RawSession*` struct. -/
abbrev ByteSeq : Type := List UInt8

/-- Lean mirror of Rust's `RawSessionCreate { nonce, contract }`.

    Field types reuse the abstract `Nonce` / `Addr` from
    `UserDataCommit.lean`. The `String` field on the Rust side
    is bech32-shaped, modelled at this layer by the abstract
    `Addr` type. -/
structure RawSessionCreate where
  nonce    : Nonce
  contract : Addr

/-- Lean mirror of Rust's `RawSessionSetPubKey { nonce, pub_key }`.

    `pub_key` is a `HexBinary` in Rust, carrying a serialized
    secp256k1 verifying key. At this layer we collapse it to the
    abstract `PubKey` type from `Ecies.lean`, since the Quartz spec
    chain treats the published ECIES pubkey opaquely. -/
structure RawSessionSetPubKey where
  nonce  : Nonce
  pubKey : PubKey

/-- **Bundled trust-boundary axiom (serde-injectivity, SessionCreate)**:
    serde_json's encoding of `RawSessionCreate` as an injective
    embedding into `ByteSeq`.

    Honest interpretation: serde_json + cw_serde produce a
    deterministic byte string per Lean value, and that map is
    injective on this fixed schema. This is a property of the
    JSON grammar + cw_serde macro expansion, NOT proved here.
    Bundles the previous pair (`serializeRawSessionCreate` axiom
    + `serializeRawSessionCreate_inj` axiom) into a single
    embedding-shaped axiom. -/
axiom serializeRawSessionCreateE : RawSessionCreate ↪ ByteSeq

/-- **Bundled trust-boundary axiom (serde-injectivity, SetPubKey)**:
    same shape as above for `RawSessionSetPubKey`. -/
axiom serializeRawSessionSetPubKeyE : RawSessionSetPubKey ↪ ByteSeq

/-- serde_json serialization of `RawSessionCreate` (as Quartz uses
    it). Public API preserved from the pre-refactor axiom; now a
    derived `def` projecting the bundled `serializeRawSessionCreateE`
    embedding. -/
noncomputable def serializeRawSessionCreate (r : RawSessionCreate) : ByteSeq :=
  serializeRawSessionCreateE r

/-- serde_json serialization of `RawSessionSetPubKey`. Public API
    preserved; derived from the bundled embedding. -/
noncomputable def serializeRawSessionSetPubKey (r : RawSessionSetPubKey) : ByteSeq :=
  serializeRawSessionSetPubKeyE r

/-- **Theorem (formerly an axiom)**: `serializeRawSessionCreate` is
    injective. Derived as a projection of the bundled
    `serializeRawSessionCreateE` embedding. -/
theorem serializeRawSessionCreate_inj :
    Function.Injective serializeRawSessionCreate := by
  intro a b h
  exact serializeRawSessionCreateE.injective h

/-- **Theorem (formerly an axiom)**: `serializeRawSessionSetPubKey`
    is injective. Derived as a projection of the bundled embedding. -/
theorem serializeRawSessionSetPubKey_inj :
    Function.Injective serializeRawSessionSetPubKey := by
  intro a b h
  exact serializeRawSessionSetPubKeyE.injective h

/-- **Bundled trust-boundary axiom (SHA-256 collision resistance,
    byte domain)**: SHA-256–based byte hash producing a `UserData`
    blob (with the trailing-32-byte-zero padding the Rust code
    applies) as an injective embedding.

    **Honesty caveat** (see file header): full injectivity of a
    fixed-width hash on an open-cardinality `ByteSeq` domain is
    mathematically impossible by pigeonhole. The truthful
    statement is that *collisions are negligible probability*
    in a random-oracle model — see `RawMessagesVCVio.lean`
    for the sketch.

    Bundles the previous pair (`commitHashBytes` axiom +
    `commitHashBytes_inj` axiom) into a single embedding-shaped
    axiom. The bundling does NOT fix the impossibility — it
    surfaces it as the load-bearing trust assumption. -/
axiom commitHashBytesE (n : Nat) : ByteSeq ↪ UserData n

/-- SHA-256–based byte hash producing a `UserData` blob. Public
    API preserved from the pre-refactor axiom; now a derived `def`
    projecting the bundled `commitHashBytesE` embedding. Marked
    `noncomputable` because the underlying embedding is an axiom. -/
noncomputable def commitHashBytes (n : Nat) (b : ByteSeq) : UserData n :=
  commitHashBytesE n b

/-- **Theorem (formerly an axiom)**: `commitHashBytes` is injective.
    Derived as a projection of the bundled `commitHashBytesE`
    embedding.

    **Honesty caveat** (carries over from `commitHashBytesE`): the
    underlying axiom is mathematically impossible. This theorem
    is sound *modulo* that impossible axiom — i.e. it correctly
    derives "injectivity of `commitHashBytes`" from "the trust
    assumption that the byte-hash is an injective embedding",
    but the trust assumption is mathematically false in the
    standard set-theoretic sense. Downstream theorems consuming
    this should eventually migrate to the random-oracle
    negligibility shape sketched in `RawMessagesVCVio.lean`. -/
theorem commitHashBytes_inj (n : Nat) :
    Function.Injective (commitHashBytes n) := by
  intro a b h
  exact (commitHashBytesE n).injective h

/-- `user_data` produced by Quartz from a `RawSessionCreate`,
    matching the Rust path

        Sha256(serde_json::to_string(&raw))

    composed with the 32→64-byte padding. Spec-level definition.

    `noncomputable` because `commitHashBytes` is derived from an
    axiom — the code generator cannot lower it, but it is still
    usable in proofs. -/
noncomputable def userDataOfSessionCreate (n : Nat) (raw : RawSessionCreate) :
    UserData n :=
  commitHashBytes n (serializeRawSessionCreate raw)

/-- `user_data` produced by Quartz from a `RawSessionSetPubKey`. -/
noncomputable def userDataOfSessionSetPubKey (n : Nat)
    (raw : RawSessionSetPubKey) : UserData n :=
  commitHashBytes n (serializeRawSessionSetPubKey raw)

/-- **Structural correspondence (SessionCreate)**: distinct Rust
    `RawSessionCreate` values produce distinct `user_data`.

    Proof: composition of `serializeRawSessionCreate_inj` and
    `commitHashBytes_inj`. The chain is exactly what the contract
    handler relies on when it compares `msg.user_data() ==
    attestation.user_data()` — the comparison is unambiguous
    because the Rust struct → `user_data` map is injective. -/
theorem distinct_raw_session_create_gives_distinct_user_data
    (n : Nat) (r1 r2 : RawSessionCreate) (hne : r1 ≠ r2) :
    userDataOfSessionCreate n r1 ≠ userDataOfSessionCreate n r2 := by
  intro h
  apply hne
  exact serializeRawSessionCreate_inj (commitHashBytes_inj n h)

/-- **Structural correspondence (SessionSetPubKey)**: distinct
    Rust `RawSessionSetPubKey` values produce distinct `user_data`.
    -/
theorem distinct_raw_session_set_pub_key_gives_distinct_user_data
    (n : Nat) (r1 r2 : RawSessionSetPubKey) (hne : r1 ≠ r2) :
    userDataOfSessionSetPubKey n r1 ≠ userDataOfSessionSetPubKey n r2 := by
  intro h
  apply hne
  exact serializeRawSessionSetPubKey_inj (commitHashBytes_inj n h)

/-- Injectivity of `userDataOfSessionCreate` repackaged as a
    `Function.Injective` statement. -/
theorem userDataOfSessionCreate_inj (n : Nat) :
    Function.Injective (userDataOfSessionCreate n) := by
  intro r1 r2 h
  exact serializeRawSessionCreate_inj (commitHashBytes_inj n h)

/-- Injectivity of `userDataOfSessionSetPubKey`. -/
theorem userDataOfSessionSetPubKey_inj (n : Nat) :
    Function.Injective (userDataOfSessionSetPubKey n) := by
  intro r1 r2 h
  exact serializeRawSessionSetPubKey_inj (commitHashBytes_inj n h)

/-
  Bridge from the abstract `UserDataCommit` hash domain to the
  byte-level `commitHashBytes` hash domain.

  We have two opaque `UserData`-valued hashes in play:
    * `commitHash       : UserDataCommit → UserData` (structured,
                                                     from
                                                     `UserDataCommit.lean`)
    * `commitHashBytes  : ByteSeq → UserData`        (raw bytes,
                                                     this file)

  The bridge `commitOfRawSessionSetPubKey` (below) reconstructs a
  `UserDataCommit` from a `RawSessionSetPubKey`. We assert as a
  trust-boundary axiom that — under the agreed serialization +
  SHA-256 schema — the two routes produce the same `user_data`.

  This is the spec-level statement that Quartz's `user_data`
  encoding for `SessionSetPubKey` IS the `commitHash` of the
  matching `UserDataCommit`. Honest statement: this collapses
  the domain-separation tag and the contract-addr/nonce fields
  of `UserDataCommit` to the Rust `RawSessionSetPubKey` layout.
-/

/-- A canonical `DomainSep` value standing in for the JSON-schema
    tag carried implicitly in the serde encoding. At this spec level
    its identity is irrelevant — only its presence in the bridge.

    **Cycle 6.20 (2026-05-20, (a)-bucket demotion)**: with
    `DomainSep` refined to `List UInt8` in the same cycle's carrier-
    refinement pass, this can be demoted to a concrete `def`. The
    value is the deployed ASCII tag `"QUARTZ-HS-V1"` interpreted
    byte-by-byte as `UInt8` codes. -/
def rawDomainSep : DomainSep :=
  "QUARTZ-HS-V1".toUTF8.toList

/-- A canonical `Addr` value standing in for the contract address
    field that `RawSessionSetPubKey` does not carry directly. (The
    Rust `SessionSetPubKey` flow runs against a single bound
    contract resolved at handler dispatch.)

    **Cycle 6.20 (2026-05-20, (a)-bucket demotion)**: with `Addr`
    refined to `String`, this can be demoted to a concrete `def`.
    The exact bech32 address used in deployment is configured at
    instantiation time and not relevant to the spec's logical
    content; we pin a documentary placeholder
    `"xion1quartzdeploymentaddress"` to make the slot non-opaque
    without claiming a specific deployed address. -/
def rawBoundContract : Addr :=
  "xion1quartzdeploymentaddress"

/-- Bridge from a `RawSessionSetPubKey` to the abstract
    `UserDataCommit` schema. The structured commit reuses the
    canonical `rawDomainSep` and `rawBoundContract` constants —
    those fields are not carried inside `RawSessionSetPubKey`
    directly but are pinned by the surrounding protocol context. -/
noncomputable def commitOfRawSessionSetPubKey
    (raw : RawSessionSetPubKey) : UserDataCommit :=
  { domainSep    := rawDomainSep
    eciesPubkey  := raw.pubKey
    contractAddr := rawBoundContract
    nonce        := raw.nonce }

/-- A canonical placeholder `PubKey` value. The SessionCreate
    message does not carry the ECIES pubkey directly — that
    arrives later via SetPubKey — so the bridge to
    `UserDataCommit` fills the slot with this placeholder.

    **Cycle 6.20 (2026-05-20, (a)-bucket demotion)**: with `PubKey`
    refined to `BitVec 264`, this can be demoted to a concrete
    `def`. The placeholder is the zero bitvec — a sentinel value
    indicating "no pubkey set yet". This is a documentary choice;
    the value is never exercised cryptographically because
    `SessionCreate`'s downstream consumers do not use the pubkey
    field. -/
def rawPlaceholderPubKey : PubKey := 0

/-- Bridge from a `RawSessionCreate` to the abstract
    `UserDataCommit` schema. -/
noncomputable def commitOfRawSessionCreate
    (raw : RawSessionCreate) : UserDataCommit :=
  { domainSep    := rawDomainSep
    eciesPubkey  := rawPlaceholderPubKey
    contractAddr := raw.contract
    nonce        := raw.nonce }

/-- **Trust-boundary axiom (hash-domain bridge, SetPubKey)**: the
    two `UserData` routes agree on `RawSessionSetPubKey`.

    Honest reading: this is the assumption that Quartz's chosen
    serde_json layout for `RawSessionSetPubKey`, when composed with
    SHA-256, *is the same hash* as `commitHash` applied to the
    structured `UserDataCommit` we built via
    `commitOfRawSessionSetPubKey`. Without this bridge the two
    abstract hash families are formally unrelated.

    Why an axiom and not a theorem: discharging it requires the
    concrete byte-level model of serde_json's encoding of both
    structs *and* a constructive definition of `commitHash` over
    the same byte stream. Both are out of scope here. -/
axiom userDataOfSessionSetPubKey_eq_commitHash
    (n : Nat) (raw : RawSessionSetPubKey) :
  userDataOfSessionSetPubKey n raw = commitHash n (commitOfRawSessionSetPubKey raw)

/-- **Trust-boundary axiom (hash-domain bridge, SessionCreate)**. -/
axiom userDataOfSessionCreate_eq_commitHash
    (n : Nat) (raw : RawSessionCreate) :
  userDataOfSessionCreate n raw = commitHash n (commitOfRawSessionCreate raw)

/-- **Bridge theorem (load-bearing)**: a `RawSessionSetPubKey`'s
    on-the-wire `user_data` matches the structured commitment for
    its ECIES pubkey.

    This is the theorem that lets `handshake_binds_ecies_key` and
    `session_confidentiality` consume an actual Rust message
    (modulo the bridge axioms above) instead of the abstract
    `UserDataCommit` witness. -/
theorem userData_session_set_pub_key_binds_ecies
    (n : Nat) (raw : RawSessionSetPubKey) :
    pkOfUserData n (userDataOfSessionSetPubKey n raw) = some raw.pubKey := by
  rw [userDataOfSessionSetPubKey_eq_commitHash n raw]
  have := pkOfUserData_commitHash n (commitOfRawSessionSetPubKey raw)
  simpa [commitOfRawSessionSetPubKey] using this

/-- **Bridge theorem (SessionCreate)**: the extractor on a
    `SessionCreate` `user_data` returns the placeholder pubkey
    pinned in `commitOfRawSessionCreate`. Mostly useful to confirm
    that the extraction definition still terminates on
    SessionCreate-shaped `user_data` blobs. -/
theorem userData_session_create_extracts_placeholder
    (n : Nat) (raw : RawSessionCreate) :
    pkOfUserData n (userDataOfSessionCreate n raw) = some rawPlaceholderPubKey := by
  rw [userDataOfSessionCreate_eq_commitHash n raw]
  have := pkOfUserData_commitHash n (commitOfRawSessionCreate raw)
  simpa [commitOfRawSessionCreate] using this

end Specs.Quartz.Crypto
