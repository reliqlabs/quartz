/-
  Trust boundary: bridge from abstract `UserDataCommit` to the
  concrete Rust message types for the sealed-auction example.

  In Rust (`examples/sealed-auction/contracts/src/msg.rs` and
  `enclave/src/request.rs`), the load-bearing message types are:

      SealedBid     { amount: Uint128 }                    (plaintext bid carried inside ECIES)
      ResolveMsg    { round_id, winner, price, bid_count } (the attested enclave output)

  This file mirrors the pattern from `TransferMessages.lean`:
    * structured records on the Lean side,
    * an axiomatic `serializeResolveMessage : ResolveMessage → ByteSeq`,
    * a `serializeResolveMessage_inj` injectivity axiom,
    * a `userDataOfResolveMessage` definition composing
      `commitHashBytes` from `RawMessages.lean`.

  Modelling choices:
    * `Uint128` aliased to `Nat` via the same `notation` pattern as
      `TransferMessages.lean` — no redeclaration here. Auction prices
      are reasoned about over total `Nat` arithmetic.
    * `Addr` reused from `UserDataCommit.lean`.
    * The bid `ciphertext` is an opaque `ByteSeq` — the enclave is
      the only party that can decrypt it, and that decryption is
      modelled as an axiomatic function in `AuctionDeterminism.lean`.
-/

import Mathlib.Logic.Function.Basic
import Specs.Quartz.Crypto.UserDataCommit
import Specs.Quartz.Crypto.RawMessages
import Specs.Quartz.Crypto.TransferMessages
import Specs.Quartz.Attestation.Dstack

namespace Specs.Quartz.Crypto

open Specs.Quartz.Attestation.Dstack

/-- Spec-level mirror of a sealed bid submission on the chain.

    `bidder` is the bidder's address; `ciphertext` is the opaque
    ECIES-encrypted blob holding the plaintext bid amount. The
    contract stores this verbatim — it cannot decrypt. -/
structure SealedBid where
  bidder     : Addr
  ciphertext : ByteSeq

/-- Spec-level mirror of `ResolveMsg` produced by the enclave.

    This is the message the enclave attests over and the contract
    consumes to settle a round. Fields mirror the Rust struct
    `ResolveMsg { round_id, winner, price, bid_count }` from
    `examples/sealed-auction/contracts/src/msg.rs`.

    `winner = none` represents the "no valid bid" branch (no bidder
    cleared the reserve). `price` is the second-price amount the
    enclave computed; `bidCount` is the number of sealed-bid
    submissions seen by the enclave. -/
structure ResolveMessage where
  roundId  : Nat
  winner   : Option Addr
  price    : Uint128
  bidCount : Nat

/-- **Trust-boundary axiom**: serde_json serialization of a
    `ResolveMessage`. Opaque at the spec level — we only need
    injectivity. Same caveat as `serializeTransferRequest`. -/
axiom serializeResolveMessage : ResolveMessage → ByteSeq

/-- **Trust-boundary axiom (serde-injectivity)**: serde_json's
    encoding of `ResolveMessage` is injective.

    Honest reading: cw_serde-derived JSON encodings of distinct
    `ResolveMessage` values produce distinct byte strings. Same
    caveat as `serializeTransferRequest_inj`: discharging would
    require modelling the JSON grammar and the cw_serde macro
    expansion. -/
axiom serializeResolveMessage_inj :
  Function.Injective serializeResolveMessage

/-- `user_data` produced by the contract / enclave from a
    `ResolveMessage`, matching the canonical Rust path

        Sha256(serde_json::to_string(&resolve_msg))

    composed with the trailing-32-byte-zero padding the Rust code
    applies. `noncomputable` because `commitHashBytes` is an axiom. -/
noncomputable def userDataOfResolveMessage (m : ResolveMessage) : UserData :=
  commitHashBytes (serializeResolveMessage m)

/-- **Structural correspondence**: distinct `ResolveMessage`s
    produce distinct `user_data`. Composition of
    `serializeResolveMessage_inj` and `commitHashBytes_inj`. -/
theorem distinct_resolve_message_gives_distinct_user_data
    (m1 m2 : ResolveMessage) (hne : m1 ≠ m2) :
    userDataOfResolveMessage m1 ≠ userDataOfResolveMessage m2 := by
  intro h
  apply hne
  exact serializeResolveMessage_inj (commitHashBytes_inj h)

/-- Injectivity of `userDataOfResolveMessage` repackaged as a
    `Function.Injective` statement. -/
theorem userDataOfResolveMessage_inj :
    Function.Injective userDataOfResolveMessage := by
  intro m1 m2 h
  exact serializeResolveMessage_inj (commitHashBytes_inj h)

end Specs.Quartz.Crypto
