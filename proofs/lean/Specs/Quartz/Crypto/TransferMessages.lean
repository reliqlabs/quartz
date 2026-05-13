/-
  Trust boundary: bridge from abstract `UserDataCommit` to the
  concrete Rust transfer message types (examples/transfers).

  In Rust (`examples/transfers/contracts/src/msg.rs`), the user-side
  inputs that drive enclave balance updates are:

      Deposit                                   (no msg body — sender is the tx signer)
      Withdraw                                  (no msg body — sender is the tx signer)
      ClearTextTransferRequestMsg { sender, receiver, amount }

  And the encrypted-transfer path goes through `TransferRequestMsg`
  whose ciphertext the enclave decrypts to a `(sender, receiver,
  amount)` tuple. At the spec level we collapse these to three
  uniform `Raw{Deposit,Withdraw,Transfer}` structs, mirroring the
  serialization layer's `user_data` contract.

  The pattern mirrors `RawMessages.lean` for the handshake side:
    * structured `Raw…` records,
    * an axiomatic `serialize…` byte encoding,
    * a `serialize…_inj` injectivity axiom,
    * a `userDataOf…` definition composing `commitHashBytes`.

  Modelling choices:
    * `Uint128` → `Nat`. The conservation theorem is purely additive;
      bit-widths are irrelevant here. Saturating arithmetic on `Uint128`
      reduces to total addition / monus on `Nat`.
    * `Addr` reused from `UserDataCommit.lean` (the same abstract type
      already used for the handshake's contract address field).
-/

import Mathlib.Logic.Function.Basic
import Specs.Quartz.Crypto.UserDataCommit
import Specs.Quartz.Crypto.RawMessages
import Specs.Quartz.Attestation.Dstack

namespace Specs.Quartz.Crypto

open Specs.Quartz.Attestation.Dstack

/-- Spec-level model of `cosmwasm_std::Uint128`.

    The transfers conservation theorem reasons about addition and
    monus over balances, not concrete 128-bit widths, so we collapse
    `Uint128` to `Nat`. The on-chain Rust code rejects overflow at the
    Uint128 boundary (via `checked_add`/`checked_sub`); at this spec
    level all arithmetic is total on `Nat`.

    NOTE: in current Lean (4.30) `omega`'s atom extraction does not
    see through `abbrev`/`@[reducible] def` type synonyms over `Nat`
    even when the synonym is syntactically transparent (the variables
    are reported as type `Uint128`, not `Nat`, and omega treats the
    additive expressions as opaque atoms). We therefore alias
    `Uint128` to `Nat` via plain `notation` rather than introducing a
    new type — this keeps signatures readable while letting `omega`
    operate on bare `Nat`. -/
notation "Uint128" => Nat

/-- Lean mirror of an abstract `Deposit { account, amount }` request. -/
structure RawDeposit where
  account : Addr
  amount  : Uint128

/-- Lean mirror of an abstract `Withdraw { account, amount }` request.

    In the Rust contract a withdrawal drains the account's full
    balance; we still carry an `amount` field at this layer so the
    conservation lemma can reason about an arbitrary decrement. The
    `applyWithdraw` definition consumes the entire balance and
    ignores the amount, exactly matching the Rust semantics. -/
structure RawWithdraw where
  account : Addr
  amount  : Uint128

/-- Lean mirror of `ClearTextTransferRequestMsg { sender, receiver,
    amount }` (or the post-decryption form of `TransferRequestMsg`). -/
structure RawTransfer where
  sender    : Addr
  recipient : Addr
  amount    : Uint128

/-- Union of the three transfer requests, mirroring the `Request`
    enum in `examples/transfers/contracts/src/msg.rs`:

        pub enum Request {
            Transfer(HexBinary),
            Withdraw(Addr),
            Deposit(Addr, Uint128),
        }
-/
inductive TransferRequest : Type
  | deposit  (r : RawDeposit)  : TransferRequest
  | withdraw (r : RawWithdraw) : TransferRequest
  | transfer (r : RawTransfer) : TransferRequest

/-- **Trust-boundary axiom**: serde_json serialization of a
    `TransferRequest`. Opaque at the spec level — we only need
    injectivity. -/
axiom serializeTransferRequest : TransferRequest → ByteSeq

/-- **Trust-boundary axiom (serde-injectivity)**: serde_json's
    encoding of `TransferRequest` is injective.

    Honest reading: cw_serde-derived JSON encodings of distinct
    enum tags or distinct field tuples produce distinct byte
    strings. Same caveat as `serializeRawSessionCreate_inj`:
    proving it would require modelling the JSON grammar and the
    cw_serde macro expansion. -/
axiom serializeTransferRequest_inj :
  Function.Injective serializeTransferRequest

/-- `user_data` produced by the contract / enclave from a
    `TransferRequest`, matching the path

        Sha256(serde_json::to_string(&request))

    composed with the trailing-32-byte-zero padding the Rust code
    applies. Spec-level definition — `noncomputable` because
    `commitHashBytes` is an axiom. -/
noncomputable def userDataOfTransferRequest (req : TransferRequest) : UserData :=
  commitHashBytes (serializeTransferRequest req)

/-- **Structural correspondence**: distinct `TransferRequest`s
    produce distinct `user_data`.

    Proof: composition of `serializeTransferRequest_inj` and
    `commitHashBytes_inj`. This is the property the contract
    handler relies on when it compares `msg.user_data() ==
    attestation.user_data()`. -/
theorem distinct_transfer_request_gives_distinct_user_data
    (r1 r2 : TransferRequest) (hne : r1 ≠ r2) :
    userDataOfTransferRequest r1 ≠ userDataOfTransferRequest r2 := by
  intro h
  apply hne
  exact serializeTransferRequest_inj (commitHashBytes_inj h)

/-- Injectivity of `userDataOfTransferRequest` repackaged as a
    `Function.Injective` statement. -/
theorem userDataOfTransferRequest_inj :
    Function.Injective userDataOfTransferRequest := by
  intro r1 r2 h
  exact serializeTransferRequest_inj (commitHashBytes_inj h)

end Specs.Quartz.Crypto
