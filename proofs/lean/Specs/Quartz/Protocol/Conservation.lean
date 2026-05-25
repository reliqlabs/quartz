/-
  Cross-component conservation theorem for the transfers example.

  Analog of `CrossComponent.cross_component_session_bind` for the
  funds-conservation invariant of `examples/transfers/`. Lifts the
  Quint-proved `inv_conservation` (sum_of_balances == total_supply)
  up into the attestation-discipline framework.

  Modelling: fixed 3-address universe (alice/bob/carol), balances
  as a 4-field record over `Uint128 := Nat`. No new cryptographic
  axioms; only `addrOf` / `addrOf_inj` for the Account→Addr
  projection.
-/

import Specs.Quartz.Crypto.Ecies
import Specs.Quartz.Crypto.UserDataCommit
import Specs.Quartz.Crypto.RawMessages
import Specs.Quartz.Crypto.TransferMessages
import Specs.Quartz.Attestation.Dstack
import Specs.Quartz.Attestation.DcapVerifier
import Specs.Quartz.Attestation.Zkdcap
import Specs.Quartz.Protocol.Handshake

namespace Specs.Quartz.Protocol.Conservation

open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.DcapVerifier
open Specs.Quartz.Attestation.Zkdcap
open Specs.Quartz.Protocol.Handshake

/-- The three accounts: alice/bob/carol from `transfers.qnt`. -/
inductive Account : Type | alice | bob | carol
deriving DecidableEq, Repr

/-- `Account → Addr` projection (structural axiom). -/
axiom addrOf : Account → Addr
axiom addrOf_inj : Function.Injective addrOf

/-- The enclave's ghost balance state. Mirrors Quint `EnclaveState`. -/
structure EnclaveBalances where
  alice : Uint128
  bob : Uint128
  carol : Uint128
  totalSupply : Uint128

namespace EnclaveBalances

def get (b : EnclaveBalances) : Account → Uint128
  | .alice => b.alice | .bob => b.bob | .carol => b.carol

def sumOfBalances (b : EnclaveBalances) : Uint128 :=
  b.alice + b.bob + b.carol

end EnclaveBalances

/-- Conservation: sum_of_balances == total_supply. -/
def conservationInvariant (b : EnclaveBalances) : Prop :=
  b.sumOfBalances = b.totalSupply

/-- Resolve an abstract `Addr` to one of our three accounts. -/
noncomputable def accountOfAddr (a : Addr) : Option Account :=
  open Classical in
  if h : ∃ acc : Account, addrOf acc = a then some (Classical.choose h)
  else none

/-! Each apply-operation has a `…Resolved` form (taking an
    `Account`) for closed-form arithmetic, and a top-level form
    resolving the abstract address first. -/

def applyDepositResolved
    (b : EnclaveBalances) (acc : Account) (amount : Uint128) : EnclaveBalances :=
  match acc with
  | .alice => { b with alice := b.alice + amount, totalSupply := b.totalSupply + amount }
  | .bob   => { b with bob   := b.bob   + amount, totalSupply := b.totalSupply + amount }
  | .carol => { b with carol := b.carol + amount, totalSupply := b.totalSupply + amount }

noncomputable def applyDeposit
    (b : EnclaveBalances) (r : RawDeposit) : Option EnclaveBalances :=
  (accountOfAddr r.account).map (applyDepositResolved b · r.amount)

def applyWithdrawResolved
    (b : EnclaveBalances) (acc : Account) : EnclaveBalances :=
  match acc with
  | .alice => { b with alice := 0, totalSupply := b.totalSupply - b.alice }
  | .bob   => { b with bob   := 0, totalSupply := b.totalSupply - b.bob   }
  | .carol => { b with carol := 0, totalSupply := b.totalSupply - b.carol }

/-- Withdraw is "drain all"; the request's `amount` field is ignored. -/
noncomputable def applyWithdraw
    (b : EnclaveBalances) (r : RawWithdraw) : Option EnclaveBalances :=
  (accountOfAddr r.account).map (applyWithdrawResolved b ·)

/-- Diagonal `s = d` cases are unreachable under the caller's guard. -/
def applyTransferResolved
    (b : EnclaveBalances) (s d : Account) (amount : Uint128) : EnclaveBalances :=
  match s, d with
  | .alice, .bob   => { b with alice := b.alice - amount, bob   := b.bob   + amount }
  | .alice, .carol => { b with alice := b.alice - amount, carol := b.carol + amount }
  | .bob,   .alice => { b with bob   := b.bob   - amount, alice := b.alice + amount }
  | .bob,   .carol => { b with bob   := b.bob   - amount, carol := b.carol + amount }
  | .carol, .alice => { b with carol := b.carol - amount, alice := b.alice + amount }
  | .carol, .bob   => { b with carol := b.carol - amount, bob   := b.bob   + amount }
  | .alice, .alice | .bob, .bob | .carol, .carol => b

/-- Transfer rejects if sender == recipient, amount == 0, or sender < amount. -/
noncomputable def applyTransfer
    (b : EnclaveBalances) (r : RawTransfer) : Option EnclaveBalances :=
  match accountOfAddr r.sender, accountOfAddr r.recipient with
  | some s, some d =>
    if s = d then none
    else if r.amount = 0 then none
    else if b.get s < r.amount then none
    else some (applyTransferResolved b s d r.amount)
  | _, _ => none

/-! ### Conservation preservation lemmas -/

theorem applyDepositResolved_preserves_conservation
    (b : EnclaveBalances) (acc : Account) (amount : Uint128)
    (hInv : conservationInvariant b) :
    conservationInvariant (applyDepositResolved b acc amount) := by
  cases acc <;>
    (simp only [conservationInvariant, EnclaveBalances.sumOfBalances,
                applyDepositResolved] at hInv ⊢
     omega)

theorem applyDeposit_preserves_conservation
    (b : EnclaveBalances) (r : RawDeposit) (b' : EnclaveBalances)
    (hInv : conservationInvariant b)
    (hApp : applyDeposit b r = some b') :
    conservationInvariant b' := by
  unfold applyDeposit at hApp
  cases hAcc : accountOfAddr r.account with
  | none => rw [hAcc] at hApp; cases hApp
  | some acc =>
    rw [hAcc, Option.map_some] at hApp
    simp only [Option.some.injEq] at hApp
    subst hApp
    exact applyDepositResolved_preserves_conservation b acc r.amount hInv

theorem applyWithdrawResolved_preserves_conservation
    (b : EnclaveBalances) (acc : Account)
    (hInv : conservationInvariant b) :
    conservationInvariant (applyWithdrawResolved b acc) := by
  cases acc <;>
    (simp only [conservationInvariant, EnclaveBalances.sumOfBalances,
                applyWithdrawResolved] at hInv ⊢
     omega)

theorem applyWithdraw_preserves_conservation
    (b : EnclaveBalances) (r : RawWithdraw) (b' : EnclaveBalances)
    (hInv : conservationInvariant b)
    (hApp : applyWithdraw b r = some b') :
    conservationInvariant b' := by
  unfold applyWithdraw at hApp
  cases hAcc : accountOfAddr r.account with
  | none => rw [hAcc] at hApp; cases hApp
  | some acc =>
    rw [hAcc, Option.map_some] at hApp
    simp only [Option.some.injEq] at hApp
    subst hApp
    exact applyWithdrawResolved_preserves_conservation b acc hInv

theorem applyTransferResolved_preserves_conservation
    (b : EnclaveBalances) (s d : Account) (amount : Uint128)
    (hSuff : amount ≤ b.get s)
    (hInv : conservationInvariant b) :
    conservationInvariant (applyTransferResolved b s d amount) := by
  cases s <;> cases d <;>
    (simp only [conservationInvariant, EnclaveBalances.sumOfBalances,
                EnclaveBalances.get, applyTransferResolved] at hInv hSuff ⊢
     omega)

theorem applyTransfer_preserves_conservation
    (b : EnclaveBalances) (r : RawTransfer) (b' : EnclaveBalances)
    (hInv : conservationInvariant b)
    (hApp : applyTransfer b r = some b') :
    conservationInvariant b' := by
  unfold applyTransfer at hApp
  cases hS : accountOfAddr r.sender with
  | none => rw [hS] at hApp; cases hApp
  | some s =>
  cases hD : accountOfAddr r.recipient with
  | none => rw [hS, hD] at hApp; cases hApp
  | some d =>
  rw [hS, hD] at hApp
  by_cases hsd : s = d
  · simp only [hsd, if_true] at hApp; cases hApp
  by_cases hAmt : r.amount = 0
  · simp only [hsd, if_false, hAmt, if_true] at hApp; cases hApp
  by_cases hLt : b.get s < r.amount
  · simp only [hsd, hAmt, hLt, if_false, if_true] at hApp; cases hApp
  simp only [hsd, hAmt, hLt, if_false, Option.some.injEq] at hApp
  subst hApp
  exact applyTransferResolved_preserves_conservation b s d r.amount
    (Nat.le_of_not_lt hLt) hInv

/-- Apply any `TransferRequest`. -/
noncomputable def applyTransferRequest
    (b : EnclaveBalances) : TransferRequest → Option EnclaveBalances
  | .deposit  r => applyDeposit  b r
  | .withdraw r => applyWithdraw b r
  | .transfer r => applyTransfer b r

/-- Combined conservation preservation across all three operations. -/
theorem applyTransferRequest_preserves_conservation
    (b : EnclaveBalances) (req : TransferRequest) (b' : EnclaveBalances)
    (hInv : conservationInvariant b)
    (hApp : applyTransferRequest b req = some b') :
    conservationInvariant b' := by
  cases req with
  | deposit r  => exact applyDeposit_preserves_conservation  b r b' hInv hApp
  | withdraw r => exact applyWithdraw_preserves_conservation b r b' hInv hApp
  | transfer r => exact applyTransfer_preserves_conservation b r b' hInv hApp

/-- **Cross-component transfers conservation (loop-closing theorem).**

    Mirrors `CrossComponent.cross_component_session_bind` but binds
    the conservation invariant (instead of the ECIES key) across
    the contract/enclave boundary.

    Proof chain:
      * `handshake_sound` — attestation discipline
      * `h_raw` — message-integrity witness (commitment binding)
      * `applyTransferRequest_preserves_conservation` — step

    No new axioms; pure composition. -/
theorem cross_component_transfers_conservation
    {n : Nat} (h : HandshakeCheck n) (acc : Accepted h)
    (req : TransferRequest)
    (h_raw : h.msgUserData = userDataOfTransferRequest n req)
    (b : EnclaveBalances)
    (hInv : conservationInvariant b)
    (b' : EnclaveBalances)
    (hApp : applyTransferRequest b req = some b') :
    (∃ q : TdxQuote,
        was_signed_by_dstack q ∧
        mrEnclaveOf n q = some h.expectedMr ∧
        userDataOf n q  = some (userDataOfTransferRequest n req)) ∧
    conservationInvariant b' := by
  obtain ⟨q, hSigned, hMr, hUd⟩ := handshake_sound h acc
  refine ⟨⟨q, hSigned, hMr, ?_⟩, ?_⟩
  · rw [hUd, h_raw]
  · exact applyTransferRequest_preserves_conservation b req b' hInv hApp

/-- **Cycle 7.17: byte-binding extension of
    `cross_component_transfers_conservation`**. Adds the cycle 7.13
    pinning of `expectedMr` to byte extractions on the signed prefix
    of the witness quote. Fourth Protocol-layer consumer of the
    parser-pinning chain. -/
theorem cross_component_transfers_conservation_pinned
    {n : Nat} (h : HandshakeCheck n) (acc : Accepted h)
    (req : TransferRequest)
    (h_raw : h.msgUserData = userDataOfTransferRequest n req)
    (b : EnclaveBalances)
    (hInv : conservationInvariant b)
    (b' : EnclaveBalances)
    (hApp : applyTransferRequest b req = some b') :
    (∃ q : TdxQuote,
        was_signed_by_dstack q ∧
        mrEnclaveOf n q = some h.expectedMr ∧
        userDataOf n q  = some (userDataOfTransferRequest n req) ∧
        h.expectedMr = (extractBitVec (q.take 632) 184 384,
                        extractBitVec (q.take 632) 520 384)) ∧
    conservationInvariant b' := by
  obtain ⟨q, hSigned, hMr, hUd, hMrPin⟩ := handshake_sound_pinned h acc
  refine ⟨⟨q, hSigned, hMr, ?_, hMrPin⟩, ?_⟩
  · rw [hUd, h_raw]
  · exact applyTransferRequest_preserves_conservation b req b' hInv hApp

end Specs.Quartz.Protocol.Conservation
