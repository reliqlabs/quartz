/-
  Composition layer: Quartz handshake soundness (stretch).

  Glues the trust-boundary specs:

    * `Specs.Quartz.Crypto.Ecies`           (enclave key custody)
    * `Specs.Quartz.Crypto.UserDataCommit`  (user_data → ECIES pubkey)
    * `Specs.Quartz.Attestation.Dstack`     (TDX quote → user_data)
    * `Specs.Quartz.Attestation.Zkdcap`     (Groth16 → quote)

  The goal at this layer is to establish that, given the four
  trust-boundary axioms, an on-chain `DstackZkAttestation` accepted
  by the contract authentically binds the enclave's published ECIES
  public key to the user-data field of a dstack-signed TDX quote.

  The handler's contract-side checks (in
  `crates/contracts/core/src/handler/execute/attested.rs`):

    1. ZK module accepts the proof  (`verifyGroth16 ... = true`).
    2. `msg.user_data() == attestation.user_data()`.
    3. `config.mr_enclave() == attestation.mr_enclave()`.

  We model the contract-side outcome as a single proposition and
  prove the soundness composition.
-/

import Specs.Quartz.Crypto.Ecies
import Specs.Quartz.Crypto.UserDataCommit
import Specs.Quartz.Attestation.Dstack
import Specs.Quartz.Attestation.Zkdcap

namespace Specs.Quartz.Protocol.Handshake

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap

/-- A pending handshake check, exactly mirroring the three contract
    predicates from `Attested<M,A>::handle`. -/
structure HandshakeCheck where
  proof          : Groth16Proof
  inputs         : PublicInputs
  /-- The MR_ENCLAVE declared by the contract's configured `Config`. -/
  expectedMr     : MrEnclave
  /-- The `user_data` carried by the inbound message. -/
  msgUserData    : UserData

/-- The contract's combined acceptance predicate. Mirror of the
    boolean conjunction the `Attested` handler enforces. -/
def Accepted (h : HandshakeCheck) : Prop :=
  verifyGroth16 zkdcapVKey h.proof h.inputs = true ∧
  mrEnclaveOf (inputs_to_quote h.inputs) = some h.expectedMr ∧
  userDataOf (inputs_to_quote h.inputs) = some h.msgUserData

/-- **Soundness of handshake acceptance**.

    If the contract accepts the handshake, then there exists a
    dstack-signed TDX quote whose MR_ENCLAVE and user_data match
    the contract-declared and message-declared values respectively.

    This composes all three trust-boundary axioms into a single
    consumable lemma for downstream protocol reasoning. -/
theorem handshake_sound (h : HandshakeCheck) (acc : Accepted h) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q  = some h.msgUserData := by
  obtain ⟨hZk, hMr, hUd⟩ := acc
  refine ⟨inputs_to_quote h.inputs, ?_, hMr, hUd⟩
  exact verifyGroth16_sound h.proof h.inputs hZk

/-- **Corollary (ECIES key custody, commitment-discharged)**.

    If the handshake is accepted *and* the in-quote `user_data` is
    the structured commitment `commitHash c` for some
    `UserDataCommit c`, then:

      1. there is a dstack-signed quote bearing that user_data, and
      2. the extracted ECIES pubkey is exactly `c.eciesPubkey`, and
      3. any plaintext encrypted to the extracted pubkey can be
         decrypted by any private key whose verifying key matches
         `c.eciesPubkey`.

    Note: relative to the earlier scaffold, the `pkOfUserData` map
    and its `= some pk` hypothesis are no longer parameters — they
    are now discharged constructively via `pkOfUserData_commitHash`
    from `UserDataCommit.lean`. The only remaining trust-boundary
    assumption used in this chain is `commitHash_inj`. -/
theorem handshake_binds_ecies_key
    (h : HandshakeCheck) (acc : Accepted h)
    (c : UserDataCommit)
    (h_commit : h.msgUserData = commitHash c)
    (sk : PrivKey)
    (h_sk : keyOf sk = c.eciesPubkey)
    (pt : Plaintext) :
    (∃ q, was_signed_by_dstack q ∧ userDataOf q = some h.msgUserData) ∧
    pkOfUserData h.msgUserData = some c.eciesPubkey ∧
    decrypt sk (encrypt c.eciesPubkey pt) = some pt := by
  refine ⟨?_, ?_, ?_⟩
  · obtain ⟨q, hq, _, hUd⟩ := handshake_sound h acc
    exact ⟨q, hq, hUd⟩
  · rw [h_commit]; exact pkOfUserData_commitHash c
  · rw [← h_sk]; exact roundtrip sk pt

end Specs.Quartz.Protocol.Handshake
