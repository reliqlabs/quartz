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
import Specs.Quartz.Attestation.DcapVerifier
import Specs.Quartz.Attestation.Zkdcap

namespace Specs.Quartz.Protocol.Handshake

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.DcapVerifier
open Specs.Quartz.Attestation.Zkdcap

/-- A pending handshake check, exactly mirroring the three contract
    predicates from `Attested<M,A>::handle`. -/
structure HandshakeCheck (n : Nat) where
  proof          : Groth16Proof
  inputs         : PublicInputs
  /-- The MR_ENCLAVE declared by the contract's configured `Config`. -/
  expectedMr     : MrEnclave
  /-- The `user_data` carried by the inbound message. -/
  msgUserData    : UserData n

/-- The contract's combined acceptance predicate. Mirror of the
    boolean conjunction the `Attested` handler enforces. -/
def Accepted {n : Nat} (h : HandshakeCheck n) : Prop :=
  -- NeZero needed for `userDataOf n` and `mrEnclaveOf n` (tdxVerifier axiom).
  verifyGroth16 zkdcapVKey h.proof h.inputs = true ∧
  mrEnclaveOf n (inputs_to_quote h.inputs) = some h.expectedMr ∧
  userDataOf n (inputs_to_quote h.inputs) = some h.msgUserData

/-- **Soundness of handshake acceptance**.

    If the contract accepts the handshake, then there exists a
    dstack-signed TDX quote whose MR_ENCLAVE and user_data match
    the contract-declared and message-declared values respectively.

    This composes all three trust-boundary axioms into a single
    consumable lemma for downstream protocol reasoning. -/
theorem handshake_sound {n : Nat} (h : HandshakeCheck n) (acc : Accepted h) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf n q = some h.expectedMr ∧
      userDataOf n q  = some h.msgUserData := by
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
    {n : Nat} (h : HandshakeCheck n) (acc : Accepted h)
    (c : UserDataCommit)
    (h_commit : h.msgUserData = commitHash n c)
    (sk : PrivKey)
    (h_sk : keyOf sk = c.eciesPubkey)
    (pt : Plaintext) :
    (∃ q, was_signed_by_dstack q ∧ userDataOf n q = some h.msgUserData) ∧
    pkOfUserData n h.msgUserData = some c.eciesPubkey ∧
    decrypt sk (encrypt c.eciesPubkey pt) = some pt := by
  refine ⟨?_, ?_, ?_⟩
  · obtain ⟨q, hq, _, hUd⟩ := handshake_sound h acc
    exact ⟨q, hq, hUd⟩
  · rw [h_commit]; exact pkOfUserData_commitHash n c
  · rw [← h_sk]; exact roundtrip sk pt

/-- **Cycle 7.15: byte-binding extension of `handshake_sound`**.

    Strengthens `handshake_sound`'s conclusion with the cycle 7.13
    binding theorem: the contract-declared `expectedMr` is provably
    equal to a specific pair of `extractBitVec` extractions on the
    first 632 bytes of the witness quote. This is the FIRST Protocol-
    layer consumer of the cycle 7.7/7.9/7.10/7.13 parser-pinning chain
    — it closes the cycle-7.5-7.13 review finding H1 ("binding
    theorems are dead weight; no Protocol/* consumes them").

    Audit consequence: a downstream auditor reading the closure of
    `handshake_sound_pinned` will see the chain of parser-binding
    axioms (`parseDcapQuote_mrTd_eq`, `parseDcapQuote_rtmr3_eq`,
    `parseDcapQuote_reportData_eq`, `extractBitVec_take`) as
    load-bearing — confirming that the contract-side `expectedMr`
    check binds enclave identity to actual quote bytes, not to
    parser-chosen fields. -/
theorem handshake_sound_pinned {n : Nat} (h : HandshakeCheck n) (acc : Accepted h) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf n q = some h.expectedMr ∧
      userDataOf n q = some h.msgUserData ∧
      h.expectedMr = (extractBitVec (q.take 632) 184 384,
                      extractBitVec (q.take 632) 520 384) := by
  obtain ⟨q, hq, hMr, hUd⟩ := handshake_sound h acc
  refine ⟨q, hq, hMr, hUd, ?_⟩
  -- Unfold mrEnclaveOf to get ∃ ud, verifyTdxQuote n q = some (h.expectedMr, ud)
  -- and verifyTdxQuote = dcapTdxVerifier.verify = verifyDcap n q productionCollateral.
  simp only [mrEnclaveOf, verifyTdxQuote, tdxVerifier, dcapTdxVerifier,
    Option.map_eq_some_iff] at hMr
  obtain ⟨⟨mr_pair, ud⟩, h_verify, h_eq⟩ := hMr
  -- h_verify : verifyDcap n q productionCollateral = some (mr_pair, ud)
  -- h_eq : mr_pair = h.expectedMr
  rw [← h_eq]
  exact (verifyDcap_output_committed_by_signed_region n q
    productionCollateral mr_pair ud h_verify).1

end Specs.Quartz.Protocol.Handshake
