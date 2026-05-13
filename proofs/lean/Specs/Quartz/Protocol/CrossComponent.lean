/-
  Cross-component loop-closing theorem.

  This file states the single end-to-end property that ties together
  the *contract side* (Verus-verified `Attested<M,A>` handler) and the
  *enclave side* (Verus-verified `session_set_pub_key.rs`) of the
  Quartz handshake.

  Each side has been specified independently:

    * Contract side: `Handshake.handshake_sound` /
      `Handshake.handshake_binds_ecies_key` show that contract
      acceptance of a `DstackZkAttestation` yields a dstack-signed
      TDX quote whose `user_data` matches `msg.user_data()`.

    * Enclave side: `RawMessages.userData_session_set_pub_key_binds_ecies`
      shows that the enclave's canonical `user_data` construction
      (`Sha256(serde_json::to_string(&RawSessionSetPubKey { nonce,
      pub_key }))`) is an injective commitment that exposes the
      committed ECIES pubkey via `pkOfUserData`.

    * Crypto: `Ecies.roundtrip` is the ECIES-correctness axiom.

  The two protocol sides have, until now, only been proven to satisfy
  their own contracts in isolation. The theorem below states their
  composition: any `Accepted` handshake whose `user_data` *was*
  produced by the enclave's canonical `RawSessionSetPubKey` encoding
  binds the published ECIES key to a dstack-attested enclave that
  holds the matching private key. This is the formal expression of
  "contract and enclave speak the same protocol".

  No new axioms are introduced. The proof is pure composition.
-/

import Specs.Quartz.Crypto.Ecies
import Specs.Quartz.Crypto.UserDataCommit
import Specs.Quartz.Crypto.RawMessages
import Specs.Quartz.Attestation.Dstack
import Specs.Quartz.Attestation.Zkdcap
import Specs.Quartz.Protocol.Handshake
import Specs.Quartz.Protocol.Confidentiality

namespace Specs.Quartz.Protocol.CrossComponent

open Specs.Quartz.Crypto.Ecies
open Specs.Quartz.Crypto
open Specs.Quartz.Attestation.Dstack
open Specs.Quartz.Attestation.Zkdcap
open Specs.Quartz.Protocol.Handshake

/-- **Cross-component session bind (loop-closing theorem).**

    Hypotheses:

      * `h : HandshakeCheck` — the three-field record mirroring the
        contract's `Attested<M,A>::handle` predicates (proof, public
        inputs, expected MR_ENCLAVE, message user_data).
      * `acc : Accepted h` — the contract accepted the inbound
        `DstackZkAttestation` (i.e. ZK verifier accepted, MR_ENCLAVE
        matched the configured one, and `msg.user_data ==
        attestation.user_data`).
      * `raw : RawSessionSetPubKey` — the concrete Rust struct the
        enclave hashed into `user_data` via
        `Sha256(serde_json::to_string(&raw))`.
      * `h_raw : h.msgUserData = userDataOfSessionSetPubKey raw` —
        the witness that the `user_data` carried on-chain is exactly
        the canonical commitment produced by the enclave for this
        `raw`. Concretely this is what
        `crates/enclave/core/src/msg/execute/session_set_pub_key.rs`
        emits.
      * `sk : PrivKey` — the ECIES signing key the enclave holds
        inside dstack (never leaves the TEE).
      * `h_sk : keyOf sk = raw.pubKey` — the enclave-side custody
        invariant that `sk`'s verifying key is what the enclave
        published.

    Conclusion (conjunction):

      1. There exists a dstack-signed TDX quote `q`.
      2. `q`'s measurement matches the contract-configured MR_ENCLAVE.
      3. `q`'s `user_data` matches the inbound message's `user_data`.
      4. `pkOfUserData` extracts `raw.pubKey` from the on-chain
         `user_data` — i.e. the contract's discipline pins the
         published ECIES key.
      5. Any plaintext encrypted under `raw.pubKey` decrypts under
         the enclave-held `sk`.

    The proof is pure composition: `handshake_sound` discharges
    (1)–(3); `userData_session_set_pub_key_binds_ecies` rewritten
    through `h_raw` discharges (4); `Ecies.roundtrip` rewritten
    through `h_sk` discharges (5). No new axioms are needed. -/
theorem cross_component_session_bind
    (h : HandshakeCheck) (acc : Accepted h)
    (raw : RawSessionSetPubKey)
    (h_raw : h.msgUserData = userDataOfSessionSetPubKey raw)
    (sk : PrivKey) (h_sk : keyOf sk = raw.pubKey) :
    ∃ q : TdxQuote,
      was_signed_by_dstack q ∧
      mrEnclaveOf q = some h.expectedMr ∧
      userDataOf q = some h.msgUserData ∧
      pkOfUserData h.msgUserData = some raw.pubKey ∧
      (∀ msg : Plaintext, decrypt sk (encrypt raw.pubKey msg) = some msg) := by
  obtain ⟨q, hSigned, hMr, hUd⟩ := handshake_sound h acc
  refine ⟨q, hSigned, hMr, hUd, ?_, ?_⟩
  · rw [h_raw]
    exact userData_session_set_pub_key_binds_ecies raw
  · intro msg
    rw [← h_sk]
    exact roundtrip sk msg

end Specs.Quartz.Protocol.CrossComponent
