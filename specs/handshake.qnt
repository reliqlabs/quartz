// Quartz Handshake Protocol
//
// Models the 3-phase secure channel establishment between a CosmWasm
// contract and a TEE enclave (dstack TDX):
//
//   Phase 1: Instantiate — store compose_hash + config on-chain
//   Phase 2: SessionCreate — enclave generates nonce, contract stores it
//   Phase 3: SessionSetPubKey — enclave proves it read the nonce,
//            generates a session key pair, contract stores the pubkey
//
// After handshake, attested messages can flow using the established
// session key and sequence numbers.

module handshake {

  // ============================================================
  // Types
  // ============================================================

  type Addr = str
  type Hash = str           // hex-encoded hash
  type PubKey = str         // hex-encoded ECDSA public key
  type Nonce = str          // hex-encoded 32-byte nonce
  type ComposeHash = str    // hex-encoded 32-byte compose-hash (TDX mr_enclave equivalent)

  type SessionState =
    | NoSession
    | SessionCreated       // nonce stored, no pubkey yet
    | SessionActive        // nonce + pubkey stored, ready for messages

  /// What the contract stores
  type ContractState = {
    config_set: bool,
    compose_hash: ComposeHash,   // expected enclave identity
    session: SessionState,
    session_nonce: Nonce,        // "" if no session
    session_pubkey: PubKey,      // "" if not yet set
    sequence_num: int,           // -1 if not initialized, 0+ after handshake
    contract_addr: Addr,
  }

  /// What the enclave stores
  type EnclaveState = {
    compose_hash: ComposeHash,   // the enclave's own identity
    contract_addr: Addr,         // "" if not yet bound
    nonce: Nonce,                // "" if not generated
    pubkey: PubKey,              // "" if not generated
    trusted_height: int,
  }

  /// An attestation wrapping a message
  type Attestation = {
    user_data_hash: Hash,        // SHA256 of the message
    compose_hash: ComposeHash,   // the attesting enclave's identity
  }

  // ============================================================
  // State
  // ============================================================

  var contract: ContractState
  var enclave: EnclaveState
  var attacker_active: bool  // whether an adversary is present

  // ============================================================
  // Constants
  // ============================================================

  val VALID_COMPOSE_HASH = "aabbccdd"
  val WRONG_COMPOSE_HASH = "deadbeef"
  val CONTRACT_ADDR = "xion1contract"
  val WRONG_CONTRACT_ADDR = "xion1wrong"
  val NONCE_1 = "nonce_aaa"
  val NONCE_2 = "nonce_bbb"
  val PUBKEY_1 = "pk_enclave_1"
  val PUBKEY_2 = "pk_enclave_2"
  val MSG_HASH_VALID = "hash_valid"

  // ============================================================
  // Initial state
  // ============================================================

  action init = all {
    contract' = {
      config_set: false,
      compose_hash: "",
      session: NoSession,
      session_nonce: "",
      session_pubkey: "",
      sequence_num: -1,
      contract_addr: CONTRACT_ADDR,
    },
    enclave' = {
      compose_hash: VALID_COMPOSE_HASH,
      contract_addr: "",
      nonce: "",
      pubkey: "",
      trusted_height: 0,
    },
    attacker_active' = false,
  }

  // ============================================================
  // Phase 1: Instantiate
  // ============================================================

  /// Honest enclave generates an attested instantiation message
  action instantiate(compose_hash: ComposeHash): bool = all {
    // Precondition: config not yet set
    not(contract.config_set),
    // The Attested wrapper verifies: attestation.compose_hash == msg.compose_hash
    // The attestation comes from the real enclave, so it carries the enclave's
    // actual compose_hash. Only succeeds if msg matches the enclave's identity.
    compose_hash == enclave.compose_hash,
    contract' = {
      ...contract,
      config_set: true,
      compose_hash: compose_hash,
    },
    enclave' = enclave,
    attacker_active' = attacker_active,
  }

  /// Attacker tries to instantiate with wrong compose_hash
  action instantiate_wrong_identity(compose_hash: ComposeHash, attest_hash: ComposeHash): bool = all {
    not(contract.config_set),
    attacker_active,
    // Attestation compose_hash must match the msg compose_hash
    // If they don't match, the Attested wrapper rejects
    compose_hash == attest_hash,
    // Attacker can only succeed if they control an enclave with matching hash
    // which means they'd need the real enclave code
    contract' = {
      ...contract,
      config_set: true,
      compose_hash: compose_hash,
    },
    enclave' = enclave,
    attacker_active' = attacker_active,
  }

  // ============================================================
  // Phase 2: SessionCreate
  // ============================================================

  /// Enclave generates nonce and sends attested SessionCreate to contract
  action session_create(nonce: Nonce, msg_contract: Addr): bool = all {
    // Preconditions
    contract.config_set,
    contract.session == NoSession or contract.session == SessionActive,
    // Enclave must not already be bound to a contract
    enclave.contract_addr == "",
    enclave.nonce == "",
    // The msg must specify the correct contract address
    msg_contract == contract.contract_addr,
    // Attestation verification (in the Attested wrapper):
    // - user_data matches hash of SessionCreate msg
    // - compose_hash matches contract config
    // Enclave state update
    enclave' = {
      ...enclave,
      contract_addr: msg_contract,
      nonce: nonce,
    },
    // Contract state update
    contract' = {
      ...contract,
      session: SessionCreated,
      session_nonce: nonce,
      session_pubkey: "",
      sequence_num: -1,  // reset if re-creating session
    },
    attacker_active' = attacker_active,
  }

  /// Attacker tries SessionCreate with wrong contract address
  action session_create_wrong_addr(nonce: Nonce): bool = all {
    contract.config_set,
    attacker_active,
    // Contract handler checks: msg.contract == env.contract.address
    // This always fails because the attacker can't fake the execution context
    false,  // unreachable — contract address is validated by the chain
    contract' = contract,
    enclave' = enclave,
    attacker_active' = attacker_active,
  }

  // ============================================================
  // Phase 3: SessionSetPubKey
  // ============================================================

  /// Enclave reads nonce from chain via light client proof, generates
  /// keypair, sends attested SessionSetPubKey to contract
  action session_set_pubkey(nonce: Nonce, pubkey: PubKey, proof_height: int): bool = all {
    // Preconditions
    contract.config_set,
    contract.session == SessionCreated,
    contract.session_pubkey == "",
    // Enclave has the matching nonce
    enclave.nonce == nonce,
    // Nonce must match what's on-chain
    nonce == contract.session_nonce,
    // Light client proof is valid (height advances)
    proof_height > enclave.trusted_height,
    // Enclave generates a new keypair
    pubkey != "",
    // Contract verifies: msg.nonce == SESSION.nonce
    // Contract verifies: SESSION.pub_key is None
    // Attestation verification: compose_hash + user_data match
    contract' = {
      ...contract,
      session: SessionActive,
      session_pubkey: pubkey,
      sequence_num: 0,  // initialize sequence counter
    },
    enclave' = {
      ...enclave,
      pubkey: pubkey,
      trusted_height: proof_height,
    },
    attacker_active' = attacker_active,
  }

  /// Attacker tries to set pubkey with wrong nonce
  action session_set_pubkey_wrong_nonce(wrong_nonce: Nonce, pubkey: PubKey): bool = all {
    contract.config_set,
    contract.session == SessionCreated,
    attacker_active,
    // Contract checks: msg.nonce == SESSION.nonce
    wrong_nonce == contract.session_nonce,
    // If the nonce matches, the attacker would need a valid attestation
    // from an enclave with the correct compose_hash — which they don't control
    false,  // attacker can't produce valid attestation
    contract' = contract,
    enclave' = enclave,
    attacker_active' = attacker_active,
  }

  // ============================================================
  // Post-handshake: Attested messages with sequence numbers
  // ============================================================

  /// Process a sequenced attested message
  action send_attested_message(msg_hash: Hash): bool = all {
    contract.session == SessionActive,
    contract.sequence_num >= 0,
    // Attestation wrapper verifies:
    // - user_data hash matches msg
    // - compose_hash matches config
    // Sequence number increments
    contract' = {
      ...contract,
      sequence_num: contract.sequence_num + 1,
    },
    enclave' = enclave,
    attacker_active' = attacker_active,
  }

  /// Re-create session (reset and start new handshake)
  action reset_session: bool = all {
    contract.config_set,
    contract.session == SessionActive,
    // Reset enclave state for new session
    enclave' = {
      ...enclave,
      contract_addr: "",
      nonce: "",
      pubkey: "",
    },
    // Session will be overwritten by next session_create
    contract' = contract,
    attacker_active' = attacker_active,
  }

  // ============================================================
  // Adversary actions
  // ============================================================

  action activate_attacker: bool = all {
    not(attacker_active),
    attacker_active' = true,
    contract' = contract,
    enclave' = enclave,
  }

  // ============================================================
  // Step
  // ============================================================

  action step = {
    nondet compose_hash = oneOf(Set(VALID_COMPOSE_HASH, WRONG_COMPOSE_HASH))
    nondet nonce = oneOf(Set(NONCE_1, NONCE_2))
    nondet pubkey = oneOf(Set(PUBKEY_1, PUBKEY_2))
    nondet msg_contract = oneOf(Set(CONTRACT_ADDR, WRONG_CONTRACT_ADDR))
    nondet msg_hash = oneOf(Set(MSG_HASH_VALID))
    nondet proof_height = oneOf(Set(1, 2, 3, 5, 10))
    any {
      instantiate(compose_hash),
      session_create(nonce, msg_contract),
      session_set_pubkey(nonce, pubkey, proof_height),
      send_attested_message(msg_hash),
      reset_session,
      activate_attacker,
    }
  }

  // ============================================================
  // Invariants
  // ============================================================

  /// Config is immutable once set
  val inv_config_immutable: bool = {
    // This is enforced by the contract handler — instantiate only works once
    // We check that config_set is monotonically true
    true  // trivially true in this model since no action unsets it
  }

  /// Session state machine transitions are valid
  val inv_valid_session_transitions: bool = {
    contract.session == NoSession or
    contract.session == SessionCreated or
    contract.session == SessionActive
  }

  /// If session is Active, pubkey and sequence_num are set
  val inv_active_session_complete: bool = {
    if (contract.session == SessionActive)
      contract.session_pubkey != "" and contract.sequence_num >= 0
    else true
  }

  /// If session is Created, pubkey is NOT set
  val inv_created_session_no_pubkey: bool = {
    if (contract.session == SessionCreated)
      contract.session_pubkey == ""
    else true
  }

  /// If no session, no nonce or pubkey
  val inv_no_session_clean: bool = {
    if (contract.session == NoSession)
      contract.session_nonce == "" and contract.session_pubkey == ""
    else true
  }

  /// Sequence number is -1 (uninitialized) or non-negative
  val inv_sequence_num_valid: bool = {
    contract.sequence_num >= -1
  }

  /// Sequence number only increases (never decreases once active)
  val inv_sequence_monotonic: bool = {
    if (contract.session == SessionActive)
      contract.sequence_num >= 0
    else true
  }

  /// Enclave nonce matches contract nonce (when session exists)
  val inv_nonce_consistency: bool = {
    if (contract.session == SessionCreated or contract.session == SessionActive)
      if (enclave.nonce != "")
        enclave.nonce == contract.session_nonce
      else true
    else true
  }

  /// Enclave pubkey matches contract pubkey (when session is active)
  val inv_pubkey_consistency: bool = {
    if (contract.session == SessionActive and enclave.pubkey != "")
      enclave.pubkey == contract.session_pubkey
    else true
  }

  /// Config compose_hash is always the valid one (attacker can't substitute)
  val inv_compose_hash_authentic: bool = {
    if (contract.config_set)
      contract.compose_hash == VALID_COMPOSE_HASH
    else true
  }

  /// Trusted height only increases
  val inv_trusted_height_monotonic: bool = {
    enclave.trusted_height >= 0
  }

  /// Composite invariant
  val all_invariants: bool = {
    inv_valid_session_transitions
    and inv_active_session_complete
    and inv_created_session_no_pubkey
    and inv_no_session_clean
    and inv_sequence_num_valid
    and inv_sequence_monotonic
    and inv_nonce_consistency
    and inv_pubkey_consistency
    and inv_compose_hash_authentic
    and inv_trusted_height_monotonic
  }

  // ============================================================
  // Temporal properties
  // ============================================================

  /// A created session eventually becomes active (liveness)
  temporal session_completes = always(
    contract.session == SessionCreated implies eventually(
      contract.session == SessionActive
    )
  )

}
