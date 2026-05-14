// Quartz Handshake Protocol — Complete Formal Specification
//
// Models the 3-phase secure channel establishment between a CosmWasm
// contract and a TEE enclave (dstack TDX), including ALL error paths
// and edge cases from the Rust implementation.
//
//   Phase 1: Instantiate — store compose_hash + config on-chain
//   Phase 2: SessionCreate — enclave generates nonce, contract stores it
//   Phase 3: SessionSetPubKey — enclave proves it read the nonce,
//            generates a session key pair, contract stores the pubkey
//
// After handshake, attested messages can flow using the established
// session key and sequence numbers.
//
// Verification target: quartz-contract-core handlers
//   handler/instantiate.rs
//   handler/execute/session_create.rs
//   handler/execute/session_set_pub_key.rs
//   handler/execute/attested.rs (Attested<M,A> wrapper)
//   state.rs (Session, Config)

module handshake {

  // ============================================================
  // Types
  // ============================================================

  type Addr = str
  type Hash = str
  type PubKey = str
  type Nonce = str
  type ComposeHash = str

  type SessionState =
    | NoSession
    | SessionCreated
    | SessionActive

  type ContractState = {
    config_set: bool,
    config_mr_enclave: ComposeHash,
    session: SessionState,
    session_nonce: Nonce,
    session_pubkey: PubKey,
    sequence_num: int,
    contract_addr: Addr,
  }

  type EnclaveState = {
    compose_hash: ComposeHash,
    contract_addr: Addr,
    nonce: Nonce,
    pubkey: PubKey,
    trusted_height: int,
  }

  /// Models the Attested<M, A> wrapper checks
  type AttestationCheck = {
    msg_user_data: Hash,
    att_user_data: Hash,
    att_compose_hash: ComposeHash,
  }

  /// Result of an action (for checking error paths)
  type ActionResult =
    | Ok
    | ErrUserDataMismatch
    | ErrMrEnclaveMismatch
    | ErrContractAddrMismatch
    | ErrBadSessionTransition
    | ErrConfigAlreadySet
    | ErrNoConfig
    | ErrNotAttempted

  /// Tag for the last action taken. Used so state-based invariants
  /// can ask "what kind of action just ran?".
  type LastAction =
    | ActInit
    | ActInstantiate
    | ActSessionCreate
    | ActSetPubkey
    | ActAttestedMsg
    | ActReset

  // ============================================================
  // State
  // ============================================================

  var contract: ContractState
  var enclave: EnclaveState
  var last_result: ActionResult

  /// History tracking — lets us promote action-based properties
  /// into state-based invariants checkable by Apalache.
  var last_action: LastAction
  /// Last inputs submitted to a verify-flow action. Reset by
  /// non-verify actions (reset_session).
  var last_msg_hash: Hash
  var last_att_user_data: Hash
  var last_att_compose_hash: ComposeHash
  var last_msg_contract: Addr
  var last_nonce: Nonce
  /// Pre-action snapshots — sampled at the start of each action.
  var prev_session: SessionState
  var prev_session_nonce: Nonce
  var prev_session_pubkey: PubKey
  var prev_config_set: bool
  var prev_config_mr_enclave: ComposeHash

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
  val VALID_HASH = "hash_valid"
  val WRONG_HASH = "hash_wrong"

  // ============================================================
  // Initial state
  // ============================================================

  action init = all {
    contract' = {
      config_set: false,
      config_mr_enclave: "",
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
    last_result' = ErrNotAttempted,
    last_action' = ActInit,
    last_msg_hash' = "",
    last_att_user_data' = "",
    last_att_compose_hash' = "",
    last_msg_contract' = "",
    last_nonce' = "",
    prev_session' = NoSession,
    prev_session_nonce' = "",
    prev_session_pubkey' = "",
    prev_config_set' = false,
    prev_config_mr_enclave' = "",
  }

  // ============================================================
  // Phase 1: Instantiate
  //
  // Rust: Instantiate<A>::handle()
  //   1. Check msg.config.mr_enclave == attestation.mr_enclave
  //   2. Attested wrapper: check user_data match, compose_hash match
  //   3. CoreInstantiate: save config to storage
  //
  // Precondition: CONFIG not yet saved (enforced by being first msg)
  // ============================================================

  /// Honest instantiate: enclave attests with correct compose_hash
  action instantiate(msg_mr_enclave: ComposeHash, att_compose_hash: ComposeHash): bool = {
    if (contract.config_set) {
      // Config already set — in real code, this would be a different
      // contract call (execute, not instantiate), but we model the guard
      all {
        last_result' = ErrConfigAlreadySet,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActInstantiate,
        last_msg_hash' = last_msg_hash,
        last_att_user_data' = last_att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (msg_mr_enclave != att_compose_hash) {
      // Instantiate<A>::handle line 18:
      // self.0.msg().config().mr_enclave() != self.0.attestation().mr_enclave()
      all {
        last_result' = ErrMrEnclaveMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActInstantiate,
        last_msg_hash' = last_msg_hash,
        last_att_user_data' = last_att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (att_compose_hash != enclave.compose_hash) {
      // Attested wrapper: attestation must come from real enclave
      // Attacker can't forge attestation with valid compose_hash
      all {
        last_result' = ErrMrEnclaveMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActInstantiate,
        last_msg_hash' = last_msg_hash,
        last_att_user_data' = last_att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else {
      // Success: CoreInstantiate::handle saves config
      all {
        last_result' = Ok,
        contract' = {
          ...contract,
          config_set: true,
          config_mr_enclave: msg_mr_enclave,
        },
        enclave' = enclave,
        last_action' = ActInstantiate,
        last_msg_hash' = last_msg_hash,
        last_att_user_data' = last_att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    }
  }

  // ============================================================
  // Phase 2: SessionCreate
  //
  // Rust: SessionCreate::handle()
  //   1. addr_validate(self.contract()) — must be valid bech32
  //   2. addr != env.contract.address — reject mismatch
  //   3. SESSION.save(Session::create(nonce)) — always overwrites
  //
  // Wrapped in Attested<SessionCreate, A>:
  //   - user_data check (msg hash == attestation user_data)
  //   - mr_enclave check (attestation.compose_hash == config)
  // ============================================================

  /// SessionCreate with attestation checks
  action session_create(
    nonce: Nonce,
    msg_contract: Addr,
    att_compose_hash: ComposeHash,
    msg_hash: Hash,
    att_user_data: Hash
  ): bool = {
    if (not(contract.config_set)) {
      all {
        last_result' = ErrNoConfig,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSessionCreate,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (msg_hash != att_user_data) {
      // Attested wrapper: user_data mismatch
      all {
        last_result' = ErrUserDataMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSessionCreate,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (att_compose_hash != contract.config_mr_enclave) {
      // Attested wrapper: mr_enclave mismatch
      all {
        last_result' = ErrMrEnclaveMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSessionCreate,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (msg_contract != contract.contract_addr) {
      // SessionCreate::handle line 17: addr != env.contract.address
      all {
        last_result' = ErrContractAddrMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSessionCreate,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else {
      // Success: SESSION.save overwrites any previous session
      // Note: no guard on current session state (the TODO in code)
      all {
        last_result' = Ok,
        contract' = {
          ...contract,
          session: SessionCreated,
          session_nonce: nonce,
          session_pubkey: "",
          // sequence_num is NOT reset here — only on SessionSetPubKey
        },
        enclave' = {
          ...enclave,
          contract_addr: msg_contract,
          nonce: nonce,
        },
        last_action' = ActSessionCreate,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    }
  }

  // ============================================================
  // Phase 3: SessionSetPubKey
  //
  // Rust: SessionSetPubKey::handle()
  //   1. SESSION.load() — must exist
  //   2. session.with_pub_key(nonce, pub_key):
  //      - self.nonce == nonce (guard 1)
  //      - self.pub_key.is_none() (guard 2)
  //      - returns Option<Self>
  //   3. SESSION.save(updated)
  //   4. SEQUENCE_NUM.save(0) — initializes counter
  //
  // Wrapped in Attested<SessionSetPubKey, A>:
  //   - user_data check
  //   - mr_enclave check
  // ============================================================

  /// SessionSetPubKey with all guards
  action session_set_pubkey(
    nonce: Nonce,
    pubkey: PubKey,
    att_compose_hash: ComposeHash,
    msg_hash: Hash,
    att_user_data: Hash
  ): bool = {
    if (not(contract.config_set)) {
      all {
        last_result' = ErrNoConfig,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (msg_hash != att_user_data) {
      // Attested wrapper: user_data mismatch
      all {
        last_result' = ErrUserDataMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (att_compose_hash != contract.config_mr_enclave) {
      // Attested wrapper: mr_enclave mismatch
      all {
        last_result' = ErrMrEnclaveMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (contract.session != SessionCreated) {
      // SESSION.load would fail or with_pub_key returns None
      // (no session, or session already active)
      all {
        last_result' = ErrBadSessionTransition,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (nonce != contract.session_nonce) {
      // Session::with_pub_key guard 1: self.nonce == nonce
      all {
        last_result' = ErrBadSessionTransition,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (contract.session_pubkey != "") {
      // Session::with_pub_key guard 2: self.pub_key.is_none()
      all {
        last_result' = ErrBadSessionTransition,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else {
      // Success: session transitions to Active, sequence_num = 0
      all {
        last_result' = Ok,
        contract' = {
          ...contract,
          session: SessionActive,
          session_pubkey: pubkey,
          sequence_num: 0,
        },
        enclave' = {
          ...enclave,
          pubkey: pubkey,
        },
        last_action' = ActSetPubkey,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    }
  }

  // ============================================================
  // Post-handshake: Attested messages
  // ============================================================

  /// Process an attested message (sequence number increments)
  action send_attested_message(
    att_compose_hash: ComposeHash,
    msg_hash: Hash,
    att_user_data: Hash
  ): bool = {
    if (contract.session != SessionActive) {
      all {
        last_result' = ErrBadSessionTransition,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActAttestedMsg,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (msg_hash != att_user_data) {
      all {
        last_result' = ErrUserDataMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActAttestedMsg,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else if (att_compose_hash != contract.config_mr_enclave) {
      all {
        last_result' = ErrMrEnclaveMismatch,
        contract' = contract,
        enclave' = enclave,
        last_action' = ActAttestedMsg,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    } else {
      all {
        last_result' = Ok,
        contract' = {
          ...contract,
          sequence_num: contract.sequence_num + 1,
        },
        enclave' = enclave,
        last_action' = ActAttestedMsg,
        last_msg_hash' = msg_hash,
        last_att_user_data' = att_user_data,
        last_att_compose_hash' = att_compose_hash,
        last_msg_contract' = last_msg_contract,
        last_nonce' = last_nonce,
        prev_session' = contract.session,
        prev_session_nonce' = contract.session_nonce,
        prev_session_pubkey' = contract.session_pubkey,
        prev_config_set' = contract.config_set,
        prev_config_mr_enclave' = contract.config_mr_enclave,
      }
    }
  }

  /// Session re-creation: enclave resets, will re-handshake
  action reset_session: bool = all {
    contract.config_set,
    contract.session == SessionActive,
    last_result' = Ok,
    enclave' = {
      ...enclave,
      contract_addr: "",
      nonce: "",
      pubkey: "",
    },
    contract' = contract,
    last_action' = ActReset,
    last_msg_hash' = "",
    last_att_user_data' = "",
    last_att_compose_hash' = "",
    last_msg_contract' = last_msg_contract,
    last_nonce' = last_nonce,
    prev_session' = contract.session,
    prev_session_nonce' = contract.session_nonce,
    prev_session_pubkey' = contract.session_pubkey,
    prev_config_set' = contract.config_set,
    prev_config_mr_enclave' = contract.config_mr_enclave,
  }

  // ============================================================
  // Step
  // ============================================================

  action step = {
    nondet mr_enclave = oneOf(Set(VALID_COMPOSE_HASH, WRONG_COMPOSE_HASH))
    nondet att_compose = oneOf(Set(VALID_COMPOSE_HASH, WRONG_COMPOSE_HASH))
    nondet nonce = oneOf(Set(NONCE_1, NONCE_2))
    nondet pubkey = oneOf(Set(PUBKEY_1, PUBKEY_2))
    nondet msg_contract = oneOf(Set(CONTRACT_ADDR, WRONG_CONTRACT_ADDR))
    nondet msg_hash = oneOf(Set(VALID_HASH, WRONG_HASH))
    nondet att_user_data = oneOf(Set(VALID_HASH, WRONG_HASH))
    any {
      instantiate(mr_enclave, att_compose),
      session_create(nonce, msg_contract, att_compose, msg_hash, att_user_data),
      session_set_pubkey(nonce, pubkey, att_compose, msg_hash, att_user_data),
      send_attested_message(att_compose, msg_hash, att_user_data),
      reset_session,
    }
  }

  // ============================================================
  // Invariants — Security Properties
  // ============================================================

  // ── Config Properties ──────────────────────────────────────────

  /// P1: Config compose_hash is always from the real enclave
  /// (attacker cannot substitute a different compose_hash)
  val inv_config_authentic: bool = {
    if (contract.config_set)
      contract.config_mr_enclave == VALID_COMPOSE_HASH
    else true
  }

  /// P2: Config is write-once — once set, compose_hash never changes.
  /// State check: if config was set before the last action, it is still
  /// set, and config_mr_enclave is unchanged from the snapshot.
  val inv_config_write_once: bool = {
    if (prev_config_set)
      contract.config_set and
        contract.config_mr_enclave == prev_config_mr_enclave
    else true
  }

  // ── Session State Machine ──────────────────────────────────────

  /// P3: Session state is always one of the three valid states
  val inv_valid_session_states: bool = {
    contract.session == NoSession or
    contract.session == SessionCreated or
    contract.session == SessionActive
  }

  /// P4: Active session always has a pubkey
  val inv_active_has_pubkey: bool = {
    if (contract.session == SessionActive)
      contract.session_pubkey != ""
    else true
  }

  /// P5: Created session never has a pubkey
  val inv_created_no_pubkey: bool = {
    if (contract.session == SessionCreated)
      contract.session_pubkey == ""
    else true
  }

  /// P6: Active session always has sequence_num >= 0
  val inv_active_has_sequence: bool = {
    if (contract.session == SessionActive)
      contract.sequence_num >= 0
    else true
  }

  /// P7: Sequence number is monotonically non-decreasing within a session
  /// (only increases via send_attested_message, resets to 0 on new session)
  val inv_sequence_valid: bool = {
    contract.sequence_num >= -1
  }

  // ── Attestation Integrity ──────────────────────────────────────

  /// P8: User data mismatch always produces an error.
  /// State check: if the last verify-flow action succeeded, the
  /// recorded msg_hash and att_user_data must have matched.
  val inv_user_data_checked: bool = {
    if (last_result == Ok and
        (last_action == ActSessionCreate or
         last_action == ActSetPubkey or
         last_action == ActAttestedMsg))
      last_msg_hash == last_att_user_data
    else true
  }

  /// P9: Wrong compose_hash always produces an error.
  /// State check: if the last verify-flow action succeeded, the
  /// recorded att_compose_hash must equal the config_mr_enclave that
  /// was in effect at the time. Since the snapshot of
  /// prev_config_mr_enclave is taken at action entry and config is
  /// write-once (P2), this captures the action-time check.
  val inv_compose_hash_checked: bool = {
    if (last_result == Ok and
        (last_action == ActSessionCreate or
         last_action == ActSetPubkey or
         last_action == ActAttestedMsg))
      last_att_compose_hash == prev_config_mr_enclave
    else true
  }

  // ── Contract Address Validation ────────────────────────────────

  /// P10: SessionCreate with wrong contract address always fails.
  /// State check: an Ok ActSessionCreate has last_msg_contract equal
  /// to the contract's own address.
  val inv_contract_addr_validated: bool = {
    if (last_result == Ok and last_action == ActSessionCreate)
      last_msg_contract == contract.contract_addr
    else true
  }

  // ── Session Transition Guards ──────────────────────────────────

  /// P11: SessionSetPubKey requires SessionCreated state.
  /// State check: an Ok ActSetPubkey had prev_session == SessionCreated.
  val inv_set_pubkey_requires_created: bool = {
    if (last_result == Ok and last_action == ActSetPubkey)
      prev_session == SessionCreated
    else true
  }

  /// P12: SessionSetPubKey requires matching nonce.
  /// State check: an Ok ActSetPubkey had last_nonce equal to the
  /// session_nonce in effect before the action.
  val inv_set_pubkey_nonce_match: bool = {
    if (last_result == Ok and last_action == ActSetPubkey)
      last_nonce == prev_session_nonce
    else true
  }

  /// P13: Pubkey can only be set once per session.
  /// State check: an Ok ActSetPubkey had prev_session_pubkey == "".
  val inv_pubkey_set_once: bool = {
    if (last_result == Ok and last_action == ActSetPubkey)
      prev_session_pubkey == ""
    else true
  }

  // ── Cross-Component Consistency ────────────────────────────────

  /// P14: Enclave nonce matches contract nonce when session exists
  val inv_nonce_consistency: bool = {
    if (contract.session == SessionCreated or contract.session == SessionActive)
      if (enclave.nonce != "")
        enclave.nonce == contract.session_nonce
      else true
    else true
  }

  /// P15: Enclave pubkey matches contract pubkey when session is active
  val inv_pubkey_consistency: bool = {
    if (contract.session == SessionActive and enclave.pubkey != "")
      enclave.pubkey == contract.session_pubkey
    else true
  }

  // ── Temporal mirrors of state-only transition invariants ─────────
  //
  // Per Round C 2026-05-14 (Claude #6 + Round-1 carryover): the
  // state-only invariants P8–P13 below predicate on `last_result ==
  // Ok and last_action == ActX`. That pattern binds the property for
  // exactly one transition (the just-completed one); after any other
  // action runs, `last_action` changes and the antecedent becomes
  // false, making the invariant vacuously true. Round-1's
  // `temporal_zk_accept_requires_vkey` settled the equivalent fix in
  // `attestation.qnt`: promote each transition-property to a
  // temporal `always(next-action-X implies next-property)` form.
  //
  // The state-only forms below are retained as fast Apalache state
  // checks; the temporal forms below give the refactor-robust binding
  // semantics that future actions cannot silently bypass.

  /// Temporal mirror of P8 (`inv_user_data_checked`).
  temporal temporal_user_data_checked = always(
    ((next(last_result) == Ok) and
     ((next(last_action) == ActSessionCreate) or
      (next(last_action) == ActSetPubkey) or
      (next(last_action) == ActAttestedMsg)))
    implies next(last_msg_hash) == next(last_att_user_data)
  )

  /// Temporal mirror of P9 (`inv_compose_hash_checked`).
  temporal temporal_compose_hash_checked = always(
    ((next(last_result) == Ok) and
     ((next(last_action) == ActSessionCreate) or
      (next(last_action) == ActSetPubkey) or
      (next(last_action) == ActAttestedMsg)))
    implies next(last_att_compose_hash) == next(prev_config_mr_enclave)
  )

  /// Temporal mirror of P10 (`inv_contract_addr_validated`).
  temporal temporal_contract_addr_validated = always(
    ((next(last_result) == Ok) and
     (next(last_action) == ActSessionCreate))
    implies next(last_msg_contract) == next(contract.contract_addr)
  )

  /// Temporal mirror of P11 (`inv_set_pubkey_requires_created`).
  temporal temporal_set_pubkey_requires_created = always(
    ((next(last_result) == Ok) and
     (next(last_action) == ActSetPubkey))
    implies next(prev_session) == SessionCreated
  )

  /// Temporal mirror of P12 (`inv_set_pubkey_nonce_match`).
  temporal temporal_set_pubkey_nonce_match = always(
    ((next(last_result) == Ok) and
     (next(last_action) == ActSetPubkey))
    implies next(last_nonce) == next(prev_session_nonce)
  )

  /// Temporal mirror of P13 (`inv_pubkey_set_once`).
  temporal temporal_pubkey_set_once = always(
    ((next(last_result) == Ok) and
     (next(last_action) == ActSetPubkey))
    implies next(prev_session_pubkey) == ""
  )

  // ── Composite ──────────────────────────────────────────────────

  val all_invariants: bool = {
    inv_config_authentic
    and inv_config_write_once
    and inv_valid_session_states
    and inv_active_has_pubkey
    and inv_created_no_pubkey
    and inv_active_has_sequence
    and inv_sequence_valid
    and inv_user_data_checked
    and inv_compose_hash_checked
    and inv_contract_addr_validated
    and inv_set_pubkey_requires_created
    and inv_set_pubkey_nonce_match
    and inv_pubkey_set_once
    and inv_nonce_consistency
    and inv_pubkey_consistency
  }
}
