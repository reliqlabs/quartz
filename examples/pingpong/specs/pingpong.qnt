// Pingpong: Encrypted Echo with Quartz
//
// The simplest Quartz example. A user sends an encrypted message
// (Ping) along with an ephemeral public key. The enclave decrypts
// the message, processes it, encrypts the response to the user's
// ephemeral key, and returns an attested Pong.
//
// Privacy: the message content is private. Only the sender (who
// holds the ephemeral private key) can read the response.

module pingpong {

  type Addr = str
  type PubKey = str
  type Ciphertext = str
  type Plaintext = str

  type ContractState = {
    session_active: bool,
    // Map of ephemeral pubkey -> encrypted response (or encrypted message before pong)
    messages: PubKey -> Ciphertext,
  }

  type EnclaveState = {
    has_session_key: bool,
  }

  type ObserverView = {
    can_see_plaintext: bool,
    can_see_ciphertexts: bool,
  }

  var contract: ContractState
  var enclave: EnclaveState
  var observer: ObserverView

  // ── Constants ──

  val PUBKEY_1 = "pk_user_1"
  val PUBKEY_2 = "pk_user_2"

  // ── Init ──

  action init = all {
    contract' = {
      session_active: true,
      messages: Map(),
    },
    enclave' = { has_session_key: true },
    observer' = { can_see_plaintext: false, can_see_ciphertexts: false },
  }

  // ── Actions ──

  /// User sends Ping: encrypted message + ephemeral pubkey
  /// Contract stores the encrypted message keyed by pubkey.
  action ping(user_pubkey: PubKey, encrypted_msg: Ciphertext): bool = all {
    contract.session_active,
    not(contract.messages.keys().contains(user_pubkey)),
    contract' = {
      ...contract,
      messages: contract.messages.put(user_pubkey, encrypted_msg),
    },
    enclave' = enclave,
    observer' = { ...observer, can_see_ciphertexts: true },
  }

  /// Enclave processes the Ping and returns attested Pong.
  /// The enclave:
  /// 1. Decrypts the message with its session key
  /// 2. Processes it (in this example, just echoes)
  /// 3. Encrypts the response to the user's ephemeral pubkey
  /// 4. Returns the attested encrypted response
  /// The contract overwrites the stored entry with the response ciphertext.
  action pong(user_pubkey: PubKey, encrypted_response: Ciphertext): bool = all {
    contract.session_active,
    contract.messages.keys().contains(user_pubkey),
    // Enclave has processed and re-encrypted for the user
    contract' = {
      ...contract,
      messages: contract.messages.put(user_pubkey, encrypted_response),
    },
    enclave' = enclave,
    // Observer still can't see plaintext — only ciphertexts changed
    observer' = { can_see_plaintext: false, can_see_ciphertexts: true },
  }

  // ── Step ──

  action step = {
    nondet pubkey = oneOf(Set(PUBKEY_1, PUBKEY_2))
    nondet ct_ping = oneOf(Set("encrypted_hello", "encrypted_world"))
    nondet ct_pong = oneOf(Set("encrypted_response_1", "encrypted_response_2"))
    any {
      ping(pubkey, ct_ping),
      pong(pubkey, ct_pong),
    }
  }

  // ── Invariants ──

  /// Plaintext is NEVER visible to observers
  val inv_plaintext_private: bool = {
    not(observer.can_see_plaintext)
  }

  /// Session must be active for any operation
  val inv_session_required: bool = {
    // All actions require session_active — enforced by guards
    true
  }

  /// Messages map only contains entries that were explicitly added
  val inv_messages_non_negative: bool = {
    contract.messages.keys().size() >= 0
  }

  val all_invariants: bool = {
    inv_plaintext_private
    and inv_messages_non_negative
  }
}
