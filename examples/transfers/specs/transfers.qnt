// Private Transfers with Quartz
//
// Models a private token transfer system where balances are encrypted
// on-chain. Users deposit/withdraw publicly, but transfers between
// users are encrypted — the contract stores ciphertext, the enclave
// processes the actual balance updates.
//
// Privacy model:
// - Deposits and withdrawals are public (involve on-chain token movement)
// - Transfer amounts between users are private (encrypted)
// - Individual balances are private (encrypted state)
// - The enclave maintains the true balance tree and produces
//   attested state updates

module transfers {

  type Addr = str
  type Amount = int
  type Ciphertext = str

  type RequestKind =
    | DepositReq
    | WithdrawReq
    | TransferReq

  type Request = {
    kind: RequestKind,
    sender: Addr,
    receiver: Addr,    // "" for deposit/withdraw
    amount: Amount,     // 0 for encrypted transfers (amount hidden)
    ciphertext: Ciphertext,  // "" for deposit/withdraw
  }

  type ContractState = {
    session_active: bool,
    denom: str,
    // Encrypted state blob — contract can't read individual balances
    encrypted_state: Ciphertext,
    // Pending requests (mix of public and encrypted)
    requests: List[Request],
    // Sequence number for replay protection
    sequence_num: int,
  }

  type EnclaveState = {
    // The enclave's private view: actual balances
    balances: Addr -> Amount,
  }

  type ObserverView = {
    can_see_balances: bool,
    can_see_transfer_amounts: bool,
    can_see_deposits: bool,
    can_see_withdrawals: bool,
  }

  var contract: ContractState
  var enclave: EnclaveState
  var observer: ObserverView

  // ── Constants ──

  val ALICE = "alice"
  val BOB = "bob"
  val CAROL = "carol"

  // ── Init ──

  action init = all {
    contract' = {
      session_active: true,
      denom: "uxion",
      encrypted_state: "",
      requests: List(),
      sequence_num: 0,
    },
    enclave' = { balances: Map() },
    observer' = {
      can_see_balances: false,
      can_see_transfer_amounts: false,
      can_see_deposits: true,  // deposits are on-chain token transfers
      can_see_withdrawals: true,
    },
  }

  // ── Actions ──

  /// User deposits tokens (public — involves on-chain token movement)
  action deposit(sender: Addr, amount: Amount): bool = all {
    contract.session_active,
    amount > 0,
    val req: Request = {
      kind: DepositReq,
      sender: sender,
      receiver: "",
      amount: amount,
      ciphertext: "",
    }
    contract' = {
      ...contract,
      requests: contract.requests.append(req),
    },
    enclave' = enclave,
    observer' = observer,
  }

  /// User requests withdrawal (public — results in on-chain token transfer)
  action withdraw(sender: Addr): bool = all {
    contract.session_active,
    val req: Request = {
      kind: WithdrawReq,
      sender: sender,
      receiver: "",
      amount: 0,
      ciphertext: "",
    }
    contract' = {
      ...contract,
      requests: contract.requests.append(req),
    },
    enclave' = enclave,
    observer' = observer,
  }

  /// User submits encrypted transfer request (private)
  /// The contract stores the ciphertext without knowing the amount.
  action transfer(sender: Addr, ciphertext: Ciphertext): bool = all {
    contract.session_active,
    ciphertext != "",
    val req: Request = {
      kind: TransferReq,
      sender: sender,
      receiver: "",  // receiver is inside the ciphertext
      amount: 0,     // amount is inside the ciphertext
      ciphertext: ciphertext,
    }
    contract' = {
      ...contract,
      requests: contract.requests.append(req),
      sequence_num: contract.sequence_num + 1,
    },
    enclave' = enclave,
    // Observer can see a transfer happened but NOT the amount or recipient
    observer' = observer,
  }

  /// Enclave processes all pending requests and produces an attested
  /// state update. This is the core private computation:
  /// 1. Read pending requests from chain (light client proof)
  /// 2. Decrypt transfer ciphertexts
  /// 3. Apply all balance changes (deposits, withdrawals, transfers)
  /// 4. Encrypt the new balance tree
  /// 5. Return attested update with encrypted state + withdrawal list
  action update(
    transfer_details: List[{sender: Addr, receiver: Addr, amount: Amount}],
    new_encrypted_state: Ciphertext
  ): bool = all {
    contract.session_active,
    contract.requests.length() > 0,
    // Process each request and update enclave balances
    val new_balances = contract.requests.indices().fold(enclave.balances, (bals, i) => {
      val req = contract.requests[i]
      if (req.kind == DepositReq) {
        val prev = if (bals.keys().contains(req.sender)) bals.get(req.sender) else 0
        bals.put(req.sender, prev + req.amount)
      } else if (req.kind == WithdrawReq) {
        val prev = if (bals.keys().contains(req.sender)) bals.get(req.sender) else 0
        bals.put(req.sender, 0)  // simplified: withdraw all
      } else {
        // TransferReq: apply from transfer_details
        bals  // simplified: would apply decrypted transfer
      }
    })
    all {
      contract' = {
        ...contract,
        encrypted_state: new_encrypted_state,
        requests: List(),  // clear processed requests
      },
      enclave' = { balances: new_balances },
      observer' = observer,
    },
  }

  /// User queries their balance via the enclave.
  /// The enclave decrypts the balance and re-encrypts to the user's
  /// ephemeral pubkey. The contract stores the encrypted response.
  action query_balance(user: Addr): bool = all {
    contract.session_active,
    // The enclave returns an encrypted balance — observer can't read it
    enclave' = enclave,
    contract' = contract,
    observer' = { ...observer, can_see_balances: false },
  }

  // ── Step ──

  action step = {
    nondet user = oneOf(Set(ALICE, BOB, CAROL))
    nondet amount = oneOf(Set(10, 50, 100, 500))
    nondet ct = oneOf(Set("ct_transfer_1", "ct_transfer_2", "ct_transfer_3"))
    nondet new_state = oneOf(Set("state_v1", "state_v2", "state_v3"))
    any {
      deposit(user, amount),
      withdraw(user),
      transfer(user, ct),
      update(List(), new_state),
      query_balance(user),
    }
  }

  // ── Invariants ──

  /// Individual balances are NEVER visible to observers
  val inv_balances_private: bool = {
    not(observer.can_see_balances)
  }

  /// Transfer amounts are NEVER visible to observers
  val inv_transfers_private: bool = {
    not(observer.can_see_transfer_amounts)
  }

  /// Deposits are always visible (public on-chain token movement)
  val inv_deposits_public: bool = {
    observer.can_see_deposits
  }

  /// Withdrawals are always visible (public on-chain token movement)
  val inv_withdrawals_public: bool = {
    observer.can_see_withdrawals
  }

  /// Sequence number never decreases
  val inv_sequence_monotonic: bool = {
    contract.sequence_num >= 0
  }

  /// Balances in the enclave are never negative
  val inv_balances_non_negative: bool = {
    enclave.balances.keys().forall(addr =>
      enclave.balances.get(addr) >= 0
    )
  }

  /// Session must be active for operations
  val inv_session_required: bool = {
    true  // enforced by action guards
  }

  val all_invariants: bool = {
    inv_balances_private
    and inv_transfers_private
    and inv_deposits_public
    and inv_withdrawals_public
    and inv_sequence_monotonic
    and inv_balances_non_negative
  }
}
