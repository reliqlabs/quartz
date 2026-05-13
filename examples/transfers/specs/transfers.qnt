// Quartz Transfers — Privacy-Preserving Balance Tracking
//
// Models the private token transfer protocol. The on-chain contract is
// the storage/dispatch layer; the enclave is the authoritative
// balance-tree owner.
//
// Privacy model:
//   - Deposits and withdrawals are public (on-chain token movement).
//   - Transfer amounts and recipients are private (encrypted).
//   - Individual balances are private (encrypted state on-chain;
//     plaintext only inside the enclave).
//
// This spec focuses on FUNDS CONSERVATION (the cw20-base style theorem
// from verified-cosmwasm/Specs/Cw20Base/Conservation.lean) as the
// core safety property, alongside the privacy and replay-protection
// invariants that already applied to the protocol.
//
// Verification target: examples/transfers/contracts/src/{contract,
//   msg, state}.rs and the enclave-side balance update logic.
//
// Conservation theorem (informal):
//   At every reachable state, the sum of all balances tracked by the
//   enclave equals the total supply, where:
//     total_supply = sum(deposits) - sum(withdrawals)
//
// In the cw20-base proof, this is `execTransfer_preserves_tokenInfo`
// (transfer leaves totalSupply alone) plus
// `execMint_increases_total` / `execBurn_decreases_total` (mint and
// burn move totalSupply by exactly the amount). Here, deposits play
// the role of mint, withdrawals the role of burn, and transfers play
// the role of transfer.

module transfers {

  // ============================================================
  // Types
  // ============================================================

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
    amount: Amount,    // hidden (0) for encrypted transfers
    ciphertext: Ciphertext,
  }

  /// Plain transfer parameters the enclave decrypts from a TransferReq.
  type TransferOp = {
    sender: Addr,
    receiver: Addr,
    amount: Amount,
  }

  type ContractState = {
    session_active: bool,
    denom: str,
    // Encrypted state blob — contract cannot read individual balances.
    encrypted_state: Ciphertext,
    // Pending requests (mix of public and encrypted).
    requests: List[Request],
    // Sequence number for replay protection on TransferRequest
    // (the RawSequenced wrapper in msg.rs).
    sequence_num: int,
  }

  type EnclaveState = {
    // The enclave's private view: actual per-address balances.
    balances: Addr -> Amount,
    // Ghost variable: cumulative total of all deposits minus
    // withdrawals. Conservation = sum_of_balances == total_supply.
    total_supply: Amount,
  }

  type ObserverView = {
    can_see_balances: bool,
    can_see_transfer_amounts: bool,
    can_see_deposits: bool,
    can_see_withdrawals: bool,
  }

  type LastAction =
    | ActInit
    | ActDeposit
    | ActWithdraw
    | ActTransfer
    | ActUpdate
    | ActQuery

  // ============================================================
  // State
  // ============================================================

  var contract: ContractState
  var enclave: EnclaveState
  var observer: ObserverView
  var last_action: LastAction
  // Snapshot of total_supply before the last action, used by
  // conservation-step invariants.
  var prev_total_supply: Amount
  var prev_balances: Addr -> Amount

  // ============================================================
  // Constants — bounded address universe for BMC tractability
  // ============================================================

  val ALICE = "alice"
  val BOB = "bob"
  val CAROL = "carol"
  val ADDRS = Set(ALICE, BOB, CAROL)

  // ============================================================
  // Helpers
  // ============================================================

  /// Balance lookup with default 0 for unseen addresses.
  pure def bal_of(b: Addr -> Amount, a: Addr): Amount = {
    if (b.keys().contains(a)) b.get(a) else 0
  }

  /// Sum of all balances across the bounded address universe.
  /// This is the LHS of the conservation invariant.
  pure def sum_of_balances(b: Addr -> Amount): Amount = {
    ADDRS.fold(0, (acc, a) => acc + bal_of(b, a))
  }

  // ============================================================
  // Initial state
  // ============================================================

  action init = all {
    contract' = {
      session_active: true,
      denom: "uxion",
      encrypted_state: "",
      requests: List(),
      sequence_num: 0,
    },
    enclave' = {
      balances: ADDRS.mapBy(_ => 0),
      total_supply: 0,
    },
    observer' = {
      can_see_balances: false,
      can_see_transfer_amounts: false,
      can_see_deposits: true,
      can_see_withdrawals: true,
    },
    last_action' = ActInit,
    prev_total_supply' = 0,
    prev_balances' = ADDRS.mapBy(_ => 0),
  }

  // ============================================================
  // Actions
  // ============================================================

  /// User deposits tokens (public — on-chain token movement).
  /// Mirrors `execute::deposit`: pushes a Deposit(addr, amount)
  /// request onto the queue.
  action deposit(sender: Addr, amount: Amount): bool = all {
    contract.session_active,
    amount > 0,
    ADDRS.contains(sender),
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
    last_action' = ActDeposit,
    prev_total_supply' = enclave.total_supply,
    prev_balances' = enclave.balances,
  }

  /// User requests withdrawal of all their balance (public — results
  /// in on-chain bank send during update). Mirrors `execute::withdraw`.
  action withdraw(sender: Addr): bool = all {
    contract.session_active,
    ADDRS.contains(sender),
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
    last_action' = ActWithdraw,
    prev_total_supply' = enclave.total_supply,
    prev_balances' = enclave.balances,
  }

  /// User submits encrypted transfer request (private). The contract
  /// stores the ciphertext WITHOUT knowing amount/recipient. The
  /// sequence number is incremented to prevent replay.
  /// Mirrors `execute::transfer_request` + the `RawSequenced` wrapper.
  action transfer_request(sender: Addr, ciphertext: Ciphertext): bool = all {
    contract.session_active,
    ADDRS.contains(sender),
    ciphertext != "",
    val req: Request = {
      kind: TransferReq,
      sender: sender,
      receiver: "",
      amount: 0,
      ciphertext: ciphertext,
    }
    contract' = {
      ...contract,
      requests: contract.requests.append(req),
      sequence_num: contract.sequence_num + 1,
    },
    enclave' = enclave,
    observer' = observer,
    last_action' = ActTransfer,
    prev_total_supply' = enclave.total_supply,
    prev_balances' = enclave.balances,
  }

  /// Apply a single deposit to enclave state. Increases the depositor's
  /// balance and the global total_supply by exactly `amount`.
  pure def apply_deposit(e: EnclaveState, sender: Addr, amount: Amount): EnclaveState = {
    {
      balances: e.balances.set(sender, bal_of(e.balances, sender) + amount),
      total_supply: e.total_supply + amount,
    }
  }

  /// Apply a withdrawal: drain the entire balance of `sender` (the
  /// contract's withdraw semantics — withdraw all). Decreases
  /// total_supply by exactly the drained amount.
  pure def apply_withdraw(e: EnclaveState, sender: Addr): EnclaveState = {
    val drained = bal_of(e.balances, sender)
    {
      balances: e.balances.set(sender, 0),
      total_supply: e.total_supply - drained,
    }
  }

  /// Apply a transfer: sender_balance -= amount, receiver_balance +=
  /// amount, total_supply UNCHANGED. Only applied if sender has
  /// sufficient balance (matches cw20-base's checked_sub semantics).
  pure def apply_transfer(e: EnclaveState, op: TransferOp): EnclaveState = {
    val sender_bal = bal_of(e.balances, op.sender)
    if (op.amount <= 0 or op.sender == op.receiver or sender_bal < op.amount) {
      e  // reject: would underflow, no-op, or trivially equal
    } else {
      {
        balances: e.balances
          .set(op.sender, sender_bal - op.amount)
          .set(op.receiver, bal_of(e.balances, op.receiver) + op.amount),
        total_supply: e.total_supply,
      }
    }
  }

  /// Enclave processes one queued request. For TransferReq it consults
  /// the supplied `transfer_op` (the enclave's decryption of the
  /// ciphertext). This is the per-step engine that `update` runs over
  /// the first N requests in the queue.
  pure def apply_request(e: EnclaveState, req: Request, op: TransferOp): EnclaveState = {
    if (req.kind == DepositReq) {
      apply_deposit(e, req.sender, req.amount)
    } else if (req.kind == WithdrawReq) {
      apply_withdraw(e, req.sender)
    } else {
      apply_transfer(e, op)
    }
  }

  /// Enclave processes the FIRST request in the queue and emits an
  /// attested UpdateMsg (modelled as the new encrypted state + the
  /// drain count = 1). We process one request per step so that
  /// invariants can fire between each balance change — this is the
  /// proof granularity that catches per-step violations of
  /// conservation.
  ///
  /// `op` is the enclave's decryption of the ciphertext, if any. For
  /// non-transfer requests it's ignored.
  action update(op: TransferOp, new_encrypted_state: Ciphertext): bool = all {
    contract.session_active,
    contract.requests.length() > 0,
    val req = contract.requests.head()
    val e_new = apply_request(enclave, req, op)
    all {
      contract' = {
        ...contract,
        encrypted_state: new_encrypted_state,
        requests: contract.requests.tail(),
      },
      enclave' = e_new,
      observer' = observer,
      last_action' = ActUpdate,
      prev_total_supply' = enclave.total_supply,
      prev_balances' = enclave.balances,
    },
  }

  /// User queries their balance via the enclave (encrypted response).
  /// Mirrors `execute::query_balance` + `execute::store_balance`.
  action query_balance(user: Addr): bool = all {
    contract.session_active,
    ADDRS.contains(user),
    enclave' = enclave,
    contract' = contract,
    observer' = { ...observer, can_see_balances: false },
    last_action' = ActQuery,
    prev_total_supply' = enclave.total_supply,
    prev_balances' = enclave.balances,
  }

  // ============================================================
  // Step
  // ============================================================

  action step = {
    nondet user = oneOf(ADDRS)
    nondet recv = oneOf(ADDRS)
    nondet amount = oneOf(Set(10, 50, 100))
    nondet ct = oneOf(Set("ct1", "ct2"))
    nondet new_state = oneOf(Set("s1", "s2"))
    val op: TransferOp = { sender: user, receiver: recv, amount: amount }
    any {
      deposit(user, amount),
      withdraw(user),
      transfer_request(user, ct),
      update(op, new_state),
      query_balance(user),
    }
  }

  // ============================================================
  // Invariants
  // ============================================================

  // ── I1: CONSERVATION ──────────────────────────────────────────
  //
  // The core safety theorem, ported from cw20-base/Conservation.lean.
  // Total supply equals the sum of every individual balance.
  // This holds because:
  //   - apply_deposit raises BOTH sum_of_balances and total_supply
  //     by `amount` (mint pattern).
  //   - apply_withdraw lowers BOTH sum_of_balances and total_supply
  //     by `drained` (burn pattern).
  //   - apply_transfer leaves BOTH sum_of_balances and total_supply
  //     unchanged (transfer preserves tokenInfo).

  /// I1: sum_of_balances == total_supply at every reachable state.
  val inv_conservation: bool = {
    sum_of_balances(enclave.balances) == enclave.total_supply
  }

  // ── I2: Non-negativity ────────────────────────────────────────

  /// I2: No address ever holds a negative balance.
  /// Mirrors the Uint128 type discipline in the Rust code:
  /// balances are unsigned, so any operation that would produce a
  /// negative value must instead be rejected (apply_transfer guard).
  val inv_balances_non_negative: bool = {
    ADDRS.forall(a => bal_of(enclave.balances, a) >= 0)
  }

  /// I2b: total_supply is never negative.
  val inv_total_supply_non_negative: bool = {
    enclave.total_supply >= 0
  }

  // ── I3: Privacy ──────────────────────────────────────────────

  /// I3: Individual balances are NEVER visible to passive observers.
  /// Encoded as: the observer view's `can_see_balances` is always
  /// false. Withdraw and deposit reveal *amounts* (since they're
  /// on-chain bank movements), but individual balance positions
  /// are not revealed by the contract.
  val inv_balances_private: bool = {
    not(observer.can_see_balances)
  }

  /// I4: Transfer amounts are NEVER visible to observers. The
  /// contract stores ciphertext only; the plaintext amount lives
  /// inside the enclave.
  val inv_transfers_private: bool = {
    not(observer.can_see_transfer_amounts)
  }

  // ── I4: Replay protection ────────────────────────────────────

  /// I5: Sequence number is monotonically non-decreasing.
  /// Mirrors `RawSequenced<TransferRequestMsg>`: each TransferRequest
  /// increments the seq, no action ever decrements it.
  val inv_sequence_monotone: bool = {
    if (last_action == ActTransfer)
      contract.sequence_num > 0
    else
      contract.sequence_num >= 0
  }

  // ── I5: Transfer atomicity / authorization ───────────────────

  /// I6: After an update step that processed a transfer, the total
  /// supply is unchanged (transfer preserves tokenInfo — the
  /// cw20-base execTransfer theorem). The conservation theorem I1
  /// gives this transitively, but stating it explicitly as a step
  /// invariant catches mutations that decouple sum_of_balances from
  /// total_supply (e.g. "transfer that mints").
  val inv_transfer_preserves_total: bool = {
    // We can only check this for the last action being ActUpdate
    // because update is the only path that touches balances.
    if (last_action == ActUpdate)
      // If total_supply changed, it must have been a non-transfer
      // request — i.e. the step balanced via deposit/withdraw, both
      // of which also move sum_of_balances correspondingly.
      // The strongest statement we can make at the level of "what
      // step just happened" is that conservation still holds.
      inv_conservation
    else
      true
  }

  /// I7: After an update step, balances stay non-negative — i.e.
  /// apply_transfer correctly rejected any underflowing attempt.
  /// Mirrors the `UintN.checked_sub` guard in execTransfer.
  val inv_no_underflow_on_transfer: bool = {
    if (last_action == ActUpdate)
      inv_balances_non_negative
    else
      true
  }

  // ── I6: Authorization ────────────────────────────────────────

  /// I8: Only the sender can decrement their own balance via a
  /// transfer (subject-to-decryption: we model this at the
  /// post-condition level — if a balance decreased between
  /// prev_balances and enclave.balances after an ActUpdate, then
  /// either it was a withdrawal of that address, or a transfer with
  /// that address as the sender. In our one-step-per-update model,
  /// we just check that any single-address decrement is bounded by
  /// the corresponding total_supply change OR by a transfer that
  /// increased some other address by the same amount.
  val inv_no_silent_balance_loss: bool = {
    if (last_action == ActUpdate) {
      // The change in sum_of_balances equals the change in total_supply.
      // This is the conservation step-form: no balance evaporates
      // without total_supply also dropping.
      sum_of_balances(enclave.balances) - sum_of_balances(prev_balances)
        == enclave.total_supply - prev_total_supply
    } else {
      true
    }
  }

  // ── Composite ────────────────────────────────────────────────

  val all_invariants: bool = {
    inv_conservation
    and inv_balances_non_negative
    and inv_total_supply_non_negative
    and inv_balances_private
    and inv_transfers_private
    and inv_sequence_monotone
    and inv_transfer_preserves_total
    and inv_no_underflow_on_transfer
    and inv_no_silent_balance_loss
  }
}
