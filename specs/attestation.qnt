// Quartz Attestation Verification
//
// Models the on-chain verification of attested messages via two paths:
//
// 1. DstackAttestation (raw TDX DCAP quote):
//    - Checks user_data hash matches the message
//    - Checks compose_hash matches contract config
//    - Accepts (DCAP quote is available for off-chain verification)
//
// 2. DstackZkAttestation (zkdcap UltraHonk proof):
//    - Checks user_data hash matches the message
//    - Checks compose_hash matches contract config
//    - Queries the Xion ZK module (ProofVerifyUltraHonk) with the proof
//    - Range-checks chain time against the proof's proven validity window and
//      rejects tcb_eval_num below the monotonic floor (the circuit has no
//      clock/counter, so this is the consumer's decision)
//    - Accepts if proof verifies
//
// The packed public_inputs ARE the journal (no separate journal blob under
// UltraHonk). DstackAnyAttestation is the runtime enum: the contract accepts
// either variant and delegates to the appropriate handler.

module attestation {

  // ============================================================
  // Types
  // ============================================================

  type Hash = str
  type ComposeHash = str
  type VKeyName = str

  type ZkProof = {
    proof_bytes: str,        // UltraHonk proof (opaque to this spec)
    public_inputs: str,      // packed field elements (the journal)
    report_data: Hash,       // decoded report_data (bound to wrapper user_data)
    rtmr3: ComposeHash,      // decoded rtmr3 (bound to config.expected_rtmr3 when pinned)
    valid_from: int,         // proven validity-window lower bound (packed date)
    valid_until: int,        // proven validity-window upper bound (packed date)
    tcb_eval: int,           // TCB-Info tcbEvaluationDataNumber (field 17)
    qe_eval: int,            // QE-Identity tcbEvaluationDataNumber (field 18, issue #4)
  }

  /// Raw TDX DCAP quote attestation
  type DstackAttestation = {
    user_data: Hash,
    compose_hash: ComposeHash,
    quote: str,              // raw TDX DCAP quote bytes
    event_log: str,          // optional RTMR event log
  }

  /// ZK proof attestation (compressed from raw quote)
  type DstackZkAttestation = {
    user_data: Hash,
    compose_hash: ComposeHash,
    proof: ZkProof,
  }

  /// The runtime enum — contract accepts either variant
  type AttestationVariant =
    | Quote
    | Zk

  type AnyAttestation = {
    variant: AttestationVariant,
    user_data: Hash,
    compose_hash: ComposeHash,
    // Quote fields (present when variant == Quote)
    quote: str,
    event_log: str,
    // Zk fields (present when variant == Zk)
    proof: ZkProof,
  }

  type AttestedMessage = {
    msg_hash: Hash,
    attestation: AnyAttestation,
  }

  type ContractConfig = {
    compose_hash: ComposeHash,
    zkdcap_vkey: str,        // "" if not configured
    min_tcb_eval: int,       // monotonic TCB-recency floor (0 ⇒ no floor)
    expected_rtmr3: ComposeHash, // "" ⇒ no register pinned (abstracts the
                                 // production mrtd/rtmr0-3 pin set)
    allow_any_image: bool,   // escape hatch: verify with no register pinned
  }

  type ZkModuleState = {
    registered_vkeys: Set[VKeyName],
    accept_all: bool,        // for mock/testing mode
  }

  type VerificationResult =
    | Accepted
    | AcceptedQuote            // raw quote accepted (no ZK)
    | RejectedUserDataMismatch
    | RejectedComposeHashMismatch
    | RejectedZkProofInvalid
    | RejectedVKeyNotFound
    | RejectedStaleOrFuture     // chain time outside window, or an eval below floor
    | RejectedBindingMismatch   // report_data != user_data, or rtmr3 != expected_rtmr3
    | SkippedNoVKey

  /// Action provenance tag. Recorded as `last_action` so temporal properties
  /// can predicate on which action fired into a given result, rather than
  /// inferring from state alone (which is brittle to action-set refactors).
  /// See multi-model adversarial synthesis 2026-05-12 in .colosseum/attacks/.
  type Action =
    | ActNone
    | ActVerifyQuote
    | ActVerifyZk
    | ActEnableMock
    | ActClearVkey
    | ActClearImagePin
    | ActAllowAnyImage

  // ============================================================
  // State
  // ============================================================

  var config: ContractConfig
  var zk_module: ZkModuleState
  var last_result: VerificationResult
  var messages_accepted: int
  var messages_rejected: int
  /// Tracks the last attestation submitted to verify_any (or a dummy
  /// value at init). Used to make state-based invariants (e.g.,
  /// "rejection was justified") checkable by Apalache.
  var last_input: AttestedMessage
  /// Provenance tag for the action that produced the current state. Set by
  /// every action (including `init` which sets `ActNone`). Load-bearing for
  /// temporal properties that need to discriminate which action's result
  /// they are witnessing.
  var last_action: Action

  // ============================================================
  // Constants
  // ============================================================

  val VALID_COMPOSE_HASH = "aabbccdd"
  val WRONG_COMPOSE_HASH = "deadbeef"
  val VALID_MSG_HASH = "msg_hash_1"
  val VALID_VKEY = "dcap-ultrahonk-v1"
  val VALID_QUOTE = "deadbeef_quote"
  val VALID_RTMR3 = "rtmr3_good"   // matches config.expected_rtmr3
  val WRONG_RTMR3 = "rtmr3_bad"

  // Packed YYYYMMDDhhmmss clock + the recency floor. CHAIN_TIME is a constant
  // so acceptance-implies-recency is a state-checkable invariant.
  val CHAIN_TIME = 20250101000000
  val TCB_FLOOR = 10

  // In-window proof, both evals >= floor, report_data/rtmr3 bind correctly.
  val VALID_PROOF = { proof_bytes: "proof_data", public_inputs: "inputs",
                      report_data: VALID_MSG_HASH, rtmr3: VALID_RTMR3,
                      valid_from: 20240101000000, valid_until: 20260101000000, tcb_eval: 17, qe_eval: 23 }
  // Empty proof bytes but otherwise valid — exercises the proof-invalid path.
  val EMPTY_PROOF = { proof_bytes: "", public_inputs: "",
                      report_data: VALID_MSG_HASH, rtmr3: VALID_RTMR3,
                      valid_from: 20240101000000, valid_until: 20260101000000, tcb_eval: 17, qe_eval: 23 }
  // Proven window entirely in the past — exercises the recency/validity rejection.
  val STALE_PROOF = { proof_bytes: "proof_data", public_inputs: "inputs",
                      report_data: VALID_MSG_HASH, rtmr3: VALID_RTMR3,
                      valid_from: 20100101000000, valid_until: 20110101000000, tcb_eval: 17, qe_eval: 23 }
  // tcb_eval below the floor (qe_eval fine) — makes the min-of-both floor
  // conjunct load-bearing (a dropped floor check would now be caught).
  val LOW_EVAL_PROOF = { proof_bytes: "proof_data", public_inputs: "inputs",
                      report_data: VALID_MSG_HASH, rtmr3: VALID_RTMR3,
                      valid_from: 20240101000000, valid_until: 20260101000000, tcb_eval: 3, qe_eval: 23 }
  // Valid proof but report_data does not bind to user_data — exercises the
  // check_zk_bindings report_data gate.
  val WRONG_RD_PROOF = { proof_bytes: "proof_data", public_inputs: "inputs",
                      report_data: "wrong_rd", rtmr3: VALID_RTMR3,
                      valid_from: 20240101000000, valid_until: 20260101000000, tcb_eval: 17, qe_eval: 23 }
  // Valid proof but rtmr3 does not match the pinned expected_rtmr3 — exercises
  // the wrong-image binding gate.
  val WRONG_RTMR3_PROOF = { proof_bytes: "proof_data", public_inputs: "inputs",
                      report_data: VALID_MSG_HASH, rtmr3: WRONG_RTMR3,
                      valid_from: 20240101000000, valid_until: 20260101000000, tcb_eval: 17, qe_eval: 23 }

  // ============================================================
  // Initial state
  // ============================================================

  /// Dummy initial input — overwritten by every verify_any step.
  val INIT_INPUT: AttestedMessage = {
    msg_hash: "",
    attestation: {
      variant: Quote,
      user_data: "",
      compose_hash: "",
      quote: "",
      event_log: "",
      proof: EMPTY_PROOF,
    },
  }

  action init = all {
    config' = {
      compose_hash: VALID_COMPOSE_HASH,
      zkdcap_vkey: VALID_VKEY,
      min_tcb_eval: TCB_FLOOR,
      expected_rtmr3: VALID_RTMR3,
      allow_any_image: false,
    },
    zk_module' = {
      registered_vkeys: Set(VALID_VKEY),
      accept_all: false,
    },
    last_result' = SkippedNoVKey,
    messages_accepted' = 0,
    messages_rejected' = 0,
    last_input' = INIT_INPUT,
    last_action' = ActNone,
  }

  // ============================================================
  // Common checks (shared by both variants)
  // ============================================================

  /// Steps 1-2 are identical for both variants: check user_data and compose_hash.
  /// Returns true if both pass, false otherwise (and sets result/counters).
  action check_common(msg: AttestedMessage): bool = all {
    msg.msg_hash == msg.attestation.user_data,
    msg.attestation.compose_hash == config.compose_hash,
  }

  // ============================================================
  // DstackAttestation handler (raw quote)
  // ============================================================

  /// Verify a raw quote attestation.
  /// Checks user_data + compose_hash, then accepts.
  /// The raw quote is available for off-chain or future on-chain DCAP verification.
  action verify_quote(msg: AttestedMessage): bool = all {
    msg.attestation.variant == Quote,
    if (msg.msg_hash != msg.attestation.user_data) {
      all {
        last_result' = RejectedUserDataMismatch,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyQuote,
      }
    } else if (msg.attestation.compose_hash != config.compose_hash) {
      all {
        last_result' = RejectedComposeHashMismatch,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyQuote,
      }
    } else {
      // Quote accepted — user_data and compose_hash verified
      all {
        last_result' = AcceptedQuote,
        messages_accepted' = messages_accepted + 1,
        messages_rejected' = messages_rejected,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyQuote,
      }
    },
  }

  // ============================================================
  // DstackZkAttestation handler (zkdcap proof)
  // ============================================================

  /// Verify a ZK proof attestation.
  /// Checks user_data + compose_hash, then queries ZK module.
  action verify_zk(msg: AttestedMessage): bool = all {
    msg.attestation.variant == Zk,
    if (msg.msg_hash != msg.attestation.user_data) {
      all {
        last_result' = RejectedUserDataMismatch,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else if (msg.attestation.compose_hash != config.compose_hash) {
      all {
        last_result' = RejectedComposeHashMismatch,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else if (config.zkdcap_vkey == "") {
      // No vkey configured — skip ZK verification
      all {
        last_result' = SkippedNoVKey,
        messages_accepted' = messages_accepted + 1,
        messages_rejected' = messages_rejected,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else if (not(zk_module.registered_vkeys.contains(config.zkdcap_vkey))) {
      // vkey not registered in ZK module
      all {
        last_result' = RejectedVKeyNotFound,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else if (msg.attestation.proof.valid_from > CHAIN_TIME
               or CHAIN_TIME > msg.attestation.proof.valid_until
               or msg.attestation.proof.tcb_eval < config.min_tcb_eval
               or msg.attestation.proof.qe_eval < config.min_tcb_eval) {
      // Recency/validity gate: chain time must lie inside the proof's proven
      // [valid_from, valid_until] window AND min(tcb_eval, qe_eval) must clear
      // the floor (here: either eval below the floor rejects). The circuit
      // proves the window but has no clock/counter.
      all {
        last_result' = RejectedStaleOrFuture,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else if (msg.attestation.proof.proof_bytes == "" and not(zk_module.accept_all)) {
      // Empty proof rejected (unless mock mode)
      all {
        last_result' = RejectedZkProofInvalid,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else if (msg.attestation.proof.report_data != msg.attestation.user_data
               or (config.expected_rtmr3 != "" and msg.attestation.proof.rtmr3 != config.expected_rtmr3)
               or (config.expected_rtmr3 == "" and not(config.allow_any_image))) {
      // Binding gate (check_zk_bindings, runs after proof verification): the
      // decoded report_data MUST equal the wrapper user_data (always); the
      // decoded rtmr3 MUST equal the pinned expected_rtmr3 (only when pinned);
      // and SECURE-BY-DEFAULT, if no register is pinned, verification is
      // rejected unless allow_any_image is set (the require-one rule).
      all {
        last_result' = RejectedBindingMismatch,
        messages_rejected' = messages_rejected + 1,
        messages_accepted' = messages_accepted,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    } else {
      // ZK proof verified + bound
      all {
        last_result' = Accepted,
        messages_accepted' = messages_accepted + 1,
        messages_rejected' = messages_rejected,
        config' = config,
        zk_module' = zk_module,
        last_input' = msg,
        last_action' = ActVerifyZk,
      }
    },
  }

  // ============================================================
  // DstackAnyAttestation handler (delegates to variant)
  // ============================================================

  /// Verify any attestation — delegates to the appropriate handler
  action verify_any(msg: AttestedMessage): bool = {
    if (msg.attestation.variant == Quote)
      verify_quote(msg)
    else
      verify_zk(msg)
  }

  // ============================================================
  // Config actions
  // ============================================================

  /// Enable mock mode (accept any proof)
  action enable_mock: bool = all {
    zk_module' = { ...zk_module, accept_all: true },
    config' = config,
    last_result' = last_result,
    messages_accepted' = messages_accepted,
    messages_rejected' = messages_rejected,
    last_input' = last_input,
    last_action' = ActEnableMock,
  }

  /// Remove vkey configuration (skip ZK verification for Zk variant)
  action clear_vkey: bool = all {
    config' = { ...config, zkdcap_vkey: "" },
    zk_module' = zk_module,
    last_result' = last_result,
    messages_accepted' = messages_accepted,
    messages_rejected' = messages_rejected,
    last_input' = last_input,
    last_action' = ActClearVkey,
  }

  /// Unpin the image (no register pinned). Makes the secure-by-default
  /// require-one reject path reachable.
  action clear_image_pin: bool = all {
    config' = { ...config, expected_rtmr3: "" },
    zk_module' = zk_module,
    last_result' = last_result,
    messages_accepted' = messages_accepted,
    messages_rejected' = messages_rejected,
    last_input' = last_input,
    last_action' = ActClearImagePin,
  }

  /// Opt into the allow-any-image escape hatch.
  action allow_any_image: bool = all {
    config' = { ...config, allow_any_image: true },
    zk_module' = zk_module,
    last_result' = last_result,
    messages_accepted' = messages_accepted,
    messages_rejected' = messages_rejected,
    last_input' = last_input,
    last_action' = ActAllowAnyImage,
  }

  // ============================================================
  // Step
  // ============================================================

  action step = {
    nondet msg_hash = oneOf(Set(VALID_MSG_HASH, "wrong_hash"))
    nondet user_data = oneOf(Set(VALID_MSG_HASH, "wrong_hash", "tampered"))
    nondet compose_hash = oneOf(Set(VALID_COMPOSE_HASH, WRONG_COMPOSE_HASH))
    nondet proof = oneOf(Set(VALID_PROOF, EMPTY_PROOF, STALE_PROOF, LOW_EVAL_PROOF, WRONG_RD_PROOF, WRONG_RTMR3_PROOF))
    nondet att_variant = oneOf(Set(Quote, Zk))
    nondet quote = oneOf(Set(VALID_QUOTE, ""))
    val msg: AttestedMessage = {
      msg_hash: msg_hash,
      attestation: {
        variant: att_variant,
        user_data: user_data,
        compose_hash: compose_hash,
        quote: quote,
        event_log: "",
        proof: proof,
      },
    }
    any {
      verify_any(msg),
      enable_mock,
      clear_vkey,
      clear_image_pin,
      allow_any_image,
    }
  }

  // ============================================================
  // Invariants
  // ============================================================

  /// Counters are non-negative
  val inv_counters_non_negative: bool = {
    messages_accepted >= 0 and messages_rejected >= 0
  }

  /// Counters are consistent
  val inv_counters_consistent: bool = {
    messages_accepted + messages_rejected >= 0
  }

  /// A message with wrong user_data is never accepted.
  /// Real check: whenever last_result is an acceptance, last_input's
  /// msg_hash and attestation.user_data must have matched.
  val inv_user_data_mismatch_rejected: bool = {
    if (last_result == Accepted or last_result == AcceptedQuote
        or last_result == SkippedNoVKey)
      last_input.msg_hash == last_input.attestation.user_data
    else true
  }

  /// A message with wrong compose_hash is never accepted (after the
  /// dummy init state, which we exclude via the input being non-empty).
  val inv_compose_hash_mismatch_rejected: bool = {
    if ((last_result == Accepted or last_result == AcceptedQuote
         or last_result == SkippedNoVKey)
        and last_input.msg_hash != "")
      last_input.attestation.compose_hash == config.compose_hash
    else true
  }

  /// Quote variant never produces a Zk-only outcome and vice versa.
  /// The handler dispatch must keep these paths disjoint.
  ///
  /// **Action-tag refactor (Round C Claude #10 + Gemma framework #6,
  /// 2026-05-14)**: previously predicated on
  /// `last_input.attestation.variant`. Because `enable_mock` and
  /// `clear_vkey` preserve `last_input' = last_input`, that state-
  /// only predicate binds on STALE input data after non-verify
  /// actions (Round-1 S1 single-shot-binding hazard). Switched to
  /// `last_action` provenance. The `last_action` tag is precise per
  /// action, so the `msg_hash != ""` filter is unnecessary — the
  /// invariant simply does not fire on init/enable_mock/clear_vkey.
  ///
  /// The bind is now: when last_action is a verify, last_result must
  /// be in the verify's allowed outcome set. After non-verify
  /// actions (init, enable_mock, clear_vkey), the invariant is
  /// vacuously true — those actions don't produce variant-specific
  /// outcomes.
  val inv_variant_outcome_consistent: bool = {
    if (last_action == ActVerifyQuote)
      // Quote path produces AcceptedQuote / user_data / compose_hash rejections
      last_result == AcceptedQuote
        or last_result == RejectedUserDataMismatch
        or last_result == RejectedComposeHashMismatch
    else if (last_action == ActVerifyZk)
      // Zk path produces Accepted / SkippedNoVKey / Zk-specific rejections
      last_result == Accepted
        or last_result == SkippedNoVKey
        or last_result == RejectedUserDataMismatch
        or last_result == RejectedComposeHashMismatch
        or last_result == RejectedVKeyNotFound
        or last_result == RejectedStaleOrFuture
        or last_result == RejectedBindingMismatch
        or last_result == RejectedZkProofInvalid
    else true
  }

  /// Zk variant Accepted is action-local: at the moment of acceptance,
  /// the vkey must have been set and registered. We cannot express
  /// this as a state-only invariant because `clear_vkey` can run
  /// after the verify and `last_result` is a frozen past decision.
  /// The check `config.zkdcap_vkey != "" && registered_vkeys.contains(...)`
  /// is enforced action-locally inside `verify_zk` (the else-if chain
  /// short-circuits to RejectedVKeyNotFound or SkippedNoVKey otherwise).
  ///
  /// State-only stub kept as `true` — the real obligation is captured
  /// by the temporal property `temporal_zk_accept_requires_vkey` below.
  val inv_zk_accept_requires_vkey: bool = true

  /// UltraHonk recency: whenever a ZK verify reaches `Accepted`, the accepted
  /// proof's proven validity window contained the chain time AND its tcb_eval
  /// cleared the floor. CHAIN_TIME and config.min_tcb_eval are stable (no
  /// action mutates them), so this acceptance-implies-recency obligation is
  /// state-checkable. Mirrors the `recency_ok` gate in the Verus prototype and
  /// `quartz_zkdcap::verify_quote_parts`.
  val inv_zk_accept_requires_recency: bool = {
    if (last_action == ActVerifyZk and last_result == Accepted)
      last_input.attestation.proof.valid_from <= CHAIN_TIME
        and CHAIN_TIME <= last_input.attestation.proof.valid_until
        and last_input.attestation.proof.tcb_eval >= config.min_tcb_eval
        and last_input.attestation.proof.qe_eval >= config.min_tcb_eval
    else true
  }

  /// check_zk_bindings: whenever a ZK verify reaches `Accepted`, the accepted
  /// proof's decoded report_data equals the wrapper user_data (ALWAYS), and its
  /// decoded rtmr3 equals the pinned config.expected_rtmr3 when one is pinned
  /// (the conditional mirrors production: expected_rtmr3 == "" ⇒ skipped).
  /// Mirrors check_zk_bindings in the production handler and the Verus
  /// proof_binds_report_data / proof_binds_rtmr3 gates.
  val inv_zk_accept_requires_binding: bool = {
    if (last_action == ActVerifyZk and last_result == Accepted)
      last_input.attestation.proof.report_data == last_input.attestation.user_data
        and (config.expected_rtmr3 == ""
             or last_input.attestation.proof.rtmr3 == config.expected_rtmr3)
    else true
  }

  // ============================================================
  // Temporal properties
  // ============================================================
  //
  // Quint 0.32.0 supports temporal properties via Apalache (marked
  // experimental). These complement the state-only invariants by
  // pinning down action-local obligations using `next(...)` to
  // observe the state that triggered a transition into `Accepted`.

  /// REVISED 2026-05-12 — rewritten after multi-model adversarial review.
  /// See `.colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-...`.
  ///
  /// At the moment `verify_zk` fires and produces `last_result == Accepted`,
  /// the pre-transition `config.zkdcap_vkey` was non-empty, was registered
  /// in the ZK module, AND (because `accept_all` mode bypasses the empty-
  /// proof rejection) the message's proof bytes were non-empty unless mock
  /// mode was explicitly enabled.
  ///
  /// **Why predicate on `last_action == ActVerifyZk` instead of state alone:**
  /// the property's witness is "the verifier ran and reached its accept
  /// branch". A pure state predicate (`last_input.attestation.variant == Zk
  /// and last_result == Accepted`) could be satisfied by a hypothetical
  /// future action that resets state without running the verifier (e.g. an
  /// audit-replay action that assigns `last_result' = Accepted` and
  /// `last_input' = some_old_zk_msg`). The action tag makes provenance
  /// load-bearing rather than inferred.
  ///
  /// Both Claude and Gemma adversaries proposed substantively this form.
  /// The mock-mode conjunct closes a separate critical finding (mock mode
  /// + empty proof reaches Accepted while vkey state appears satisfied).
  temporal temporal_zk_accept_requires_vkey = always(
    (next(last_action) == ActVerifyZk
     and next(last_result) == Accepted)
    implies (config.zkdcap_vkey != ""
             and zk_module.registered_vkeys.contains(config.zkdcap_vkey)
             and (not(zk_module.accept_all)
                  or next(last_input.attestation.proof.proof_bytes) != ""))
  )

  /// Secure-by-default image binding (require-one). At the moment `verify_zk`
  /// produces `Accepted`, the then-current config had EITHER a pinned image
  /// register OR `allow_any_image` explicitly set — you cannot accept a proof
  /// while leaving the image unbound by accident. Temporal (not state) form for
  /// the same reason as the vkey property: `clear_image_pin`/`allow_any_image`
  /// are separate transitions, and `verify_zk` preserves config, so the
  /// pre-transition config IS the config the verifier used. Mirrors the
  /// require-one gate in the production handler and the Verus model.
  temporal temporal_zk_accept_requires_image = always(
    (next(last_action) == ActVerifyZk
     and next(last_result) == Accepted)
    implies (config.expected_rtmr3 != "" or config.allow_any_image)
  )

  /// Once mock mode is enabled (`accept_all = true`), it stays enabled.
  /// No action writes `accept_all = false`. The temporal form makes the
  /// monotonicity guarantee explicit at every transition.
  temporal temporal_mock_mode_monotonic = always(
    zk_module.accept_all implies next(zk_module.accept_all)
  )

  /// Once mock-mode is enabled it stays enabled — clear_vkey does
  /// not reset accept_all. Captures a regression risk where toggling
  /// the vkey could be confused for resetting test mode.
  val inv_mock_mode_monotonic: bool = {
    // This is a state-only invariant: if accept_all is true, no action
    // sets it back to false. Verified by exhaustive transition search.
    true
    // (The model enforces this: enable_mock sets accept_all=true and
    // no other action writes accept_all=false. Promoting to a state
    // check would require tracking history of accept_all values.)
  }

  val all_invariants: bool = {
    inv_counters_non_negative
    and inv_counters_consistent
    and inv_user_data_mismatch_rejected
    and inv_compose_hash_mismatch_rejected
    and inv_variant_outcome_consistent
    and inv_zk_accept_requires_vkey
    and inv_zk_accept_requires_recency
    and inv_zk_accept_requires_binding
  }
}
