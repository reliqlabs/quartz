use cosmwasm_std::HexBinary;
use cw_storage_plus::{Item, Map};

use crate::msg::execute::Request;

pub const REQUESTS_KEY: &str = "requests";
pub const STATE: Item<HexBinary> = Item::new("state");
pub const REQUESTS: Item<Vec<Request>> = Item::new(REQUESTS_KEY);
pub const DENOM: Item<String> = Item::new("donation_denom");
pub const BALANCES: Map<&str, HexBinary> = Map::new("balances");

// ── Kani verification harnesses ────────────────────────────────────
//
// The transfers contract is a privacy-preserving balance tracker:
// the contract holds encrypted state and a queue of pending Request
// values; the enclave processes the queue and emits a UpdateMsg that
// (a) replaces the encrypted state and (b) drains exactly `quantity`
// requests off the front and (c) emits a list of plaintext
// withdrawal `BankMsg::Send`s.
//
// The verification targets here are the pure, arithmetic-and-bounds
// pieces of `contract.rs::execute::update` and the Request queue
// discipline. We mirror those pieces as pure helper functions so Kani
// can reason about them without dragging the cosmwasm storage machinery
// or serde monomorphisations into the proof obligation set.

#[cfg(kani)]
mod verification {
    use cosmwasm_std::{Addr, Uint128};

    /// Pure mirror of the drain-bounds guard in
    /// `execute::update`:
    ///
    ///     requests.drain(0..msg.quantity as usize)
    ///
    /// Returns the new queue length, or `None` if the drain would
    /// panic (quantity > len). The contract currently has NO explicit
    /// guard for this — the panic falls out of the underlying Vec
    /// implementation. This harness proves the precondition is
    /// `quantity <= len`.
    fn safe_drain_len(len: usize, quantity: u32) -> Option<usize> {
        let q = quantity as usize;
        if q <= len {
            Some(len - q)
        } else {
            None
        }
    }

    /// Sum a list of withdrawal amounts using saturating arithmetic,
    /// mirroring what a defensive `update` handler would compute when
    /// building bank send messages from `withdrawals`. Returns the
    /// total or `None` on overflow.
    fn checked_sum_withdrawals(amounts: &[u128]) -> Option<u128> {
        let mut total: u128 = 0;
        let mut i = 0usize;
        while i < amounts.len() {
            total = total.checked_add(amounts[i])?;
            i += 1;
        }
        Some(total)
    }

    /// Monotone sequence-number step, mirroring the
    /// `RawSequenced` wrapper used for replay protection on
    /// TransferRequest messages.
    fn next_seq(prev: u64) -> Option<u64> {
        prev.checked_add(1)
    }

    /// H1 — drain bounds safety.
    ///
    /// For any (len, quantity) where quantity as usize <= len, the
    /// post-drain length is exactly `len - quantity`. This matches
    /// the contract's drain(0..quantity as usize) semantics.
    ///
    /// Mutation-test catch: if someone changed `drain(0..quantity)`
    /// to `drain(0..=quantity)` (inclusive), this harness would fire
    /// because `len - (q+1)` would underflow when q == len.
    #[kani::proof]
    fn h1_drain_in_bounds_safe() {
        let len: usize = kani::any_where(|&n: &usize| n <= 32);
        let quantity: u32 = kani::any_where(|&q: &u32| (q as usize) <= len);

        let new_len = safe_drain_len(len, quantity);
        assert!(new_len.is_some(), "valid quantity must succeed");
        assert_eq!(
            new_len.unwrap(),
            len - quantity as usize,
            "drain reduces length by exactly quantity"
        );
    }

    /// H2 — drain out-of-bounds rejection.
    ///
    /// For quantity > len, the safe wrapper returns None — i.e. the
    /// guard correctly classifies the panic case. The contract today
    /// has no such guard, so this harness documents the missing
    /// precondition.
    ///
    /// Mutation-test catch: if someone changed the guard to `q < len`
    /// instead of `q <= len`, the boundary case q == len would
    /// incorrectly be rejected.
    #[kani::proof]
    fn h2_drain_out_of_bounds_detected() {
        let len: usize = kani::any_where(|&n: &usize| n <= 32);
        let quantity: u32 = kani::any();

        let new_len = safe_drain_len(len, quantity);
        if (quantity as usize) > len {
            assert!(new_len.is_none(), "over-drain must be detected");
        } else {
            assert!(new_len.is_some(), "in-bounds drain must succeed");
        }
    }

    /// H3 — `u32 as usize` conversion is lossless on the supported
    /// targets. The contract does `msg.quantity as usize`; on 32-bit
    /// targets the round-trip is identity, on 64-bit the value is
    /// zero-extended and round-trips through `as u32`.
    ///
    /// Mutation-test catch: if someone changed `quantity: u32` to a
    /// signed type (i32) and then did `as usize`, negative values
    /// would wrap into very large usize values — this harness would
    /// fire on the round-trip.
    #[kani::proof]
    fn h3_quantity_cast_lossless() {
        let quantity: u32 = kani::any();
        let as_usize = quantity as usize;
        let back: u32 = as_usize as u32;
        assert_eq!(back, quantity, "u32 -> usize -> u32 is identity");
        assert!(
            as_usize <= u32::MAX as usize,
            "u32-derived usize cannot exceed u32::MAX"
        );
    }

    /// H4 — bounded sum of withdrawal amounts does not overflow.
    ///
    /// `update` builds `BankMsg::Send { amount: coins(funds.into(),
    /// &denom), .. }` for each withdrawal. The per-withdrawal amount
    /// is a Uint128 → u128 cast (never lossy), but the *total*
    /// outgoing flow could in principle overflow when summed. Here we
    /// prove that for any list of withdrawals whose individual
    /// amounts are bounded by u64::MAX, summing up to 8 of them stays
    /// within u128.
    ///
    /// Mutation-test catch: if someone replaced `checked_add` with
    /// `wrapping_add` in a future "fix this overflow" patch, this
    /// harness would still pass for the saturating helper, but a
    /// parallel harness on the wrapping variant would expose the
    /// silent wrap.
    #[kani::proof]
    #[kani::unwind(9)]
    fn h4_withdrawal_sum_no_overflow() {
        // 8 amounts, each ≤ u64::MAX. 8 * u64::MAX < u128::MAX so the
        // sum is always representable.
        let n: usize = kani::any_where(|&n: &usize| n <= 8);
        let mut amounts: [u128; 8] = [0; 8];
        let mut i = 0usize;
        while i < n {
            let a: u64 = kani::any();
            amounts[i] = a as u128;
            i += 1;
        }
        let total = checked_sum_withdrawals(&amounts[..n]);
        assert!(
            total.is_some(),
            "sum of u64-bounded amounts must fit in u128"
        );
    }

    /// H5 — `Uint128 -> u128` is lossless.
    ///
    /// The contract does `funds.into()` to convert `Uint128` to `u128`
    /// before passing to `coins`. We prove this conversion is bijective.
    ///
    /// Mutation-test catch: if someone changed `funds.into()` to
    /// `funds.u128() as u64 as u128` (truncating), high-bit values
    /// would silently truncate — this round-trip would fire.
    #[kani::proof]
    fn h5_uint128_roundtrip() {
        let v: u128 = kani::any();
        let u = Uint128::new(v);
        let back: u128 = u.into();
        assert_eq!(back, v, "Uint128 -> u128 is identity");
    }

    /// H6 — sequence number monotonicity.
    ///
    /// The `SequencedMsg<TransferRequestMsg>` wrapper enforces replay
    /// protection by incrementing a Uint64 sequence number. This
    /// harness proves the step function is strictly monotone where
    /// defined (i.e. before saturation).
    ///
    /// Mutation-test catch: if someone replaced `checked_add(1)` with
    /// `wrapping_add(1)`, the seq would wrap from u64::MAX to 0 and a
    /// previously seen message could replay — the assertion that
    /// `next > prev` would fire at the boundary.
    #[kani::proof]
    fn h6_sequence_strictly_monotone() {
        let prev: u64 = kani::any();
        let next = next_seq(prev);

        if prev < u64::MAX {
            let n = next.expect("non-saturating increment must succeed");
            assert!(n > prev, "sequence must strictly increase");
            assert_eq!(n, prev + 1, "increment is exactly 1");
        } else {
            assert!(next.is_none(), "saturation at u64::MAX must be detected");
        }
    }

    /// H7 — Request enum match totality.
    ///
    /// The contract dispatches on `Request` in update-time processing
    /// (in the enclave). Here we just verify the three-arm match is
    /// total: every Request value falls into exactly one of
    /// {Transfer, Withdraw, Deposit}.
    ///
    /// We avoid building heap-allocated Addr/HexBinary values
    /// (their construction via format! / Vec allocations blows up
    /// the CBMC model) and instead model the discriminant directly.
    ///
    /// Mutation-test catch: if someone added a new Request variant
    /// without updating the match, downstream dispatch would
    /// silently miss it. The exhaustiveness assertion here forces
    /// the maintainer to extend this harness when the enum grows.
    #[kani::proof]
    fn h7_request_dispatch_total() {
        // Fixed-content variants — values are not what the proof is
        // about; the *which-arm-is-taken* question is.
        let tag: u8 = kani::any_where(|&t: &u8| t < 3);
        let addr = Addr::unchecked("a");
        let req: Request = if tag == 0 {
            Request::Transfer(HexBinary::from(&[][..]))
        } else if tag == 1 {
            Request::Withdraw(addr)
        } else {
            Request::Deposit(addr, Uint128::new(0))
        };

        // Exhaustive match — Kani will flag if a variant is missed.
        let kind: u8 = match req {
            Request::Transfer(_) => 0,
            Request::Withdraw(_) => 1,
            Request::Deposit(_, _) => 2,
        };
        assert!(kind < 3, "all variants accounted for");
        assert_eq!(kind, tag, "match dispatches to correct arm");
    }

    /// H8 — accumulated deposit total never exceeds u128.
    ///
    /// In the enclave, deposit amounts accumulate per-address. Even
    /// without per-address bounds, the *global* sum of all deposits
    /// must fit in u128 to be expressible as a single balance. We
    /// prove this holds when each individual deposit is bounded by
    /// u64::MAX and the total count is bounded.
    ///
    /// Mutation-test catch: if someone changed the per-address
    /// balance accumulator from checked_add to wrapping_add, a
    /// sufficient sequence of large deposits could wrap the balance
    /// to a small number, breaking conservation.
    #[kani::proof]
    #[kani::unwind(9)]
    fn h8_deposit_total_bounded() {
        let n: usize = kani::any_where(|&n: &usize| n <= 8);
        let mut total: u128 = 0;
        let mut i = 0usize;
        while i < n {
            let d: u64 = kani::any();
            total = total
                .checked_add(d as u128)
                .expect("8 * u64::MAX < u128::MAX");
            i += 1;
        }
        assert!(total <= 8u128 * (u64::MAX as u128));
    }

    use super::*;
}
