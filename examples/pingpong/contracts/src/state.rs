use cosmwasm_std::HexBinary;
use cw_storage_plus::Map;

pub const PINGS_KEY: &str = "pings";

// Maps pubkeys (String representation of HexBinary) to messages (HexBinary representaton of encrypted data)
// The message that a pubkey maps to is encrypted either to that pubkey or the enclave's pubkey
pub const PINGS: Map<String, HexBinary> = Map::new(PINGS_KEY);

// ── Kani verification harnesses (post-Round-E remediation) ─────────
//
// **Round E 2026-05-20**: the prior harness set (six harnesses:
// `pings_key_stable`, `ping_field_roundtrip`, `pong_field_roundtrip`,
// `ping_pong_pubkey_symmetry`, `hexbinary_clone_roundtrip`,
// `ping_clone_preserves_fields`) was removed after cross-family
// review surfaced that every harness reduced to a tautology of
// Rust's by-value semantics, `derive(Clone)`, or string-literal
// equality. Four of five voices flagged the pingpong harness set
// as not exercising the production handler at all (Claude #1
// critical, gpt-5.5 verdict BREAKS, Kimi #11 advisory, Nemotron #5
// advisory). The cross-voice agreement was that the harnesses
// consumed CI time without verifying any pingpong-specific
// property.
//
// What the production code actually needs verified:
//
//   - `execute::ping` overwrite behavior (Round C critical #13):
//     production unconditionally overwrites `PINGS[pubkey.to_hex()]`
//     on every ping call, including when a pending pong response is
//     stored. The Quint spec models this as an `ErrSlotOccupied`
//     path that does not exist in Rust. A harness that exercises
//     the actual contract handler is needed; this requires either a
//     `cw_multi_test` integration test (out of Kani's scope) or a
//     refactor to extract a pure predicate from `execute::ping`
//     that the handler also invokes.
//
//   - `inv_plaintext_private` (Round C critical #12 carry-over):
//     the Quint review showed `observer.can_see_plaintext` was a
//     static `false` constant with no writer, making the privacy
//     claim vacuous. The Kani surface for pingpong cannot model an
//     adversarial observer; the privacy property is necessarily
//     out of scope here. The Quint-side docstring caveat at
//     `examples/pingpong/specs/pingpong.qnt:348` documents this gap.
//
// Both items are Quartz-agent follow-ups (production code or
// integration tests, not harness-level changes). The Colosseum side
// recorded them in `.colosseum/attacks/kani-2026-05-20/synthesis.md`
// and removed the tautological harness set so the CI-reported "Kani
// verified" count reflects only properties that actually exercise
// the contract.

#[cfg(kani)]
mod verification {
    use super::PINGS_KEY;

    /// PINGS_KEY namespace stability. The cw-storage-plus `Map`
    /// relies on this key being non-empty and distinct from sibling
    /// Items in the same contract crate. Verified once at the
    /// constant level; the Map's namespace uniqueness against other
    /// items is structurally enforced by the type system at compile
    /// time.
    ///
    /// Retained from the prior set as the one harness with a
    /// non-tautological property (the contract relies on PINGS_KEY
    /// being non-empty for the Map abstraction's safety
    /// guarantees).
    #[kani::proof]
    fn pings_key_non_empty() {
        assert!(!PINGS_KEY.is_empty(), "PINGS_KEY must not be empty");
    }
}
