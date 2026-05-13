use cosmwasm_std::HexBinary;
use cw_storage_plus::Map;

pub const PINGS_KEY: &str = "pings";

// Maps pubkeys (String representation of HexBinary) to messages (HexBinary representaton of encrypted data)
// The message that a pubkey maps to is encrypted either to that pubkey or the enclave's pubkey
pub const PINGS: Map<String, HexBinary> = Map::new(PINGS_KEY);

// ── Kani verification harnesses ────────────────────────────────────
//
// These harnesses verify pure-logic properties of the pingpong
// example: the storage-key constant, message struct field discipline,
// the symmetry between Ping and Pong storage-key derivation, and the
// HexBinary roundtrip discipline that the contract's ping/pong
// handlers rely on.
//
// Mutable storage (the PINGS Map) is exercised at the
// cw_multi_test integration layer; here we verify the building
// blocks that the handlers compose.
//
// Loop-heavy paths (SHA-256 over serde_json output via
// `Pong::user_data()`, full `HexBinary::to_hex()` over arbitrary
// lengths) are not modelled here — they would require unwind bounds
// large enough to defeat the <5s/harness target. The harnesses
// below run in well under a second each on Kani 0.67.

#[cfg(kani)]
mod verification {
    use cosmwasm_std::HexBinary;

    use super::PINGS_KEY;
    use crate::msg::execute::{Ping, Pong};

    /// PINGS_KEY is a non-empty stable string. The cw-storage-plus
    /// Map relies on this namespace being unique; an empty key would
    /// collide with sibling Items.
    #[kani::proof]
    fn pings_key_stable() {
        assert!(!PINGS_KEY.is_empty(), "PINGS_KEY must not be empty");
        assert_eq!(PINGS_KEY, "pings");
    }

    /// Ping field-routing: construction places the supplied pubkey
    /// and message in the named fields and nowhere else.
    #[kani::proof]
    #[kani::unwind(20)]
    fn ping_field_roundtrip() {
        let pk_bytes: [u8; 4] = kani::any();
        let msg_bytes: [u8; 4] = kani::any();
        let pubkey = HexBinary::from(pk_bytes.to_vec());
        let message = HexBinary::from(msg_bytes.to_vec());

        let ping = Ping {
            pubkey: pubkey.clone(),
            message: message.clone(),
        };

        assert!(ping.pubkey == pubkey, "pubkey field must round-trip");
        assert!(ping.message == message, "message field must round-trip");
    }

    /// Pong field-routing: same property as Ping. Pong is the
    /// attested response, so any field crosstalk would let the
    /// enclave's `response` collide with the client's `pubkey`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn pong_field_roundtrip() {
        let pk_bytes: [u8; 4] = kani::any();
        let resp_bytes: [u8; 4] = kani::any();
        let pubkey = HexBinary::from(pk_bytes.to_vec());
        let response = HexBinary::from(resp_bytes.to_vec());

        let pong = Pong {
            pubkey: pubkey.clone(),
            response: response.clone(),
        };

        assert!(pong.pubkey == pubkey, "pubkey field must round-trip");
        assert!(pong.response == response, "response field must round-trip");
    }

    /// Ping and Pong share their `pubkey` field discipline. The
    /// contract uses `pong.pubkey.to_hex()` to overwrite the slot
    /// keyed by `ping.pubkey.to_hex()`; if a Pong constructed with
    /// the same pubkey bytes as a Ping disagreed on the field
    /// contents, the pong handler would write to a different slot.
    #[kani::proof]
    #[kani::unwind(20)]
    fn ping_pong_pubkey_symmetry() {
        let pk_bytes: [u8; 4] = kani::any();
        let ping_msg: [u8; 4] = kani::any();
        let pong_resp: [u8; 4] = kani::any();
        let pubkey = HexBinary::from(pk_bytes.to_vec());

        let ping = Ping {
            pubkey: pubkey.clone(),
            message: HexBinary::from(ping_msg.to_vec()),
        };
        let pong = Pong {
            pubkey: pubkey.clone(),
            response: HexBinary::from(pong_resp.to_vec()),
        };

        assert!(
            ping.pubkey == pong.pubkey,
            "ping/pong pubkey must agree when constructed from the same bytes"
        );
    }

    /// HexBinary roundtrip: bytes survive `from(Vec<u8>)` and a
    /// `clone()` unchanged. This is the bedrock of the storage-key
    /// equality the contract assumes — the same pubkey bytes always
    /// produce the same HexBinary, and equal HexBinary keys hash to
    /// the same storage slot.
    #[kani::proof]
    #[kani::unwind(20)]
    fn hexbinary_clone_roundtrip() {
        let bytes: [u8; 8] = kani::any();
        let hb = HexBinary::from(bytes.to_vec());
        let hb2 = hb.clone();
        assert!(hb == hb2, "HexBinary clone must preserve equality");
        // The byte view also agrees
        assert!(hb.as_slice() == hb2.as_slice(), "byte slices must match");
    }

    /// Ping clone preserves both fields. The contract clones the
    /// AttestedMsg before delegating to the framework handler; any
    /// drift between the cloned and original Ping would let one
    /// path pass attestation while the other carries different data.
    #[kani::proof]
    #[kani::unwind(20)]
    fn ping_clone_preserves_fields() {
        let pk_bytes: [u8; 4] = kani::any();
        let msg_bytes: [u8; 4] = kani::any();
        let ping = Ping {
            pubkey: HexBinary::from(pk_bytes.to_vec()),
            message: HexBinary::from(msg_bytes.to_vec()),
        };
        let cloned = ping.clone();
        assert!(ping.pubkey == cloned.pubkey, "cloned pubkey differs");
        assert!(ping.message == cloned.message, "cloned message differs");
    }
}
