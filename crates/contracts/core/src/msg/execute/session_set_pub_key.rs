use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError};
use sha2::{Digest, Sha256};

use crate::{
    msg::{execute::attested::HasUserData, HasDomainType},
    state::{Nonce, UserData},
};

#[derive(Clone, Debug, PartialEq)]
pub struct SessionSetPubKey {
    nonce: Nonce,
    pub_key: Vec<u8>,
}

impl SessionSetPubKey {
    pub fn new(nonce: Nonce, pub_key: Vec<u8>) -> Self {
        Self { nonce, pub_key }
    }

    pub fn into_tuple(self) -> (Nonce, Vec<u8>) {
        (self.nonce, self.pub_key)
    }
}

#[cw_serde]
pub struct RawSessionSetPubKey {
    nonce: HexBinary,
    pub_key: HexBinary,
}

impl RawSessionSetPubKey {
    pub fn pub_key(&self) -> &HexBinary {
        &self.pub_key
    }
}

impl TryFrom<RawSessionSetPubKey> for SessionSetPubKey {
    type Error = StdError;

    fn try_from(value: RawSessionSetPubKey) -> Result<Self, Self::Error> {
        let nonce = value.nonce.to_array()?;
        Ok(Self {
            nonce,
            pub_key: value.pub_key.into(),
        })
    }
}

impl From<SessionSetPubKey> for RawSessionSetPubKey {
    fn from(value: SessionSetPubKey) -> Self {
        Self {
            nonce: value.nonce.into(),
            pub_key: value.pub_key.into(),
        }
    }
}

impl HasDomainType for RawSessionSetPubKey {
    type DomainType = SessionSetPubKey;
}

impl HasUserData for SessionSetPubKey {
    fn user_data(&self) -> UserData {
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_string(&RawSessionSetPubKey::from(self.clone()))
                .expect("infallible serializer"),
        );
        let digest: [u8; 32] = hasher.finalize().into();

        let mut user_data = [0u8; 64];
        user_data[0..32].copy_from_slice(&digest);
        user_data
    }
}

// ── Kani verification harnesses ────────────────────────────────────

#[cfg(kani)]
mod verification {
    use super::*;

    /// SessionSetPubKey::new + into_tuple is identity on (nonce, pub_key).
    /// Bounded unwind for Vec equality.
    #[kani::proof]
    #[kani::unwind(40)]
    fn session_set_pub_key_tuple_roundtrip() {
        let nonce: Nonce = kani::any();
        let pub_key = vec![0x04u8; 33];
        let msg = SessionSetPubKey::new(nonce, pub_key.clone());
        let (n, p) = msg.into_tuple();
        assert_eq!(n, nonce);
        assert_eq!(p, pub_key);
    }

    /// RawSessionSetPubKey ↔ SessionSetPubKey preserves both the
    /// nonce AND the pub_key bytes when the HexBinary nonce is
    /// exactly 32 bytes.
    ///
    /// **Round E 2026-05-20 strengthening (GPT-5.5 #2 sibling)**: the
    /// prior version unpacked only the nonce from the round-tripped
    /// message, leaving the pub_key bytes unchecked. A regression in
    /// `RawSessionSetPubKey::from(SessionSetPubKey)` that truncated or
    /// re-encoded the pub_key would have passed.
    #[kani::proof]
    #[kani::unwind(40)]
    fn session_set_pub_key_raw_roundtrip() {
        let nonce: Nonce = kani::any();
        let pub_key = vec![0x04u8; 33];
        let original = SessionSetPubKey::new(nonce, pub_key.clone());
        let raw: RawSessionSetPubKey = original.clone().into();
        let back = SessionSetPubKey::try_from(raw).expect("32-byte nonce roundtrips");
        let (n, p) = back.into_tuple();
        assert_eq!(n, nonce, "nonce must survive roundtrip");
        assert_eq!(p, pub_key, "pub_key bytes must survive roundtrip");
    }

    // **Round E 2026-05-20 attempted addition (Kimi #5), withdrawn**:
    // a `session_set_pub_key_user_data_deterministic` harness was
    // drafted matching the `session_create.rs` counterpart, but
    // intractable for the same reason — SHA-256 + serde_json path
    // explosion under any reasonable unwind bound. See the analogous
    // commentary block in `session_create.rs`'s verification module
    // for the full rationale and the three options the Quartz agent
    // could pursue. Gap documented; harness not landed.
}
