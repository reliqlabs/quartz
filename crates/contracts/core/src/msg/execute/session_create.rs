use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError};
use sha2::{Digest, Sha256};

use crate::{
    msg::{execute::attested::HasUserData, HasDomainType},
    state::{Nonce, UserData},
};

#[derive(Clone, Debug, PartialEq)]
pub struct SessionCreate {
    nonce: Nonce,
    contract: String,
}

impl SessionCreate {
    pub fn new(nonce: Nonce, contract: String) -> Self {
        Self { nonce, contract }
    }

    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    pub fn contract(&self) -> &str {
        self.contract.as_str()
    }
}

#[cw_serde]
pub struct RawSessionCreate {
    nonce: HexBinary,
    contract: String,
}

impl TryFrom<RawSessionCreate> for SessionCreate {
    type Error = StdError;

    fn try_from(value: RawSessionCreate) -> Result<Self, Self::Error> {
        let nonce = value.nonce.to_array()?;
        let contract = value.contract;
        Ok(Self { nonce, contract })
    }
}

impl From<SessionCreate> for RawSessionCreate {
    fn from(value: SessionCreate) -> Self {
        Self {
            nonce: value.nonce.into(),
            contract: value.contract,
        }
    }
}

impl HasDomainType for RawSessionCreate {
    type DomainType = SessionCreate;
}

impl HasUserData for SessionCreate {
    fn user_data(&self) -> UserData {
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_string(&RawSessionCreate::from(self.clone()))
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

    /// SessionCreate::new + accessors are consistent: nonce()/contract()
    /// return what was passed in. The contract string is fixed ("c") to
    /// avoid Kani's unbounded-string overhead — we're verifying the
    /// struct's field-discipline, not String semantics.
    #[kani::proof]
    fn session_create_accessors() {
        let nonce: Nonce = kani::any();
        let contract = String::from("c");
        let msg = SessionCreate::new(nonce, contract.clone());
        assert_eq!(msg.nonce(), nonce);
        assert_eq!(msg.contract(), contract.as_str());
    }

    /// RawSessionCreate ↔ SessionCreate roundtrip preserves both the
    /// nonce AND the contract field when the nonce HexBinary is
    /// exactly 32 bytes.
    ///
    /// **Round E 2026-05-20 strengthening (GPT-5.5 #2)**: the prior
    /// version asserted only nonce preservation, leaving the contract
    /// field unchecked. A regression in `RawSessionCreate::from(SessionCreate)`
    /// that dropped or rewrote the contract field would have passed
    /// the prior harness. Both fields are now checked.
    #[kani::proof]
    fn session_create_roundtrip() {
        let nonce: Nonce = kani::any();
        let contract = String::from("c");
        let original = SessionCreate::new(nonce, contract.clone());
        let raw: RawSessionCreate = original.clone().into();
        let back = SessionCreate::try_from(raw).expect("32-byte nonce roundtrips");
        assert_eq!(back.nonce(), nonce, "nonce must survive roundtrip");
        assert_eq!(back.contract(), contract.as_str(), "contract must survive roundtrip");
    }

    // **Round E 2026-05-20 attempted addition (Kimi #5), withdrawn**:
    // a `session_create_user_data_deterministic` harness was added
    // and verified locally compile-clean, but CBMC could not bound
    // the SHA-256 + serde_json path within the `<5s/harness` target
    // documented at the top of `state.rs`. A 10-minute test run at
    // `#[kani::unwind(64)]` did not terminate (single CBMC process
    // at 99% CPU; the path-explosion budget for SHA-256's 64-round
    // compression loop combined with serde_json's recursive
    // serialization is the dominant cost). The harness is therefore
    // not landed in this commit.
    //
    // The `HasUserData::user_data()` attestation-critical path
    // remains unverified at the Kani layer. It is covered indirectly
    // by the cw_multi_test integration tests at
    // `tests/integration/`, which exercise the full attestation
    // pipeline end-to-end with concrete inputs. A pure Kani proof
    // would require either:
    //   (a) replacing `serde_json::to_string` with a bounded-size
    //       serialization helper under `#[cfg(kani)]` (would
    //       constitute a production code change — Quartz-agent
    //       scope), or
    //   (b) treating SHA-256 as an uninterpreted function via a
    //       `#[kani::stub]` (would defeat the point of the
    //       determinism check), or
    //   (c) the analogue of the Verus `random oracle` axiom: a
    //       harness that calls `user_data()` twice and asserts byte
    //       equality without exercising the underlying hash, relying
    //       on the standard-library guarantee that SHA-256 is a
    //       pure function. The `assert_eq!` reduces to memory
    //       equality on the returned `[u8; 64]`, which Kani can
    //       check without unwinding the hash if the hash is treated
    //       as an opaque function. This is option (b) in different
    //       framing.
    //
    // Decision (Round E remediation): document the gap; queue (a)
    // for Quartz-agent review (replacing serde_json with a bounded
    // helper would also make the production path more Kani-friendly
    // for other invariants).
}
