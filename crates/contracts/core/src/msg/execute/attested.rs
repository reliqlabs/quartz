use std::{convert::Into, default::Default};

use cosmwasm_schema::{cw_serde, schemars};
use cosmwasm_std::{HexBinary, StdError};
use serde::Serialize;

#[cfg(not(feature = "mock"))]
pub type DefaultAttestation = DstackAnyAttestation;
#[cfg(not(feature = "mock"))]
pub type RawDefaultAttestation = RawDstackAnyAttestation;

#[cfg(feature = "mock")]
pub type DefaultAttestation = MockAttestation;
#[cfg(feature = "mock")]
pub type RawDefaultAttestation = RawMockAttestation;

use crate::{
    msg::HasDomainType,
    state::{MrEnclave, UserData},
};

/// A wrapper struct for holding a message and it's attestation.
#[derive(Clone, Debug, PartialEq)]
pub struct Attested<M, A> {
    pub msg: M,
    pub attestation: A,
}

impl<M, A> Attested<M, A> {
    pub fn new(msg: M, attestation: A) -> Self {
        Self { msg, attestation }
    }

    pub fn into_tuple(self) -> (M, A) {
        let Attested { msg, attestation } = self;
        (msg, attestation)
    }

    pub fn msg(&self) -> &M {
        &self.msg
    }

    pub fn attestation(&self) -> &A {
        &self.attestation
    }
}

#[cw_serde]
pub struct RawAttested<RM, RA> {
    pub msg: RM,
    pub attestation: RA,
}

impl<RM, RA> TryFrom<RawAttested<RM, RA>> for Attested<RM::DomainType, RA::DomainType>
where
    RM: HasDomainType,
    RA: HasDomainType,
{
    type Error = StdError;

    fn try_from(value: RawAttested<RM, RA>) -> Result<Self, Self::Error> {
        Ok(Self {
            msg: value.msg.try_into()?,
            attestation: value.attestation.try_into()?,
        })
    }
}

impl<RM, RA> From<Attested<RM::DomainType, RA::DomainType>> for RawAttested<RM, RA>
where
    RM: HasDomainType,
    RA: HasDomainType,
{
    fn from(value: Attested<RM::DomainType, RA::DomainType>) -> Self {
        Self {
            msg: value.msg.into(),
            attestation: value.attestation.into(),
        }
    }
}

impl<RM, RA> HasDomainType for RawAttested<RM, RA>
where
    RM: HasDomainType,
    RA: HasDomainType,
{
    type DomainType = Attested<RM::DomainType, RA::DomainType>;
}

/// A trait that defines how to extract user data from a given type.
pub trait HasUserData {
    fn user_data(&self) -> UserData;
}

pub fn user_data_json<T: Serialize>(value: &T) -> UserData {
    use serde_json::to_string;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(to_string(value).expect("infallible serializer"));
    let digest: [u8; 32] = hasher.finalize().into();

    let mut user_data = [0u8; 64];
    user_data[0..32].copy_from_slice(&digest);
    user_data
}

pub trait Attestation {
    fn mr_enclave(&self) -> MrEnclave;
}

// ── Mock Attestation ───────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct MockAttestation(pub UserData);

impl Default for MockAttestation {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

#[cw_serde]
pub struct RawMockAttestation(pub HexBinary);

impl TryFrom<RawMockAttestation> for MockAttestation {
    type Error = StdError;

    fn try_from(value: RawMockAttestation) -> Result<Self, Self::Error> {
        Ok(Self(value.0.to_array()?))
    }
}

impl From<MockAttestation> for RawMockAttestation {
    fn from(value: MockAttestation) -> Self {
        Self(value.0.into())
    }
}

impl HasDomainType for RawMockAttestation {
    type DomainType = MockAttestation;
}

impl HasUserData for MockAttestation {
    fn user_data(&self) -> UserData {
        self.0
    }
}

impl Attestation for MockAttestation {
    fn mr_enclave(&self) -> MrEnclave {
        Default::default()
    }
}

// ── Dstack Attestation (raw quote, verified by on-chain DCAP) ──────

/// TDX attestation carrying the raw TDX DCAP quote.
///
/// NOTE: on-chain DCAP verification is NOT implemented. The handler for this
/// variant fails closed (`Error::RawDcapUnsupported`) unless the contract is
/// built with the `insecure-accept-raw-quote` feature (dev/test only). Use the
/// `DstackZkAttestation` (zkdcap UltraHonk) path for verified attestation. This
/// variant exists for a future native on-chain DCAP verifier or off-chain use.
#[derive(Clone, Debug, PartialEq)]
pub struct DstackAttestation {
    /// The user data (report_data) embedded in the TDX quote
    pub user_data: UserData,
    /// compose-hash: the TDX equivalent of mr_enclave (from RTMR3)
    pub compose_hash: MrEnclave,
    /// Raw TDX DCAP quote bytes
    pub quote: Vec<u8>,
    /// Optional RTMR event log (for RTMR replay verification)
    pub event_log: Option<String>,
}

impl DstackAttestation {
    pub fn new(
        user_data: UserData,
        compose_hash: MrEnclave,
        quote: Vec<u8>,
        event_log: Option<String>,
    ) -> Self {
        Self {
            user_data,
            compose_hash,
            quote,
            event_log,
        }
    }
}

#[cw_serde]
pub struct RawDstackAttestation {
    pub user_data: HexBinary,
    pub compose_hash: HexBinary,
    pub quote: HexBinary,
    pub event_log: Option<String>,
}

impl TryFrom<RawDstackAttestation> for DstackAttestation {
    type Error = StdError;

    fn try_from(value: RawDstackAttestation) -> Result<Self, Self::Error> {
        Ok(Self {
            user_data: value.user_data.to_array()?,
            compose_hash: value.compose_hash.to_array()?,
            quote: value.quote.into(),
            event_log: value.event_log,
        })
    }
}

impl From<DstackAttestation> for RawDstackAttestation {
    fn from(value: DstackAttestation) -> Self {
        Self {
            user_data: value.user_data.into(),
            compose_hash: value.compose_hash.into(),
            quote: value.quote.into(),
            event_log: value.event_log,
        }
    }
}

impl HasDomainType for RawDstackAttestation {
    type DomainType = DstackAttestation;
}

impl HasUserData for DstackAttestation {
    fn user_data(&self) -> UserData {
        self.user_data
    }
}

impl Attestation for DstackAttestation {
    fn mr_enclave(&self) -> MrEnclave {
        self.compose_hash
    }
}

// ── Dstack ZK Attestation (zkdcap UltraHonk proof, verified via ZK module) ──

/// TDX attestation using a dcap-noir UltraHonk proof.
///
/// The raw TDX quote is compressed into an UltraHonk proof verified by the
/// chain's ZK module (`/xion.zk.v1.Query/ProofVerifyUltraHonk`). The packed
/// `zkdcap_public_inputs` (672 bytes / 21 BN254 field elements) carry every
/// field the contract binds against: measurements (MRTD, RTMR0..3),
/// report_data, tcb_status, timestamp, and the recency window
/// (tcb_eval_num, qe_eval_num, valid_from, valid_until). There is no separate
/// journal — the public inputs ARE the journal.
///
/// Smaller on-chain footprint, but requires proof generation (Noir/bb prover).
#[derive(Clone, Debug, PartialEq)]
pub struct DstackZkAttestation {
    /// The user data (report_data) embedded in the TDX quote
    pub user_data: UserData,
    /// compose-hash: the TDX equivalent of mr_enclave (from RTMR3)
    pub compose_hash: MrEnclave,
    /// UltraHonk proof bytes
    pub zkdcap_proof: Vec<u8>,
    /// Packed UltraHonk public inputs: 672 bytes / 21 BE BN254 field elements
    /// (the dcap-noir layout; see `quartz_zkdcap::layout`).
    pub zkdcap_public_inputs: Vec<u8>,
    /// dstack RTMR3 event log (JSON array of `TdxEvent`). Used only when the
    /// config pins `expected_compose_hash`: the handler replays it against the
    /// proof-bound RTMR3 and binds the compose-hash. Host-supplied but
    /// non-load-bearing — the replay anchors on the proof's RTMR3.
    pub event_log: Option<String>,
}

impl DstackZkAttestation {
    pub fn new(
        user_data: UserData,
        compose_hash: MrEnclave,
        zkdcap_proof: Vec<u8>,
        zkdcap_public_inputs: Vec<u8>,
        event_log: Option<String>,
    ) -> Self {
        Self {
            user_data,
            compose_hash,
            zkdcap_proof,
            zkdcap_public_inputs,
            event_log,
        }
    }
}

#[cw_serde]
pub struct RawDstackZkAttestation {
    pub user_data: HexBinary,
    pub compose_hash: HexBinary,
    pub zkdcap_proof: HexBinary,
    pub zkdcap_public_inputs: HexBinary,
    #[serde(default)]
    pub event_log: Option<String>,
}

impl TryFrom<RawDstackZkAttestation> for DstackZkAttestation {
    type Error = StdError;

    fn try_from(value: RawDstackZkAttestation) -> Result<Self, Self::Error> {
        Ok(Self {
            user_data: value.user_data.to_array()?,
            compose_hash: value.compose_hash.to_array()?,
            zkdcap_proof: value.zkdcap_proof.into(),
            zkdcap_public_inputs: value.zkdcap_public_inputs.into(),
            event_log: value.event_log,
        })
    }
}

impl From<DstackZkAttestation> for RawDstackZkAttestation {
    fn from(value: DstackZkAttestation) -> Self {
        Self {
            user_data: value.user_data.into(),
            compose_hash: value.compose_hash.into(),
            zkdcap_proof: value.zkdcap_proof.into(),
            zkdcap_public_inputs: value.zkdcap_public_inputs.into(),
            event_log: value.event_log,
        }
    }
}

impl HasDomainType for RawDstackZkAttestation {
    type DomainType = DstackZkAttestation;
}

impl HasUserData for DstackZkAttestation {
    fn user_data(&self) -> UserData {
        self.user_data
    }
}

impl Attestation for DstackZkAttestation {
    fn mr_enclave(&self) -> MrEnclave {
        self.compose_hash
    }
}

// ── DstackAnyAttestation (accepts either variant) ──────────────────

/// Enum that accepts either a raw quote or a ZK proof attestation.
///
/// Used as `DefaultAttestation` so contracts can accept whichever the
/// host submits — raw DstackAttestation when no noir prover is
/// available, or DstackZkAttestation when one is.
#[derive(Clone, Debug, PartialEq)]
pub enum DstackAnyAttestation {
    Quote(DstackAttestation),
    Zk(DstackZkAttestation),
}

/// Raw (serializable) enum for DstackAnyAttestation.
///
/// Uses `untagged` serde — the two variants have distinct field sets
/// (quote vs zkdcap_proof) so deserialization is unambiguous.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RawDstackAnyAttestation {
    /// Try ZK first — has zkdcap_proof field
    Zk(RawDstackZkAttestation),
    /// Fallback to raw quote — has quote field
    Quote(RawDstackAttestation),
}

impl TryFrom<RawDstackAnyAttestation> for DstackAnyAttestation {
    type Error = StdError;

    fn try_from(value: RawDstackAnyAttestation) -> Result<Self, Self::Error> {
        match value {
            RawDstackAnyAttestation::Quote(raw) => Ok(Self::Quote(raw.try_into()?)),
            RawDstackAnyAttestation::Zk(raw) => Ok(Self::Zk(raw.try_into()?)),
        }
    }
}

impl From<DstackAnyAttestation> for RawDstackAnyAttestation {
    fn from(value: DstackAnyAttestation) -> Self {
        match value {
            DstackAnyAttestation::Quote(a) => Self::Quote(a.into()),
            DstackAnyAttestation::Zk(a) => Self::Zk(a.into()),
        }
    }
}

impl HasDomainType for RawDstackAnyAttestation {
    type DomainType = DstackAnyAttestation;
}

impl HasUserData for DstackAnyAttestation {
    fn user_data(&self) -> UserData {
        match self {
            Self::Quote(a) => a.user_data(),
            Self::Zk(a) => a.user_data(),
        }
    }
}

impl Attestation for DstackAnyAttestation {
    fn mr_enclave(&self) -> MrEnclave {
        match self {
            Self::Quote(a) => a.mr_enclave(),
            Self::Zk(a) => a.mr_enclave(),
        }
    }
}

// ── Noop wrapper ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct Noop<T>(pub T);

#[cw_serde]
pub struct RawNoop<T>(pub T);

impl<T: Serialize> HasDomainType for RawNoop<T> {
    type DomainType = Noop<T>;
}

impl<T> HasUserData for Noop<T>
where
    T: HasUserData,
{
    fn user_data(&self) -> UserData {
        self.0.user_data()
    }
}

impl<T> TryFrom<RawNoop<T>> for Noop<T> {
    type Error = StdError;

    fn try_from(value: RawNoop<T>) -> Result<Self, Self::Error> {
        Ok(Self(value.0))
    }
}

impl<T> From<Noop<T>> for RawNoop<T> {
    fn from(value: Noop<T>) -> Self {
        Self(value.0)
    }
}
