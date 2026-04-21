use std::{convert::Into, default::Default};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError};
use serde::Serialize;

#[cfg(not(feature = "mock"))]
pub type DefaultAttestation = DstackAttestation;
#[cfg(not(feature = "mock"))]
pub type RawDefaultAttestation = RawDstackAttestation;

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

/// TDX attestation using the raw TDX DCAP quote.
///
/// The quote is verified on-chain by the dcap-qvl library or a DCAP
/// verifier contract. Use this when no ZK prover is available, or
/// when the chain supports native DCAP verification.
///
/// Larger on-chain footprint (~1.2 KB quote + collateral) but no
/// proof generation latency.
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

// ── Dstack ZK Attestation (zkdcap proof, verified via ZK module) ───

/// TDX attestation using a zkdcap Groth16 proof.
///
/// The raw TDX quote is compressed into a Groth16 proof (~352 bytes)
/// verified by the chain's ZK module. The journal contains all fields
/// the contract needs (compose_hash, report_data, tcb_status).
///
/// Smaller on-chain footprint, but requires proof generation (~5s gnark).
#[derive(Clone, Debug, PartialEq)]
pub struct DstackZkAttestation {
    /// The user data (report_data) embedded in the TDX quote
    pub user_data: UserData,
    /// compose-hash: the TDX equivalent of mr_enclave (from RTMR3)
    pub compose_hash: MrEnclave,
    /// zkdcap Groth16 proof bytes
    pub zkdcap_proof: Vec<u8>,
    /// zkdcap public inputs
    pub zkdcap_public_inputs: Vec<String>,
    /// zkdcap journal (DcapJournal — contains tcb_status,
    /// measurements, report_data, timestamp)
    pub zkdcap_journal: Vec<u8>,
}

impl DstackZkAttestation {
    pub fn new(
        user_data: UserData,
        compose_hash: MrEnclave,
        zkdcap_proof: Vec<u8>,
        zkdcap_public_inputs: Vec<String>,
        zkdcap_journal: Vec<u8>,
    ) -> Self {
        Self {
            user_data,
            compose_hash,
            zkdcap_proof,
            zkdcap_public_inputs,
            zkdcap_journal,
        }
    }
}

#[cw_serde]
pub struct RawDstackZkAttestation {
    pub user_data: HexBinary,
    pub compose_hash: HexBinary,
    pub zkdcap_proof: HexBinary,
    pub zkdcap_public_inputs: Vec<String>,
    pub zkdcap_journal: HexBinary,
}

impl TryFrom<RawDstackZkAttestation> for DstackZkAttestation {
    type Error = StdError;

    fn try_from(value: RawDstackZkAttestation) -> Result<Self, Self::Error> {
        Ok(Self {
            user_data: value.user_data.to_array()?,
            compose_hash: value.compose_hash.to_array()?,
            zkdcap_proof: value.zkdcap_proof.into(),
            zkdcap_public_inputs: value.zkdcap_public_inputs,
            zkdcap_journal: value.zkdcap_journal.into(),
        })
    }
}

impl From<DstackZkAttestation> for RawDstackZkAttestation {
    fn from(value: DstackZkAttestation) -> Self {
        Self {
            user_data: value.user_data.into(),
            compose_hash: value.compose_hash.into(),
            zkdcap_proof: value.zkdcap_proof.into(),
            zkdcap_public_inputs: value.zkdcap_public_inputs,
            zkdcap_journal: value.zkdcap_journal.into(),
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
