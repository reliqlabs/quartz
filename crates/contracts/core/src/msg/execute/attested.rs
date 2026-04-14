use std::{convert::Into, default::Default};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError};
use serde::Serialize;

pub type DefaultAttestation = MockAttestation;
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
