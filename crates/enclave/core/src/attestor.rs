use log::debug;
use quartz_contract_core::{
    msg::{
        execute::attested::{Attestation, HasUserData, MockAttestation, RawMockAttestation},
        HasDomainType,
    },
    state::MrEnclave,
};
use serde::Serialize;

use crate::backup_restore::{Export, Import};

pub type DefaultAttestor = MockAttestor;

/// The trait defines the interface for generating attestations from within an enclave.
pub trait Attestor: Send + Sync + 'static {
    type Error: ToString;
    type Attestation: Attestation;
    type RawAttestation: HasDomainType<DomainType = Self::Attestation> + Serialize;

    fn quote(&self, user_data: impl HasUserData) -> Result<Vec<u8>, Self::Error>;

    fn mr_enclave(&self) -> Result<MrEnclave, Self::Error>;

    fn attestation(&self, user_data: impl HasUserData) -> Result<Self::Attestation, Self::Error>;
}

/// A mock `Attestor` that creates a quote consisting of just the user report data. (only meant for
/// testing purposes)
#[derive(Clone, PartialEq, Debug, Default)]
pub struct MockAttestor;

impl Attestor for MockAttestor {
    type Error = String;
    type Attestation = MockAttestation;
    type RawAttestation = RawMockAttestation;

    fn quote(&self, user_data: impl HasUserData) -> Result<Vec<u8>, Self::Error> {
        debug!("Generating mock quote");
        let user_data = user_data.user_data();
        Ok(user_data.to_vec())
    }

    fn mr_enclave(&self) -> Result<MrEnclave, Self::Error> {
        debug!("Retrieving mock MRENCLAVE");
        Ok(Default::default())
    }

    fn attestation(&self, user_data: impl HasUserData) -> Result<Self::Attestation, Self::Error> {
        debug!("Generating mock attestation");
        Ok(MockAttestation(user_data.user_data()))
    }
}

#[async_trait::async_trait]
impl Import for MockAttestor {
    type Error = ();

    async fn import(&mut self, _data: Vec<u8>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl Export for MockAttestor {
    type Error = ();

    async fn export(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }
}

