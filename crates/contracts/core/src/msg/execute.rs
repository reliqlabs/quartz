pub mod attested;
pub mod sequenced;
pub mod session_create;
pub mod session_set_pub_key;
pub mod signed;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError};

use crate::msg::{
    execute::{
        attested::{Attested, DefaultAttestation, RawAttested, RawDefaultAttestation},
        session_create::{RawSessionCreate, SessionCreate},
        session_set_pub_key::{RawSessionSetPubKey, SessionSetPubKey},
    },
    HasDomainType,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Execute<Attestation = DefaultAttestation> {
    SessionCreate(Attested<SessionCreate, Attestation>),
    SessionSetPubKey(Attested<SessionSetPubKey, Attestation>),
    /// O3: governed raise-only per-FMSPC TCB-Info floor update.
    SetTcbEvalFloor(SetTcbEvalFloor),
}

#[cw_serde]
pub enum RawExecute<RawAttestation = RawDefaultAttestation> {
    #[serde(rename = "session_create")]
    RawSessionCreate(RawAttested<RawSessionCreate, RawAttestation>),
    #[serde(rename = "session_set_pub_key")]
    RawSessionSetPubKey(RawAttested<RawSessionSetPubKey, RawAttestation>),
    #[serde(rename = "set_tcb_eval_floor")]
    RawSetTcbEvalFloor(RawSetTcbEvalFloor),
}

impl<RA> TryFrom<RawExecute<RA>> for Execute<RA::DomainType>
where
    RA: HasDomainType,
{
    type Error = StdError;

    fn try_from(value: RawExecute<RA>) -> Result<Self, Self::Error> {
        match value {
            RawExecute::RawSessionCreate(msg) => {
                Ok(Execute::SessionCreate(TryFrom::try_from(msg)?))
            }
            RawExecute::RawSessionSetPubKey(msg) => {
                Ok(Execute::SessionSetPubKey(TryFrom::try_from(msg)?))
            }
            RawExecute::RawSetTcbEvalFloor(msg) => {
                Ok(Execute::SetTcbEvalFloor(TryFrom::try_from(msg)?))
            }
        }
    }
}

impl<RA> From<Execute<RA::DomainType>> for RawExecute<RA>
where
    RA: HasDomainType,
{
    fn from(value: Execute<RA::DomainType>) -> Self {
        match value {
            Execute::SessionCreate(msg) => RawExecute::RawSessionCreate(From::from(msg)),
            Execute::SessionSetPubKey(msg) => RawExecute::RawSessionSetPubKey(From::from(msg)),
            Execute::SetTcbEvalFloor(msg) => RawExecute::RawSetTcbEvalFloor(From::from(msg)),
        }
    }
}

impl<RA> HasDomainType for RawExecute<RA>
where
    RA: HasDomainType,
{
    type DomainType = Execute<RA::DomainType>;
}

/// O3 governed raise-only TCB-Info floor update. This is NOT an
/// attested/enclave message: it is authorized by the configured `config.admin`
/// in the handler and enforced monotonic (raise-only) against the current
/// effective floor. QE-Identity keeps its own independent floor.
#[derive(Clone, Debug, PartialEq)]
pub struct SetTcbEvalFloor {
    pub fmspc: [u8; 6],
    pub min_tcb_eval_num: u64,
}

#[cw_serde]
pub struct RawSetTcbEvalFloor {
    /// Hex-encoded 6-byte platform FMSPC the floor applies to.
    pub fmspc: HexBinary,
    /// New minimum acceptable TCB-Info tcbEvaluationDataNumber (raise-only).
    pub min_tcb_eval_num: u64,
}

impl TryFrom<RawSetTcbEvalFloor> for SetTcbEvalFloor {
    type Error = StdError;

    fn try_from(value: RawSetTcbEvalFloor) -> Result<Self, Self::Error> {
        Ok(Self {
            fmspc: value
                .fmspc
                .to_array::<6>()
                .map_err(|e| StdError::msg(format!("fmspc: {e}")))?,
            min_tcb_eval_num: value.min_tcb_eval_num,
        })
    }
}

impl From<SetTcbEvalFloor> for RawSetTcbEvalFloor {
    fn from(value: SetTcbEvalFloor) -> Self {
        Self {
            fmspc: HexBinary::from(value.fmspc.as_slice()),
            min_tcb_eval_num: value.min_tcb_eval_num,
        }
    }
}
