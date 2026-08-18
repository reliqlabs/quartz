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
    /// O3: governed raise-only QE-Identity floor update.
    SetQeEvalFloor(SetQeEvalFloor),
    /// O3: governed tighten-only FMSPC-authorization update.
    SetFmspcPolicy(SetFmspcPolicy),
}

#[cw_serde]
pub enum RawExecute<RawAttestation = RawDefaultAttestation> {
    #[serde(rename = "session_create")]
    RawSessionCreate(RawAttested<RawSessionCreate, RawAttestation>),
    #[serde(rename = "session_set_pub_key")]
    RawSessionSetPubKey(RawAttested<RawSessionSetPubKey, RawAttestation>),
    #[serde(rename = "set_tcb_eval_floor")]
    RawSetTcbEvalFloor(RawSetTcbEvalFloor),
    #[serde(rename = "set_qe_eval_floor")]
    RawSetQeEvalFloor(SetQeEvalFloor),
    #[serde(rename = "set_fmspc_policy")]
    RawSetFmspcPolicy(SetFmspcPolicy),
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
            RawExecute::RawSetQeEvalFloor(msg) => Ok(Execute::SetQeEvalFloor(msg)),
            RawExecute::RawSetFmspcPolicy(msg) => Ok(Execute::SetFmspcPolicy(msg)),
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
            Execute::SetQeEvalFloor(msg) => RawExecute::RawSetQeEvalFloor(msg),
            Execute::SetFmspcPolicy(msg) => RawExecute::RawSetFmspcPolicy(msg),
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
/// effective floor. QE-Identity keeps its own independent floor, raised by
/// `SetQeEvalFloor`.
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

/// O3 governed raise-only QE-Identity floor update. Same authority and
/// monotonicity rules as `SetTcbEvalFloor`, over the independent QE-Identity
/// tcbEvaluationDataNumber. QE Identity is not FMSPC-scoped, so this carries no
/// platform key and the raise applies to the whole contract.
///
/// The wire and domain forms are identical (one `u64`), so unlike
/// `SetTcbEvalFloor` there is no separate `Raw` type to convert through.
#[cw_serde]
pub struct SetQeEvalFloor {
    /// New minimum acceptable QE-Identity tcbEvaluationDataNumber (raise-only).
    pub min_qe_eval_num: u64,
}

/// O3 governed **tighten-only** FMSPC-authorization update. Not an
/// attested/enclave message: authorized by the configured `config.admin` in the
/// handler.
///
/// Turning the requirement ON restricts attestation to platform families with a
/// registered `TCB_FLOORS` entry. There is deliberately no way to turn it back
/// OFF: loosening an authorization boundary is a silent security downgrade, and
/// `RawConfig::tighten_require_registered_fmspc` refuses it. A deployment that
/// needs to admit another platform family registers that FMSPC with
/// `SetTcbEvalFloor`, which is the reversible operation.
///
/// The wire and domain forms are identical, so like `SetQeEvalFloor` there is no
/// separate `Raw` type to convert through.
#[cw_serde]
pub struct SetFmspcPolicy {
    /// MUST be `true`. Present so the message is self-describing on the wire and
    /// an operator cannot mistake it for a toggle.
    pub require_registered_fmspc: bool,
}
