use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, StdError, Uint64};
use cw_storage_plus::{Item, Map};
use quartz_zkdcap::VkeyTrust;
use serde::{Deserialize, Serialize};

pub type MrEnclave = [u8; 32];
pub type Nonce = [u8; 32];
pub type UserData = [u8; 64];
pub type Hash = [u8; 32];
pub type Height = u64;
pub type TrustThreshold = (u64, u64);

/// Custom serde for `Option<[u8; 48]>`. Serde's built-in array impls only
/// cover lengths up to 32; the 48-byte SHA-384 measurement registers need
/// this helper. Wire form is a `Vec<u8>` (binary), length-checked on
/// deserialise.
pub(crate) mod rtmr_opt_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &Option<[u8; 48]>, ser: S) -> Result<S::Ok, S::Error> {
        val.as_ref().map(|a| a.as_slice()).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<[u8; 48]>, D::Error> {
        let opt = <Option<Vec<u8>>>::deserialize(de)?;
        match opt {
            None => Ok(None),
            Some(v) => {
                if v.len() != 48 {
                    return Err(serde::de::Error::custom(format!(
                        "expected_rtmr3 wrong length: expected 48, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            }
        }
    }
}

pub const CONFIG_KEY: &str = "quartz_config";
pub const SESSION_KEY: &str = "quartz_session";
pub const SEQUENCE_NUM_KEY: &str = "quartz_seq_num";
pub const CONFIG: Item<RawConfig> = Item::new(CONFIG_KEY);
pub const SESSION: Item<Session> = Item::new(SESSION_KEY);
pub const SEQUENCE_NUM: Item<Uint64> = Item::new(SEQUENCE_NUM_KEY);

/// Per-FMSPC raise-only TCB-Info recency floors (O3 state). Keyed by the 6-byte
/// platform FMSPC, value is the minimum acceptable TCB-Info
/// tcbEvaluationDataNumber for that platform. A registered entry takes
/// precedence over the global-default `Config::min_tcb_eval_num`; both are only
/// ever raised (see the `SetTcbEvalFloor` handler). QE-Identity keeps its own
/// independent floor on the stored config, raised via `SetQeEvalFloor`, so the
/// two collateral streams never collapse.
pub const TCB_FLOORS_KEY: &str = "quartz_tcb_floors";
pub const TCB_FLOORS: Map<&[u8], u64> = Map::new(TCB_FLOORS_KEY);

/// Which identity claim a deployment requires about the verification key that
/// answered, selected at instantiate time.
///
/// Separate from [`quartz_zkdcap::VkeyTrust`] because the pins themselves live
/// in dedicated `Config` fields: keeping the digest in
/// `expected_zkdcap_vkey_sha256` means state written before this enum existed
/// still deserializes, with `Bytes` as the default, preserving the earlier
/// hard-coded behaviour byte for byte.
#[cw_serde]
#[derive(Copy, Default, Eq)]
pub enum VkeyTrustMode {
    /// Require the exact reviewed key material. Needs
    /// `expected_zkdcap_vkey_sha256`.
    #[default]
    Bytes,
    /// Require the registry record's authority to equal
    /// `expected_vkey_authority`. Suits a governance-owned key, and survives
    /// legitimate rotations without a config change.
    Authority,
    /// Require nothing beyond name or id resolution. Sound only to the degree
    /// the registry authority is trusted; that trust is not checked here.
    NameOnly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    mr_enclave: MrEnclave,
    light_client_opts: LightClientOpts,
    /// Governance authority permitted to raise per-FMSPC TCB floors via the
    /// `SetTcbEvalFloor` execute message. `None` (legacy / unset state) means
    /// no one is authorized: floor updates FAIL CLOSED. Mirrors the app-level
    /// `config.admin` authority pattern (examples/sealed-auction,
    /// examples/ranked-choice).
    #[serde(default)]
    admin: Option<Addr>,
    /// Verification key name registered in Xion's ZK module for the dcap-noir
    /// UltraHonk proof. When set, the `DstackZkAttestation` handler queries
    /// `/xion.zk.v1.Query/ProofVerifyUltraHonk` directly.
    zkdcap_vkey: Option<String>,
    /// SHA-256 digest of the exact Xion-stored verification-key bytes named by
    /// `zkdcap_vkey`. Carries the pin for `VkeyTrust::Bytes`, which is the
    /// default and the strongest model. Legacy configs deserialize as `None`.
    #[serde(default)]
    expected_zkdcap_vkey_sha256: Option<[u8; 32]>,
    /// What this deployment requires about the IDENTITY of the key that
    /// answered, as opposed to the validity of the proof.
    ///
    /// Secure-by-default: absent state deserializes to `Bytes`, which needs
    /// `expected_zkdcap_vkey_sha256` set and fails closed without it, matching
    /// the previous hard-coded behaviour exactly. Relaxing it is a conscious
    /// deployment act, in the same spirit as `allow_any_image`.
    ///
    /// Choose deliberately. `AddVKey` is permissionless and stores the caller
    /// as the key's authority, so whether a name or id is trustworthy depends
    /// on that specific key's registration: a governance-owned key changes only
    /// by proposal, while an owner-registered one changes at its owner's whim.
    #[serde(default)]
    vkey_trust: VkeyTrustMode,
    /// Expected `authority` on the x/zk registry record, for
    /// `VkeyTrustMode::Authority`. Typically the governance module address, in
    /// which case a key change requires a passed proposal. Unused by the other
    /// modes.
    #[serde(default)]
    expected_vkey_authority: Option<String>,
    /// Per-register TDX measurement pins for the image binding. Each register
    /// that is `Some` is ENFORCED (the proof's decoded value must equal it);
    /// `None` is SKIPPED. dstack mapping (see attestation.md): MRTD = virtual
    /// firmware; RTMR0 = virtual HW config (vCPU/RAM/devices); RTMR1 = kernel;
    /// RTMR2 = kernel cmdline + initrd; RTMR3 = app layer (compose-hash +
    /// per-instance data). MRTD/RTMR1/RTMR2 are stable per dstack base image;
    /// RTMR0 only for a fixed VM shape; RTMR3 is per-instance so a constant pin
    /// binds a single instance (prefer compose-hash binding via event-log replay
    /// for stable app identity — a follow-up). Secure-by-default: when a vkey is
    /// configured (verification on) at least one register must be pinned, unless
    /// `allow_any_image` is set.
    #[serde(default, with = "rtmr_opt_serde")]
    expected_mrtd: Option<[u8; 48]>,
    #[serde(default, with = "rtmr_opt_serde")]
    expected_rtmr0: Option<[u8; 48]>,
    #[serde(default, with = "rtmr_opt_serde")]
    expected_rtmr1: Option<[u8; 48]>,
    #[serde(default, with = "rtmr_opt_serde")]
    expected_rtmr2: Option<[u8; 48]>,
    #[serde(default, with = "rtmr_opt_serde")]
    expected_rtmr3: Option<[u8; 48]>,
    /// Expected dstack compose-hash (the stable, instance-independent app
    /// identity). When set, the handler replays the attestation's RTMR3 event
    /// log against the proof-bound RTMR3 and binds the compose-hash to this
    /// value — the recommended app pin (RTMR3-as-constant only binds one
    /// instance). Counts toward the require-one rule.
    #[serde(default)]
    expected_compose_hash: Option<Vec<u8>>,
    /// Escape hatch: allow verification with NO register pinned (trust any
    /// genuine TDX enclave). Default `false` = secure-by-default.
    #[serde(default)]
    allow_any_image: bool,
    /// Monotonic TCB-Info recency floor. The circuit has no counter, so the
    /// staleness decision is the consumer's. `0` (the default) means no floor.
    /// A production policy should select this floor using the proof-bound FMSPC.
    #[serde(default)]
    min_tcb_eval_num: u64,
    /// Monotonic QE-Identity recency floor. This is independent from the
    /// TCB-Info floor because Intel advances the two collateral streams
    /// separately. `0` (the default) means no floor.
    #[serde(default)]
    min_qe_eval_num: u64,
    /// Maximum acceptable TCB-status severity (lower = better; see
    /// `quartz_zkdcap::tcb_status`). The `DstackZkAttestation` handler rejects a
    /// proof whose decoded `tcb_status` exceeds this. SECURE-BY-DEFAULT: `0`
    /// (the default) is `UP_TO_DATE` only. Raise it explicitly to accept
    /// advisory statuses (e.g. `1` = also accept `SW_HARDENING_NEEDED`); the
    /// circuit already rejects `REVOKED` in-circuit. Note real Intel TDX
    /// platforms commonly report `SW_HARDENING_NEEDED`, so an operator on such a
    /// platform must raise this consciously.
    #[serde(default)]
    max_tcb_status: u8,
    /// Reject a proof whose FMSPC has no `TCB_FLOORS` entry, instead of falling
    /// back to `min_tcb_eval_num`. `false` (the default) is the legacy
    /// global-default policy; see `RawConfig::require_registered_fmspc`.
    #[serde(default)]
    require_registered_fmspc: bool,
}

impl Config {
    pub fn new(
        mr_enclave: MrEnclave,
        light_client_opts: LightClientOpts,
        zkdcap_vkey: Option<String>,
    ) -> Self {
        Self {
            mr_enclave,
            light_client_opts,
            zkdcap_vkey,
            expected_zkdcap_vkey_sha256: None,
            vkey_trust: VkeyTrustMode::default(),
            expected_vkey_authority: None,
            expected_mrtd: None,
            expected_rtmr0: None,
            expected_rtmr1: None,
            expected_rtmr2: None,
            expected_rtmr3: None,
            expected_compose_hash: None,
            allow_any_image: false,
            min_tcb_eval_num: 0,
            min_qe_eval_num: 0,
            max_tcb_status: 0,               // UP_TO_DATE only (secure-by-default)
            require_registered_fmspc: false, // legacy global-default policy
            admin: None,
        }
    }

    /// Builder variant: same as `new` but also pins the expected RTMR3.
    pub fn new_with_rtmr3(
        mr_enclave: MrEnclave,
        light_client_opts: LightClientOpts,
        zkdcap_vkey: Option<String>,
        expected_rtmr3: [u8; 48],
    ) -> Self {
        Self::new(mr_enclave, light_client_opts, zkdcap_vkey).with_expected_rtmr3(expected_rtmr3)
    }

    /// Builder: pin the full base-image measurement set (any subset). Pass
    /// `None` for registers you don't want to enforce.
    pub fn with_image_pins(
        mut self,
        mrtd: Option<[u8; 48]>,
        rtmr0: Option<[u8; 48]>,
        rtmr1: Option<[u8; 48]>,
        rtmr2: Option<[u8; 48]>,
        rtmr3: Option<[u8; 48]>,
    ) -> Self {
        self.expected_mrtd = mrtd;
        self.expected_rtmr0 = rtmr0;
        self.expected_rtmr1 = rtmr1;
        self.expected_rtmr2 = rtmr2;
        self.expected_rtmr3 = rtmr3;
        self
    }

    /// Builder: pin RTMR3 only.
    pub fn with_expected_rtmr3(mut self, rtmr3: [u8; 48]) -> Self {
        self.expected_rtmr3 = Some(rtmr3);
        self
    }

    /// Builder: pin the exact Xion-stored UltraHonk verification-key bytes by
    /// their SHA-256 digest.
    pub fn with_expected_zkdcap_vkey_sha256(mut self, sha256: [u8; 32]) -> Self {
        self.expected_zkdcap_vkey_sha256 = Some(sha256);
        self
    }

    /// Builder: pin the dstack compose-hash (stable app identity, via RTMR3
    /// event-log replay). The recommended app pin.
    pub fn with_expected_compose_hash(mut self, compose_hash: Vec<u8>) -> Self {
        self.expected_compose_hash = Some(compose_hash);
        self
    }

    /// Builder: opt out of the secure-by-default image-pin requirement (trust
    /// any genuine TDX enclave). Use only when image identity is bound elsewhere.
    pub fn with_allow_any_image(mut self, allow: bool) -> Self {
        self.allow_any_image = allow;
        self
    }

    /// Backward-compatible builder for the former shared recency floor. Sets
    /// both independent floors to the same value. Use
    /// [`Self::with_eval_num_floors`] when the streams have different floors.
    pub fn with_min_tcb_eval_num(mut self, min_tcb_eval_num: u64) -> Self {
        self.min_tcb_eval_num = min_tcb_eval_num;
        self.min_qe_eval_num = min_tcb_eval_num;
        self
    }

    /// Builder: set independent TCB-Info and QE-Identity recency floors.
    pub fn with_eval_num_floors(mut self, min_tcb_eval_num: u64, min_qe_eval_num: u64) -> Self {
        self.min_tcb_eval_num = min_tcb_eval_num;
        self.min_qe_eval_num = min_qe_eval_num;
        self
    }

    /// Builder: set the maximum acceptable TCB-status severity (lower = better;
    /// see `quartz_zkdcap::tcb_status`). Default is `0` (UP_TO_DATE only).
    pub fn with_max_tcb_status(mut self, max_tcb_status: u8) -> Self {
        self.max_tcb_status = max_tcb_status;
        self
    }

    /// Builder: authorize only platform families with a registered `TCB_FLOORS`
    /// entry, failing closed on any other FMSPC. Off by default so an upgrade of
    /// existing state cannot start rejecting platforms that were passing; a new
    /// deployment that knows its platform set should turn it on. Extend the set
    /// afterwards with `SetTcbEvalFloor` rather than a redeploy.
    pub fn with_require_registered_fmspc(mut self, require: bool) -> Self {
        self.require_registered_fmspc = require;
        self
    }
    /// Builder: set the governance admin permitted to raise per-FMSPC TCB
    /// floors. Reuses the repo's `config.admin` authority pattern.
    pub fn with_admin(mut self, admin: Addr) -> Self {
        self.admin = Some(admin);
        self
    }

    pub fn admin(&self) -> Option<&Addr> {
        self.admin.as_ref()
    }

    pub fn light_client_opts(&self) -> &LightClientOpts {
        &self.light_client_opts
    }

    pub fn mr_enclave(&self) -> MrEnclave {
        self.mr_enclave
    }

    pub fn zkdcap_vkey(&self) -> Option<&str> {
        self.zkdcap_vkey.as_deref()
    }

    pub fn expected_zkdcap_vkey_sha256(&self) -> Option<&[u8; 32]> {
        self.expected_zkdcap_vkey_sha256.as_ref()
    }

    pub fn vkey_trust_mode(&self) -> VkeyTrustMode {
        self.vkey_trust
    }

    pub fn expected_vkey_authority(&self) -> Option<&str> {
        self.expected_vkey_authority.as_deref()
    }

    /// Assemble the trust model the backend should enforce, or `Err` naming the
    /// missing pin.
    ///
    /// The error case is the one that matters: a mode whose pin is absent must
    /// NOT silently degrade to a weaker check, because the deployment asked for
    /// something the contract would then not be doing. Callers surface this as
    /// a verification failure.
    pub fn vkey_trust(&self) -> Result<VkeyTrust, &'static str> {
        match self.vkey_trust {
            VkeyTrustMode::Bytes => self
                .expected_zkdcap_vkey_sha256
                .map(VkeyTrust::Bytes)
                .ok_or("vkey_trust is `bytes` but expected_zkdcap_vkey_sha256 is unset"),
            VkeyTrustMode::Authority => self
                .expected_vkey_authority
                .clone()
                .map(VkeyTrust::Authority)
                .ok_or("vkey_trust is `authority` but expected_vkey_authority is unset"),
            VkeyTrustMode::NameOnly => Ok(VkeyTrust::NameOnly),
        }
    }

    /// Builder: require the registry record's authority rather than exact key
    /// bytes. Sets the mode and its pin together so they cannot disagree.
    pub fn with_expected_vkey_authority(mut self, authority: String) -> Self {
        self.vkey_trust = VkeyTrustMode::Authority;
        self.expected_vkey_authority = Some(authority);
        self
    }

    /// Builder: accept whatever the configured name or id resolves to.
    ///
    /// This checks NOTHING about key identity. Only appropriate when the
    /// registry authority for that key is known and trusted, e.g. a
    /// governance-owned key. Named verbosely on purpose.
    pub fn with_unchecked_vkey_name_only(mut self) -> Self {
        self.vkey_trust = VkeyTrustMode::NameOnly;
        self
    }

    pub fn expected_mrtd(&self) -> Option<&[u8; 48]> {
        self.expected_mrtd.as_ref()
    }
    pub fn expected_rtmr0(&self) -> Option<&[u8; 48]> {
        self.expected_rtmr0.as_ref()
    }
    pub fn expected_rtmr1(&self) -> Option<&[u8; 48]> {
        self.expected_rtmr1.as_ref()
    }
    pub fn expected_rtmr2(&self) -> Option<&[u8; 48]> {
        self.expected_rtmr2.as_ref()
    }
    pub fn expected_rtmr3(&self) -> Option<&[u8; 48]> {
        self.expected_rtmr3.as_ref()
    }
    pub fn expected_compose_hash(&self) -> Option<&[u8]> {
        self.expected_compose_hash.as_deref()
    }
    pub fn allow_any_image(&self) -> bool {
        self.allow_any_image
    }

    pub fn min_tcb_eval_num(&self) -> u64 {
        self.min_tcb_eval_num
    }

    pub fn min_qe_eval_num(&self) -> u64 {
        self.min_qe_eval_num
    }

    pub fn max_tcb_status(&self) -> u8 {
        self.max_tcb_status
    }

    pub fn require_registered_fmspc(&self) -> bool {
        self.require_registered_fmspc
    }
}

#[cw_serde]
pub struct RawConfig {
    mr_enclave: HexBinary,
    light_client_opts: RawLightClientOpts,
    /// Governance admin (bech32). `None` = legacy / unset; floor updates fail
    /// closed. See `Config::admin`.
    #[serde(default)]
    admin: Option<String>,
    zkdcap_vkey: Option<String>,
    /// Hex-encoded SHA-256 digest of the exact Xion-stored verification key.
    /// Missing legacy state remains deserializable but cannot verify a zkdcap
    /// attestation when `zkdcap_vkey` is configured.
    #[serde(default)]
    expected_zkdcap_vkey_sha256: Option<HexBinary>,
    /// Identity model for the verification key. Omitted means `bytes`, which
    /// preserves the earlier hard-coded behaviour.
    #[serde(default)]
    vkey_trust: VkeyTrustMode,
    /// Expected registry `authority`, required when `vkey_trust` is
    /// `authority`.
    #[serde(default)]
    expected_vkey_authority: Option<String>,
    /// Hex-encoded 48-byte expected TDX measurement registers. See `Config`.
    #[serde(default)]
    expected_mrtd: Option<HexBinary>,
    #[serde(default)]
    expected_rtmr0: Option<HexBinary>,
    #[serde(default)]
    expected_rtmr1: Option<HexBinary>,
    #[serde(default)]
    expected_rtmr2: Option<HexBinary>,
    #[serde(default)]
    expected_rtmr3: Option<HexBinary>,
    /// Hex-encoded expected dstack compose-hash. See `Config::expected_compose_hash`.
    #[serde(default)]
    expected_compose_hash: Option<HexBinary>,
    #[serde(default)]
    allow_any_image: bool,
    /// Monotonic TCB-recency floor. See `Config::min_tcb_eval_num`.
    #[serde(default)]
    min_tcb_eval_num: u64,
    /// Independent QE-Identity floor. `None` identifies state written before
    /// the split and falls back to `min_tcb_eval_num`, preserving the old
    /// shared-floor policy during deserialization.
    #[serde(default)]
    min_qe_eval_num: Option<u64>,
    /// Maximum acceptable TCB-status severity. See `Config::max_tcb_status`.
    /// Default `0` = UP_TO_DATE only (secure-by-default).
    #[serde(default)]
    max_tcb_status: u8,
    /// Authorize only platform families with a registered `TCB_FLOORS` entry.
    ///
    /// The fallback this gates is not a weaker *recency* check: Intel advances
    /// `tcbEvaluationDataNumber` fleet-wide (all 16 FMSPCs in the 2026-07 capture
    /// read 19), so an unregistered platform is measured against the same number
    /// a registered one would carry. What the fallback decides is
    /// **authorization**: whether a platform family nobody enumerated may attest
    /// at all.
    ///
    /// `false` (the default, and what legacy state deserializes to) keeps the
    /// documented global-default policy so an upgrade cannot start rejecting
    /// platforms that were passing before. `true` fails closed on an
    /// unregistered FMSPC; registering one is a governed `SetTcbEvalFloor`, so
    /// the authorized set is extended by admin transaction rather than by
    /// redeploy.
    #[serde(default)]
    require_registered_fmspc: bool,
}

impl RawConfig {
    pub fn mr_enclave(&self) -> &[u8] {
        self.mr_enclave.as_slice()
    }

    pub fn zkdcap_vkey(&self) -> Option<&str> {
        self.zkdcap_vkey.as_deref()
    }

    pub fn admin(&self) -> Option<&str> {
        self.admin.as_deref()
    }

    pub fn expected_zkdcap_vkey_sha256(&self) -> Option<&[u8]> {
        self.expected_zkdcap_vkey_sha256
            .as_ref()
            .map(HexBinary::as_slice)
    }

    pub fn vkey_trust_mode(&self) -> VkeyTrustMode {
        self.vkey_trust
    }

    pub fn expected_vkey_authority(&self) -> Option<&str> {
        self.expected_vkey_authority.as_deref()
    }

    /// Assemble the trust model to enforce, or `Err` naming what is missing or
    /// malformed. See [`Config::vkey_trust`]: a mode without its pin must fail
    /// closed rather than degrade to a weaker check.
    pub fn vkey_trust(&self) -> Result<VkeyTrust, String> {
        match self.vkey_trust {
            VkeyTrustMode::Bytes => {
                let raw = self
                    .expected_zkdcap_vkey_sha256
                    .as_ref()
                    .ok_or("vkey_trust is `bytes` but expected_zkdcap_vkey_sha256 is unset")?;
                let digest: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| "expected_zkdcap_vkey_sha256 must be exactly 32 bytes")?;
                Ok(VkeyTrust::Bytes(digest))
            }
            VkeyTrustMode::Authority => self
                .expected_vkey_authority
                .clone()
                .map(VkeyTrust::Authority)
                .ok_or_else(|| {
                    "vkey_trust is `authority` but expected_vkey_authority is unset".to_string()
                }),
            VkeyTrustMode::NameOnly => Ok(VkeyTrust::NameOnly),
        }
    }

    pub fn expected_mrtd(&self) -> Option<&[u8]> {
        self.expected_mrtd.as_ref().map(|h| h.as_slice())
    }
    pub fn expected_rtmr0(&self) -> Option<&[u8]> {
        self.expected_rtmr0.as_ref().map(|h| h.as_slice())
    }
    pub fn expected_rtmr1(&self) -> Option<&[u8]> {
        self.expected_rtmr1.as_ref().map(|h| h.as_slice())
    }
    pub fn expected_rtmr2(&self) -> Option<&[u8]> {
        self.expected_rtmr2.as_ref().map(|h| h.as_slice())
    }
    pub fn expected_rtmr3(&self) -> Option<&[u8]> {
        self.expected_rtmr3.as_ref().map(|h| h.as_slice())
    }
    pub fn expected_compose_hash(&self) -> Option<&[u8]> {
        self.expected_compose_hash.as_ref().map(|h| h.as_slice())
    }
    pub fn allow_any_image(&self) -> bool {
        self.allow_any_image
    }

    pub fn min_tcb_eval_num(&self) -> u64 {
        self.min_tcb_eval_num
    }

    pub fn min_qe_eval_num(&self) -> u64 {
        self.min_qe_eval_num.unwrap_or(self.min_tcb_eval_num)
    }

    /// Governed raise-only QE-Identity floor update (`SetQeEvalFloor`).
    ///
    /// `Ok(previous_effective_floor)` on success, `Err(current_effective_floor)`
    /// when `new_floor` would lower it. Raise-only lives in the type so no
    /// in-crate caller can express a lowering.
    ///
    /// Unlike the TCB floor this is a config field rather than a `Map` entry:
    /// Intel serves one QE Identity per TEE type, not one per FMSPC, so there
    /// is nothing to key a map on, and keeping it on the stored config means
    /// every existing `Config` query already exposes the floor in force.
    /// Legacy `None` state resolves through `min_qe_eval_num()` first, so the
    /// raise is checked against the inherited TCB floor rather than zero.
    pub fn raise_min_qe_eval_num(&mut self, new_floor: u64) -> Result<u64, u64> {
        let current = self.min_qe_eval_num();
        if new_floor < current {
            return Err(current);
        }
        self.min_qe_eval_num = Some(new_floor);
        Ok(current)
    }

    pub fn max_tcb_status(&self) -> u8 {
        self.max_tcb_status
    }

    pub fn require_registered_fmspc(&self) -> bool {
        self.require_registered_fmspc
    }

    /// Governed **tighten-only** FMSPC-authorization update (`SetFmspcPolicy`).
    ///
    /// `Ok(previous)` on success, `Err(())` when the caller asks to turn the
    /// requirement back off. Loosening an authorization boundary is a silent
    /// security downgrade, so, exactly as with the raise-only floors, the
    /// restriction lives in the type and no in-crate caller can express it. A
    /// deployment that genuinely needs to widen its platform set registers the
    /// additional FMSPC instead, which is the reversible operation.
    /// Mirrors `raise_min_qe_eval_num`: `Ok(previous)` on success, and on refusal
    /// `Err(current)` carries the policy already in force.
    pub fn tighten_require_registered_fmspc(&mut self) -> Result<bool, bool> {
        if self.require_registered_fmspc {
            return Err(true);
        }
        self.require_registered_fmspc = true;
        Ok(false)
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = StdError;

    fn try_from(value: RawConfig) -> Result<Self, Self::Error> {
        fn reg(h: Option<HexBinary>, name: &str) -> Result<Option<[u8; 48]>, StdError> {
            h.map(|h| h.to_array::<48>())
                .transpose()
                .map_err(|e| StdError::msg(format!("{name}: {e}")))
        }
        let min_qe_eval_num = value.min_qe_eval_num.unwrap_or(value.min_tcb_eval_num);
        let expected_zkdcap_vkey_sha256 = value
            .expected_zkdcap_vkey_sha256
            .map(|hash| hash.to_array::<32>())
            .transpose()
            .map_err(|e| StdError::msg(format!("expected_zkdcap_vkey_sha256: {e}")))?;
        Ok(Self {
            mr_enclave: value.mr_enclave.to_array()?,
            light_client_opts: value
                .light_client_opts
                .try_into()
                .map_err(|e| StdError::msg(format!("light_client_opts: {e}")))?,
            zkdcap_vkey: value.zkdcap_vkey,
            admin: value.admin.map(Addr::unchecked),
            expected_zkdcap_vkey_sha256,
            vkey_trust: value.vkey_trust,
            expected_vkey_authority: value.expected_vkey_authority,
            expected_mrtd: reg(value.expected_mrtd, "expected_mrtd")?,
            expected_rtmr0: reg(value.expected_rtmr0, "expected_rtmr0")?,
            expected_rtmr1: reg(value.expected_rtmr1, "expected_rtmr1")?,
            expected_rtmr2: reg(value.expected_rtmr2, "expected_rtmr2")?,
            expected_rtmr3: reg(value.expected_rtmr3, "expected_rtmr3")?,
            expected_compose_hash: value.expected_compose_hash.map(|h| h.to_vec()),
            allow_any_image: value.allow_any_image,
            min_tcb_eval_num: value.min_tcb_eval_num,
            require_registered_fmspc: value.require_registered_fmspc,
            min_qe_eval_num,
            max_tcb_status: value.max_tcb_status,
        })
    }
}

impl From<Config> for RawConfig {
    fn from(value: Config) -> Self {
        Self {
            mr_enclave: value.mr_enclave.into(),
            light_client_opts: value.light_client_opts.into(),
            zkdcap_vkey: value.zkdcap_vkey,
            admin: value.admin.map(String::from),
            expected_zkdcap_vkey_sha256: value.expected_zkdcap_vkey_sha256.map(HexBinary::from),
            vkey_trust: value.vkey_trust,
            expected_vkey_authority: value.expected_vkey_authority,
            expected_mrtd: value.expected_mrtd.map(HexBinary::from),
            expected_rtmr0: value.expected_rtmr0.map(HexBinary::from),
            expected_rtmr1: value.expected_rtmr1.map(HexBinary::from),
            expected_rtmr2: value.expected_rtmr2.map(HexBinary::from),
            expected_rtmr3: value.expected_rtmr3.map(HexBinary::from),
            expected_compose_hash: value.expected_compose_hash.map(HexBinary::from),
            allow_any_image: value.allow_any_image,
            min_tcb_eval_num: value.min_tcb_eval_num,
            min_qe_eval_num: Some(value.min_qe_eval_num),
            max_tcb_status: value.max_tcb_status,
            require_registered_fmspc: value.require_registered_fmspc,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LightClientOpts {
    chain_id: String,
    trusted_height: Height,
    trusted_hash: Hash,
    trust_threshold: TrustThreshold,
    trusting_period: u64,
    max_clock_drift: u64,
    max_block_lag: u64,
}

impl LightClientOpts {
    /// Validation predicate for `new`. Returns `Ok(())` if the inputs are
    /// well-formed, or `Err(&'static str)` describing the first failed
    /// invariant.
    ///
    /// Extracted from `new` so that Kani harnesses can exercise the
    /// validation logic without paying for `StdError::msg`'s
    /// `std::backtrace::Backtrace::capture()` call, which under Kani's
    /// host-arch simulation pulls in an unbounded
    /// `drop_in_place::<[BacktraceSymbol]>` loop that no reasonable
    /// `--unwind` setting terminates. See `Specs/Quartz/state.rs` mod
    /// `verification` for the corresponding harnesses (now usable under
    /// standard `cargo kani`, no `--cfg kani_slow` needed).
    pub fn validate_inputs(
        trust_threshold: TrustThreshold,
        trusted_height: Height,
    ) -> Result<(), &'static str> {
        let (numerator, denominator) = (trust_threshold.0, trust_threshold.1);
        if numerator > denominator {
            return Err("trust_threshold_too_large");
        }
        if denominator == 0 {
            return Err("undefined_trust_threshold");
        }
        // Original logic was `3 * numerator < denominator`, which overflows in
        // u64 for `numerator > u64::MAX / 3`. Caught by Kani 2026-05-21. Cast
        // to u128 to keep the same semantic check (threshold ratio below 1/3)
        // without the overflow path.
        if (numerator as u128) * 3 < denominator as u128 {
            return Err("trust_threshold_too_small");
        }
        // i64 fit check on trusted_height
        let _: i64 = trusted_height
            .try_into()
            .map_err(|_| "trusted_height too large")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: String,
        trusted_height: Height,
        trusted_hash: Hash,
        trust_threshold: TrustThreshold,
        trusting_period: u64,
        max_clock_drift: u64,
        max_block_lag: u64,
    ) -> Result<Self, StdError> {
        Self::validate_inputs(trust_threshold, trusted_height).map_err(StdError::msg)?;

        Ok(Self {
            chain_id,
            trusted_height,
            trusted_hash,
            trust_threshold,
            trusting_period,
            max_clock_drift,
            max_block_lag,
        })
    }

    pub fn chain_id(&self) -> &String {
        &self.chain_id
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn trusted_hash(&self) -> &Hash {
        &self.trusted_hash
    }

    pub fn trust_threshold(&self) -> &TrustThreshold {
        &self.trust_threshold
    }

    pub fn trusting_period(&self) -> u64 {
        self.trusting_period
    }

    pub fn max_clock_drift(&self) -> u64 {
        self.max_clock_drift
    }

    pub fn max_block_lag(&self) -> u64 {
        self.max_block_lag
    }
}

#[cw_serde]
pub struct RawLightClientOpts {
    chain_id: String,
    trusted_height: u64,
    trusted_hash: HexBinary,
    trust_threshold: (u64, u64),
    trusting_period: u64,
    max_clock_drift: u64,
    max_block_lag: u64,
}

impl TryFrom<RawLightClientOpts> for LightClientOpts {
    type Error = StdError;

    fn try_from(value: RawLightClientOpts) -> Result<Self, Self::Error> {
        Self::new(
            value.chain_id,
            value.trusted_height,
            value.trusted_hash.to_array()?,
            (value.trust_threshold.0, value.trust_threshold.1),
            value.trusting_period,
            value.max_clock_drift,
            value.max_block_lag,
        )
    }
}

impl From<LightClientOpts> for RawLightClientOpts {
    fn from(value: LightClientOpts) -> Self {
        Self {
            chain_id: value.chain_id,
            trusted_height: value.trusted_height,
            trusted_hash: Vec::<u8>::from(value.trusted_hash).into(),
            trust_threshold: (value.trust_threshold.0, value.trust_threshold.1),
            trusting_period: value.trusting_period,
            max_clock_drift: value.max_clock_drift,
            max_block_lag: value.max_block_lag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn light_client_opts() -> LightClientOpts {
        LightClientOpts::new(
            "testing".to_string(),
            1,
            [0u8; 32],
            (2, 3),
            1_209_600,
            300,
            600,
        )
        .unwrap()
    }

    #[test]
    fn independent_eval_floor_builder_preserves_both_values() {
        let config = Config::new([0u8; 32], light_client_opts(), None).with_eval_num_floors(19, 17);
        assert_eq!(config.min_tcb_eval_num(), 19);
        assert_eq!(config.min_qe_eval_num(), 17);
    }

    #[test]
    fn legacy_shared_floor_builder_sets_both_values() {
        let config = Config::new([0u8; 32], light_client_opts(), None).with_min_tcb_eval_num(15);
        assert_eq!(config.min_tcb_eval_num(), 15);
        assert_eq!(config.min_qe_eval_num(), 15);
    }

    #[test]
    fn legacy_raw_config_without_qe_floor_inherits_tcb_floor() {
        let config = Config::new([0u8; 32], light_client_opts(), None).with_min_tcb_eval_num(15);
        let raw: RawConfig = config.into();
        let mut json = serde_json::to_value(raw).unwrap();
        json.as_object_mut().unwrap().remove("min_qe_eval_num");

        let legacy: RawConfig = serde_json::from_value(json).unwrap();
        assert_eq!(legacy.min_tcb_eval_num(), 15);
        assert_eq!(legacy.min_qe_eval_num(), 15);
    }

    #[test]
    fn expected_zkdcap_vkey_sha256_builder_and_raw_round_trip() {
        let expected = [0x42; 32];
        let config = Config::new(
            [0u8; 32],
            light_client_opts(),
            Some("dcap-ultrahonk-v1".to_string()),
        )
        .with_expected_zkdcap_vkey_sha256(expected);
        assert_eq!(config.expected_zkdcap_vkey_sha256(), Some(&expected));

        let raw: RawConfig = config.into();
        assert_eq!(raw.expected_zkdcap_vkey_sha256(), Some(expected.as_slice()));

        let decoded = Config::try_from(raw).unwrap();
        assert_eq!(decoded.expected_zkdcap_vkey_sha256(), Some(&expected));
    }

    #[test]
    fn legacy_raw_config_without_vkey_hash_deserializes_unpinned() {
        let config = Config::new(
            [0u8; 32],
            light_client_opts(),
            Some("dcap-ultrahonk-v1".to_string()),
        )
        .with_expected_zkdcap_vkey_sha256([0x42; 32]);
        let raw: RawConfig = config.into();
        let mut json = serde_json::to_value(raw).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("expected_zkdcap_vkey_sha256");

        let legacy: RawConfig = serde_json::from_value(json).unwrap();
        assert_eq!(legacy.zkdcap_vkey(), Some("dcap-ultrahonk-v1"));
        assert_eq!(legacy.expected_zkdcap_vkey_sha256(), None);
        let decoded = Config::try_from(legacy).unwrap();
        assert_eq!(decoded.expected_zkdcap_vkey_sha256(), None);
    }

    #[test]
    fn malformed_zkdcap_vkey_hash_length_is_rejected() {
        let config = Config::new(
            [0u8; 32],
            light_client_opts(),
            Some("dcap-ultrahonk-v1".to_string()),
        )
        .with_expected_zkdcap_vkey_sha256([0x42; 32]);
        let raw: RawConfig = config.into();
        let mut json = serde_json::to_value(raw).unwrap();
        json["expected_zkdcap_vkey_sha256"] = serde_json::Value::String("42".repeat(31));

        let malformed: RawConfig = serde_json::from_value(json).unwrap();
        let err = Config::try_from(malformed).unwrap_err();
        assert!(err.to_string().contains("expected_zkdcap_vkey_sha256"));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn admin_round_trips_through_raw_config() {
        let admin = Addr::unchecked("cosmos1adminaddr");
        let config = Config::new([0u8; 32], light_client_opts(), None).with_admin(admin.clone());
        assert_eq!(config.admin(), Some(&admin));

        let raw: RawConfig = config.into();
        assert_eq!(raw.admin(), Some("cosmos1adminaddr"));

        let decoded = Config::try_from(raw).unwrap();
        assert_eq!(decoded.admin(), Some(&admin));
    }

    #[test]
    fn legacy_raw_config_without_admin_deserializes_as_none() {
        let config = Config::new([0u8; 32], light_client_opts(), None);
        let raw: RawConfig = config.into();
        let mut json = serde_json::to_value(raw).unwrap();
        json.as_object_mut().unwrap().remove("admin");

        let legacy: RawConfig = serde_json::from_value(json).unwrap();
        assert_eq!(legacy.admin(), None);
        assert_eq!(Config::try_from(legacy).unwrap().admin(), None);
    }
}

#[cw_serde]
pub struct Session {
    nonce: HexBinary,
    pub_key: Option<HexBinary>,
}

impl Session {
    pub fn create(nonce: Nonce) -> Self {
        Self {
            nonce: nonce.into(),
            pub_key: None,
        }
    }

    pub fn with_pub_key(mut self, nonce: Nonce, pub_key: Vec<u8>) -> Option<Self> {
        if self.nonce == nonce && self.pub_key.is_none() {
            self.pub_key = Some(pub_key.into());
            Some(self)
        } else {
            None
        }
    }

    pub fn nonce(&self) -> Nonce {
        self.nonce.to_array().expect("correct by construction")
    }

    pub fn pub_key(self) -> Option<HexBinary> {
        self.pub_key
    }
}

// ── Kani verification harnesses ────────────────────────────────────

#[cfg(kani)]
mod verification {
    use super::*;

    // Round E 2026-05-20: `session_with_pub_key_no_panic` removed.
    // The harness asserted only that `Session::with_pub_key` does not
    // panic; the function body contains a nonce comparison, an
    // `is_none()` check, and an `Option` return, with no panic source
    // (no indexing, no unwrap, no division). The non-panic property
    // was vacuously true and the harness did not exercise any
    // functional property of the production code. Kimi #4 and
    // Nemotron #1 in the Round E cross-family review flagged this
    // independently; both other voices included it in their
    // "tautological" pattern count. The remaining `session_with_pub_key_guards`
    // harness covers the functional property (nonce-matching guard
    // behavior); the dropped harness was strictly redundant.
    //
    // See .colosseum/attacks/kani-2026-05-20/synthesis.md for the
    // cross-voice analysis.

    /// Session::with_pub_key returns Some only when nonce matches
    /// and pub_key was None.
    #[kani::proof]
    fn session_with_pub_key_guards() {
        let create_nonce: Nonce = kani::any();
        let check_nonce: Nonce = kani::any();
        let pub_key = vec![0x04u8; 33];

        let session = Session::create(create_nonce);
        let result = session.with_pub_key(check_nonce, pub_key);

        if create_nonce == check_nonce {
            // Nonce matches, pub_key was None → must be Some
            assert!(
                result.is_some(),
                "matching nonce with None pubkey must succeed"
            );
        } else {
            // Nonce mismatch → must be None
            assert!(result.is_none(), "mismatched nonce must fail");
        }
    }

    /// Session::with_pub_key rejects double-set (pub_key already Some).
    /// Bounded unwind: Vec<u8> equality goes through memcmp which Kani
    /// cannot infer a finite bound for; cap explicitly.
    #[kani::proof]
    #[kani::unwind(40)]
    fn session_pubkey_set_once() {
        let nonce: Nonce = kani::any();
        let pk1 = vec![0x04u8; 33];
        let pk2 = vec![0x05u8; 33];

        let session = Session::create(nonce);
        let session = session.with_pub_key(nonce, pk1).unwrap();
        // Second set with same nonce must fail
        let result = session.with_pub_key(nonce, pk2);
        assert!(result.is_none(), "double pubkey set must be rejected");
    }

    /// Session::nonce() is safe when constructed via Session::create.
    #[kani::proof]
    fn session_nonce_roundtrip() {
        let nonce: Nonce = kani::any();
        let session = Session::create(nonce);
        let recovered = session.nonce();
        assert_eq!(nonce, recovered, "nonce must round-trip");
    }

    // The LightClientOpts harnesses below exercise `validate_inputs`
    // directly rather than `new`. Both paths apply the same predicate;
    // `new` adds a `StdError::msg` wrapping that calls
    // `std::backtrace::Backtrace::capture()` under Kani's host-arch
    // simulation (the wasm32 build uses `Backtrace::disabled()` and is
    // unaffected). The capture pulls in an unbounded
    // `drop_in_place::<[BacktraceSymbol]>` loop that no `--unwind`
    // setting terminates. Going through `validate_inputs` keeps the
    // verification surface identical (same `Err` cases, same `Ok`
    // case) while avoiding the backtrace constructor entirely. The
    // `#[cfg(kani_slow)]` gate is removed; these are now standard
    // `cargo kani` harnesses.

    /// LightClientOpts validation rejects ill-formed trust thresholds.
    /// Proves: 3*num < den is rejected, num > den is rejected,
    /// den == 0 is rejected, valid inputs accepted.
    #[kani::proof]
    #[kani::unwind(4)]
    fn light_client_opts_threshold_validation() {
        let num: u64 = kani::any();
        let den: u64 = kani::any();
        // Use small height to avoid i64 overflow path dominating
        let height: u64 = kani::any_where(|&h: &u64| h <= i64::MAX as u64);

        let result = LightClientOpts::validate_inputs((num, den), height);

        // Use u128 comparison in the oracle to match the production check
        // and avoid overflow in the harness's own arithmetic.
        let three_num_u128: u128 = (num as u128) * 3;
        if den == 0 {
            assert!(result.is_err(), "zero denominator must fail");
        } else if num > den {
            assert!(result.is_err(), "num > den must fail");
        } else if three_num_u128 < den as u128 {
            assert!(result.is_err(), "threshold < 1/3 must fail");
        } else {
            assert!(result.is_ok(), "valid threshold must succeed");
        }
    }

    /// LightClientOpts validation rejects heights that don't fit in i64.
    #[kani::proof]
    #[kani::unwind(4)]
    fn light_client_opts_height_bounds() {
        let height: u64 = kani::any();

        let result = LightClientOpts::validate_inputs((2, 3), height);

        if height > i64::MAX as u64 {
            assert!(result.is_err(), "height > i64::MAX must fail");
        } else {
            assert!(result.is_ok(), "valid height must succeed");
        }
    }
}

#[cfg(test)]
mod vkey_trust_tests {
    use super::*;

    fn cfg() -> Config {
        let lco = LightClientOpts::new(
            "testing".to_string(),
            1,
            [0u8; 32],
            (2, 3),
            1_209_600,
            300,
            600,
        )
        .unwrap();
        Config::new([0u8; 32], lco, None)
    }

    // Absent state must land on the strictest model, so an upgrade cannot
    // silently loosen a deployment that never opted in.
    #[test]
    fn default_mode_is_bytes() {
        assert_eq!(VkeyTrustMode::default(), VkeyTrustMode::Bytes);
        assert_eq!(cfg().vkey_trust_mode(), VkeyTrustMode::Bytes);
    }

    // The whole point of the resolver: a mode without its pin is a refusal, not
    // a downgrade to whatever weaker check happens to be available.
    #[test]
    fn bytes_without_a_digest_refuses() {
        let err = cfg().vkey_trust().expect_err("must not resolve");
        assert!(err.contains("expected_zkdcap_vkey_sha256"), "{err}");
    }

    #[test]
    fn authority_without_an_address_refuses() {
        let mut c = cfg();
        c.vkey_trust = VkeyTrustMode::Authority;
        let err = c.vkey_trust().expect_err("must not resolve");
        assert!(err.contains("expected_vkey_authority"), "{err}");
    }

    #[test]
    fn each_mode_resolves_once_its_pin_is_set() {
        let digest = [0x11u8; 32];
        let bytes = cfg()
            .with_expected_zkdcap_vkey_sha256(digest)
            .vkey_trust()
            .unwrap();
        assert_eq!(bytes, VkeyTrust::Bytes(digest));

        let gov = "xion10d07y265gmmuvt4z0w9aw880jnsr700jctf8qc".to_string();
        let authority = cfg()
            .with_expected_vkey_authority(gov.clone())
            .vkey_trust()
            .unwrap();
        assert_eq!(authority, VkeyTrust::Authority(gov));

        // NameOnly needs no pin, and says so by resolving from a bare config.
        let name_only = cfg().with_unchecked_vkey_name_only().vkey_trust().unwrap();
        assert_eq!(name_only, VkeyTrust::NameOnly);
        assert!(name_only.is_unchecked());
    }

    // Builders set mode and pin together so the two cannot disagree.
    #[test]
    fn builders_keep_mode_and_pin_consistent() {
        let c = cfg().with_expected_vkey_authority("xion1gov".to_string());
        assert_eq!(c.vkey_trust_mode(), VkeyTrustMode::Authority);
        assert_eq!(c.expected_vkey_authority(), Some("xion1gov"));

        let c = cfg().with_unchecked_vkey_name_only();
        assert_eq!(c.vkey_trust_mode(), VkeyTrustMode::NameOnly);
    }

    // Legacy stored state carries a digest and no mode; it must keep behaving
    // exactly as it did before the enum existed.
    #[test]
    fn legacy_state_without_the_mode_field_stays_on_bytes() {
        let digest = [0xabu8; 32];
        let mut c = cfg().with_expected_zkdcap_vkey_sha256(digest);
        let json = serde_json::to_string(&c).unwrap();
        let stripped = json.replace(r#""vkey_trust":"bytes","#, "");
        assert!(
            !stripped.contains("vkey_trust"),
            "field removed for the test"
        );

        let revived: Config = serde_json::from_str(&stripped).unwrap();
        assert_eq!(revived.vkey_trust_mode(), VkeyTrustMode::Bytes);
        assert_eq!(revived.vkey_trust().unwrap(), VkeyTrust::Bytes(digest));
        c.vkey_trust = VkeyTrustMode::Bytes;
        assert_eq!(revived, c);
    }
}
