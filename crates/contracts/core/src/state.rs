use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, Uint64};
use cw_storage_plus::Item;
use serde::{Deserialize, Serialize};

pub type MrEnclave = [u8; 32];
pub type Nonce = [u8; 32];
pub type UserData = [u8; 64];
pub type Hash = [u8; 32];
pub type Height = u64;
pub type TrustThreshold = (u64, u64);

pub const CONFIG_KEY: &str = "quartz_config";
pub const SESSION_KEY: &str = "quartz_session";
pub const SEQUENCE_NUM_KEY: &str = "quartz_seq_num";
pub const CONFIG: Item<RawConfig> = Item::new(CONFIG_KEY);
pub const SESSION: Item<Session> = Item::new(SESSION_KEY);
pub const SEQUENCE_NUM: Item<Uint64> = Item::new(SEQUENCE_NUM_KEY);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    mr_enclave: MrEnclave,
    light_client_opts: LightClientOpts,
    /// Verification key name registered in Xion's ZK module for zkdcap proof verification.
    /// When set, DstackAttestation handler queries the ZK module directly.
    zkdcap_vkey: Option<String>,
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
        }
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
}

#[cw_serde]
pub struct RawConfig {
    mr_enclave: HexBinary,
    light_client_opts: RawLightClientOpts,
    zkdcap_vkey: Option<String>,
}

impl RawConfig {
    pub fn mr_enclave(&self) -> &[u8] {
        self.mr_enclave.as_slice()
    }

    pub fn zkdcap_vkey(&self) -> Option<&str> {
        self.zkdcap_vkey.as_deref()
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = StdError;

    fn try_from(value: RawConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            mr_enclave: value.mr_enclave.to_array()?,
            light_client_opts: value
                .light_client_opts
                .try_into()
                .map_err(|e| StdError::msg(format!("light_client_opts: {e}")))?,
            zkdcap_vkey: value.zkdcap_vkey,
        })
    }
}

impl From<Config> for RawConfig {
    fn from(value: Config) -> Self {
        Self {
            mr_enclave: value.mr_enclave.into(),
            light_client_opts: value.light_client_opts.into(),
            zkdcap_vkey: value.zkdcap_vkey,
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
        let _: i64 = trusted_height.try_into().map_err(|_| "trusted_height too large")?;
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
            assert!(result.is_some(), "matching nonce with None pubkey must succeed");
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
