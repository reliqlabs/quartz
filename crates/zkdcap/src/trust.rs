//! What a consumer is willing to trust about the identity of the verification
//! key that answered a proof query.
//!
//! Xion's `x/zk` registry gives a consumer three distinct things it could pin,
//! and they are not interchangeable. `AddVKey` is permissionless and stores the
//! CALLER as the key's authority; `UpdateVKey` and `RemoveVKey` then gate on
//! that stored authority. So:
//!
//! - a NAME can be repointed (`RemoveVKey` + `AddVKey` yields a new id and new
//!   bytes under the same name), and
//! - an ID's CONTENTS are mutable in place (`UpdateVKey` replaces the bytes
//!   under the same id and name).
//!
//! Both mutations are available to whoever holds the key's stored authority.
//! Which of them you must defend against is therefore a property of the
//! specific key's registration, not of the chain, and it differs per
//! deployment. A key whose authority is the governance module changes only by
//! passed proposal; a key registered from an ordinary account changes whenever
//! its owner likes.
//!
//! Hard-coding the strictest answer for everyone is what [`VkeyTrust`] replaces.

use crate::Hash32;

/// The identity claim a consumer requires before accepting a verification.
///
/// Ordered strongest to weakest. See the module docs for why the weakest is
/// sometimes the right choice, and [`VkeyTrust::is_enforceable_today`] for
/// which are reachable from a CosmWasm contract against a given chain.
/// Serializable so a consumer may store the selection and its pin as ONE field,
/// which is the shape that cannot disagree with itself. `quartz-contract-core`
/// instead splits mode from pin, because its `Config` is already deployed with a
/// standalone digest field and absent-field-means-`Bytes` is what keeps that
/// state readable; a consumer without that constraint should prefer this type
/// directly.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VkeyTrust {
    /// Accept only this exact key material, identified by SHA-256 over the
    /// registry's stored bytes.
    ///
    /// Strongest: indifferent to who controls the registry, because it pins the
    /// bytes rather than a binding to them. Two costs. It requires the chain to
    /// echo the digest from the verify response (see the crate's `xion`
    /// backend), and it must be updated on every legitimate key rotation,
    /// because a new key means a new digest.
    Bytes(Hash32),
    /// Accept whatever key the name or id resolves to, provided the registry
    /// record's `authority` equals this address.
    ///
    /// Suited to a key whose authority is the governance module: it turns "we
    /// trust that changing this key needs a proposal" from an assumption into a
    /// claim the consumer checks. Survives legitimate rotations without a
    /// config change, which byte pinning does not. Weaker in one specific way
    /// worth stating: it trusts the authority not to install a bad key, where
    /// [`VkeyTrust::Bytes`] does not.
    Authority(String),
    /// Accept whatever the name or id resolves to, with key identity enforced
    /// out of band at deploy time.
    ///
    /// Cheapest, and sound exactly to the degree the registry authority is
    /// trusted. Appropriate for a governance-controlled key when the deployer
    /// has accepted that trust deliberately; wrong for an owner-controlled one.
    NameOnly,
}

impl VkeyTrust {
    /// Whether this model can be enforced by a CosmWasm contract, given what
    /// the target chain supports.
    ///
    /// `digest_echo` is whether the chain's `ProofVerifyUltraHonk` response
    /// carries the vkey digest, and `vkey_query_whitelisted` is whether
    /// `/xion.zk.v1.Query/VKey` is callable from a contract. Both were false on
    /// every Xion release through `v30.0.0`, which is why [`Self::NameOnly`] was
    /// the only contract-enforceable model at that point.
    ///
    /// A consumer should not silently downgrade when its chosen model is
    /// unenforceable; it should refuse to verify, which is what the backend
    /// does.
    pub const fn is_enforceable_today(
        &self,
        digest_echo: bool,
        vkey_query_whitelisted: bool,
    ) -> bool {
        match self {
            // Reachable either by the echo on the already-whitelisted verify
            // path, or by reading the key back and hashing it.
            Self::Bytes(_) => digest_echo || vkey_query_whitelisted,
            // Only the registry record carries the authority, so this needs the
            // query regardless of the echo.
            Self::Authority(_) => vkey_query_whitelisted,
            // Nothing to check beyond resolution, which the verify path does.
            Self::NameOnly => true,
        }
    }

    /// True when this model checks nothing about key identity beyond
    /// resolution, so a deployment selecting it is accepting the registry
    /// authority on trust. Callers that want a loud deployment-time signal
    /// should branch on this.
    pub const fn is_unchecked(&self) -> bool {
        matches!(self, Self::NameOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The capability matrix, pinned so the availability facts stay explicit
    // rather than living in prose. Column order: (digest_echo,
    // vkey_query_whitelisted).
    #[test]
    fn enforceability_matches_chain_capabilities() {
        let bytes = VkeyTrust::Bytes([7u8; 32]);
        let authority = VkeyTrust::Authority("xion1gov".to_string());
        let name_only = VkeyTrust::NameOnly;

        // Every Xion release through v30.0.0: no echo, VKey not whitelisted.
        assert!(!bytes.is_enforceable_today(false, false));
        assert!(!authority.is_enforceable_today(false, false));
        assert!(name_only.is_enforceable_today(false, false));

        // With the digest echo alone, byte pinning works and needs no query.
        assert!(bytes.is_enforceable_today(true, false));
        assert!(!authority.is_enforceable_today(true, false));

        // With the VKey query alone, both work: bytes via readback.
        assert!(bytes.is_enforceable_today(false, true));
        assert!(authority.is_enforceable_today(false, true));

        // Both available.
        assert!(bytes.is_enforceable_today(true, true));
        assert!(authority.is_enforceable_today(true, true));
    }

    // A legacy key can carry an EMPTY authority in state while being
    // governance-controlled, because x/zk resolves empty to the gov module
    // address at read time and only InitGenesis backfills the field. Observed
    // live: 1 of 25 keys on xion-testnet-2 (id 1, "Zk Email"). A consumer
    // reading the record therefore cannot confirm the effective authority
    // matches its pin, and treating `""` as a match would match every such key.
    // Documented here because the check lives in the backend and this is where
    // a reader looks for what Authority means.
    #[test]
    fn authority_pin_is_meaningless_against_an_empty_record_field() {
        let gov = "xion10d07y265gmmuvt4z0w9aw880jnsr700jctf8qc";
        let trust = VkeyTrust::Authority(gov.to_string());

        // The pin itself must never be empty, or it would assert nothing.
        assert!(!matches!(&trust, VkeyTrust::Authority(a) if a.is_empty()));

        // And an empty pin is exactly what a caller must not configure. dossier
        // and quartz both reject it before it reaches the backend.
        let degenerate = VkeyTrust::Authority(String::new());
        assert!(matches!(&degenerate, VkeyTrust::Authority(a) if a.is_empty()));
    }

    #[test]
    fn only_name_only_is_unchecked() {
        assert!(!VkeyTrust::Bytes([0u8; 32]).is_unchecked());
        assert!(!VkeyTrust::Authority(String::new()).is_unchecked());
        assert!(VkeyTrust::NameOnly.is_unchecked());
    }
}
