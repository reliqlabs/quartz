# burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b (nemotron-3-120b-a12b) — verus-prototype Critical 4 + 5 cross-critique

- Elapsed: 132.0s
- Model: burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b

---

# Cross-critique by verus-reviewer

## Critical 4 vote: DEFEND

The finding is valid. The wrapper's `Attested<M,A>::handle` (lines 179, 184 in production attested.rs) validates `attestation.user_data()` and `attestation.mr_enclave()` against the message and config. However, `DstackZkAttestation::handle` (lines 94-99 in production) constructs the ZK verification request using only `self.zkdcap_proof` and `self.zkdcap_public_inputs`, without verifying these values correspond to the attested `user_data` and `mr_enclave`. The Verus spec (`zk_query_verify_succeeded` at attested.rs:397-401) only confirms the proof is valid for the given public inputs, not that those inputs commit to the expected `user_data` and `mr_enclave`. An attacker could submit a valid proof for a different enclave while setting the attestation's self-declared fields to pass the wrapper's checks, breaking the core guarantee that "the proof attests to *this* enclave." Claude's suggested defense—adding a spec-level binding predicate verified in the handler—is necessary and sufficient.

## Critical 5 vote: DEFEND

The finding is valid. Theorem `pub_key_matches_sk` (lines 178-194 in verus-prototype/key_manager.rs) proves the binding `verifying_key_spec(km.sk) == pub_key(&km).0` for a static `DefaultKeyManager` value. However, production `Import::import` (lines 53-56 in default.rs) mutates `self.sk` in place via `self.sk = SigningKey::from_slice(&data)?`. After mutation, any cached `PubKey` no longer corresponds to `km.sk`, violating the temporal binding required for security. The Verus prototype models `import_sk` as a pure function (lines 171-174) that returns a fresh key without state mutation, failing to capture this critical behavior. Claude's suggested defense—adding a `pub_key_published` ghost field invalidated or updated by `import`—is necessary to prove the invariant persists across key rotations.

## Net recommendation

Both fixes should be included in the upstream PR. For Critical 4, modify the DstackZkAttestation handler to verify that the zkdcap_public_inputs commit to the attestation's user_data and mr_enclave (e.g., by checking a derived value matches expected inputs). For Critical 5, update the Verus prototype to model Import::import as a mutating operation and either: (a) prove pub_key_matches_sk requires re-verification after import, or (b) add a ghost field tracking the last-published key binding that Import::import updates atomically with the signing key. These changes close the identified trust gaps without overcorrecting.

