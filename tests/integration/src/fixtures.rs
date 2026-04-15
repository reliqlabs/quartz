//! Test fixtures for zkdcap proof verification.
//!
//! Generates structurally valid SnarkJS-format Groth16 proofs and
//! DcapJournal data for integration testing. These are synthetic —
//! they won't pass real cryptographic verification, but they exercise
//! the full serialization pipeline and journal binding logic.

use sha2::{Digest, Sha256};

/// A synthetic DcapJournal matching the zkdcap-core format.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DcapJournal {
    #[serde(with = "hex::serde")]
    pub quote_hash: [u8; 32],
    pub quote_verified: bool,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    pub mr_td: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    pub report_data: String,
    pub verification_timestamp: u64,
}

/// A complete set of fixture data for testing DstackAttestation verification.
pub struct ZkdcapFixture {
    /// SnarkJS-format Groth16 proof (JSON bytes)
    pub proof_bytes: Vec<u8>,
    /// Public inputs as decimal strings
    pub public_inputs: Vec<String>,
    /// DcapJournal (JSON bytes)
    pub journal_bytes: Vec<u8>,
    /// The compose_hash (mr_enclave equivalent)
    pub compose_hash: [u8; 32],
    /// Raw TDX quote bytes (synthetic)
    pub quote_bytes: Vec<u8>,
    /// User data (report_data from the quote)
    pub user_data: [u8; 64],
}

impl ZkdcapFixture {
    /// Generate a complete fixture with consistent internal references.
    pub fn generate() -> Self {
        // Synthetic quote (just needs to be non-empty and hashable)
        let quote_bytes: Vec<u8> = [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(256).collect();
        let quote_hash: [u8; 32] = Sha256::digest(&quote_bytes).into();

        // Compose hash (mr_enclave equivalent)
        let compose_hash = [0xAA; 32];

        // User data (report_data)
        let mut user_data = [0u8; 64];
        user_data[0..32].copy_from_slice(&[0xBB; 32]);

        // Journal
        let journal = DcapJournal {
            quote_hash,
            quote_verified: true,
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
            mr_td: hex::encode([0x11; 48]),
            rtmr0: hex::encode([0x22; 48]),
            rtmr1: hex::encode([0x33; 48]),
            rtmr2: hex::encode([0x44; 48]),
            rtmr3: hex::encode(compose_hash), // rtmr3 contains compose_hash
            report_data: hex::encode(user_data),
            verification_timestamp: 1713052800, // 2024-04-14 00:00:00 UTC
        };
        let journal_bytes = serde_json::to_vec(&journal).unwrap();

        // Compute journal hash for public inputs binding
        let journal_hash: [u8; 32] = Sha256::digest(&journal_bytes).into();

        // Synthetic vkey hash (BN254 field element as decimal string)
        let vkey_hash = "12345678901234567890123456789012345678901234567890123456789012345678";

        // Masked journal hash as BN254 field element (decimal string)
        // In SP1, this is SHA256(journal) with top 3 bits masked off
        let mut masked = journal_hash;
        masked[0] &= 0x1F; // mask top 3 bits for BN254 field
        let journal_field = num_to_decimal(&masked);

        let public_inputs = vec![vkey_hash.to_string(), journal_field];

        // SnarkJS-format Groth16 proof (structurally valid, cryptographically meaningless)
        let proof = serde_json::json!({
            "pi_a": [
                "5583158245518012202854967966688803983422579480975771799159435109682404412144",
                "19132509617989255559927911185942768582713778613503304661723852230698387114840",
                "1"
            ],
            "pi_b": [
                [
                    "16209151427684011206863591092531391562117041646748639896310737311173246509260",
                    "17729357182912272387117349263688449009610186531485947940640482832772517448927"
                ],
                [
                    "5695516600618485685754260649529465903248888152110855008128547397403792546988",
                    "656772577582924627058107331850692187484072991458347712020152128940322124285"
                ],
                ["1", "0"]
            ],
            "pi_c": [
                "17453897224382172288517505191435866511305436208311355514241444398256793953872",
                "9163422778422181829456976190497942172380575625369266408413936273192580460236",
                "1"
            ],
            "protocol": "groth16",
            "curve": "bn128"
        });
        let proof_bytes = serde_json::to_vec(&proof).unwrap();

        Self {
            proof_bytes,
            public_inputs,
            journal_bytes,
            compose_hash,
            quote_bytes,
            user_data,
        }
    }
}

/// gnark-native fixture data for ProofVerifyGnark endpoint.
pub struct GnarkFixture {
    /// gnark native proof bytes (serialized groth16.Proof)
    /// BN254 Groth16: 3 curve points = Ar(G1) + Bs(G2) + Krs(G1)
    /// G1 = 2x32 bytes, G2 = 2x2x32 bytes → total 384 bytes minimum
    pub proof_bytes: Vec<u8>,
    /// Public inputs as concatenated 32-byte big-endian fr.Element values
    pub public_inputs_bytes: Vec<u8>,
    /// Same journal and quote as SnarkJS fixture
    pub journal_bytes: Vec<u8>,
    pub compose_hash: [u8; 32],
    pub quote_bytes: Vec<u8>,
    pub user_data: [u8; 64],
}

impl GnarkFixture {
    /// Generate a gnark-native fixture with binary proof and public inputs.
    pub fn generate() -> Self {
        // Reuse the same journal/quote/compose_hash as SnarkJS fixture
        let quote_bytes: Vec<u8> =
            [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(256).collect();
        let quote_hash: [u8; 32] = Sha256::digest(&quote_bytes).into();
        let compose_hash = [0xAA; 32];
        let mut user_data = [0u8; 64];
        user_data[0..32].copy_from_slice(&[0xBB; 32]);

        let journal = DcapJournal {
            quote_hash,
            quote_verified: true,
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
            mr_td: hex::encode([0x11; 48]),
            rtmr0: hex::encode([0x22; 48]),
            rtmr1: hex::encode([0x33; 48]),
            rtmr2: hex::encode([0x44; 48]),
            rtmr3: hex::encode(compose_hash),
            report_data: hex::encode(user_data),
            verification_timestamp: 1713052800,
        };
        let journal_bytes = serde_json::to_vec(&journal).unwrap();
        let journal_hash: [u8; 32] = Sha256::digest(&journal_bytes).into();

        // Synthetic gnark proof: 384 bytes (3 BN254 curve points)
        // Ar (G1): 64 bytes, Bs (G2): 128 bytes, Krs (G1): 64 bytes
        // Plus optional commitment data
        let mut proof_bytes = vec![0u8; 384];
        // Fill with non-zero data so it doesn't look empty
        for (i, b) in proof_bytes.iter_mut().enumerate() {
            *b = ((i * 7 + 13) % 256) as u8;
        }

        // Public inputs: concatenated 32-byte big-endian field elements
        // Two inputs: vkey_hash and journal_hash (masked for BN254)
        let mut public_inputs_bytes = Vec::with_capacity(64);

        // Input 0: synthetic vkey hash (32 bytes)
        let mut vkey_hash = [0u8; 32];
        vkey_hash[0..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        public_inputs_bytes.extend_from_slice(&vkey_hash);

        // Input 1: masked journal hash (32 bytes)
        let mut masked_journal = journal_hash;
        masked_journal[0] &= 0x1F; // mask top 3 bits for BN254 field
        public_inputs_bytes.extend_from_slice(&masked_journal);

        Self {
            proof_bytes,
            public_inputs_bytes,
            journal_bytes,
            compose_hash,
            quote_bytes,
            user_data,
        }
    }
}

/// Convert a 32-byte big-endian value to a decimal string.
fn num_to_decimal(bytes: &[u8; 32]) -> String {
    let mut result = vec![0u8];
    for &byte in bytes {
        // Multiply existing result by 256
        let mut carry = 0u16;
        for digit in result.iter_mut().rev() {
            let val = (*digit as u16) * 256 + carry;
            *digit = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            result.insert(0, (carry % 10) as u8);
            carry /= 10;
        }
        // Add byte
        let mut carry = byte as u16;
        for digit in result.iter_mut().rev() {
            let val = (*digit as u16) + carry;
            *digit = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            result.insert(0, (carry % 10) as u8);
            carry /= 10;
        }
    }
    result.iter().map(|d| (b'0' + d) as char).collect()
}
