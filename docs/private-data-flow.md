# Private On-Chain Data: Full Control Flow

## Parties

| Party | Role | Trust Basis |
|-------|------|-------------|
| **User** | Data owner, Xion abstract account | Authenticated by chain (email, social, biometric, passkey) |
| **Recipient** | Granted access by User | Authenticated by chain |
| **Contract** | CosmWasm on Xion, stores ciphertexts + permissions | On-chain, deterministic, auditable |
| **TEE Enclave** | Quartz dstack CVM (Intel TDX), processes plaintext | Hardware attestation (TDX quote → zkdcap proof) |
| **Validators** | Commonware threshold simplex, hold IBE master shares | Threshold trust — no single validator sees full key |
| **ZK Module** | Xion native module, verifies Groth16 proofs | Chain-native, all validators execute |

## Why No Per-User Key Management?

IBE (Identity-Based Encryption) lets anyone encrypt data **to an identity string**
(e.g. a Xion address) using only the **public master key**. No recipient key exchange,
no seed phrases, no key servers. The validators collectively extract decryption keys
on demand — but only deliver them inside the attested TEE.

---

## System Setup (once)

```mermaid
sequenceDiagram
    participant V as Validators
    participant Chain as Xion Chain
    participant TEE as TEE Enclave
    participant ZK as ZK Module

    Note over V: Consensus DKG (threshold simplex)
    V->>V: Generate IBE master key shares
    V->>Chain: Publish IBE master public key (MPK)

    Note over TEE: Quartz Handshake
    TEE->>TEE: Generate TDX quote + session keypair
    TEE->>Chain: Attested Instantiate (compose_hash, config)
    Chain->>ZK: Verify zkdcap Groth16 proof
    ZK-->>Chain: verified = true
    TEE->>Chain: Attested SessionCreate (nonce)
    TEE->>Chain: Attested SessionSetPubKey (session_pk)
    Note over Chain: Contract stores session_pk + compose_hash
```

After setup, the chain knows:
- **MPK**: anyone can encrypt to any identity
- **session_pk**: the TEE's public key for secure communication
- **compose_hash**: the TEE's verified code identity

---

## 1. Store Private Data

No TEE involvement. User encrypts locally with IBE.

```mermaid
sequenceDiagram
    participant U as User
    participant App as Frontend
    participant C as Contract

    U->>App: "Store this data"
    App->>App: IBE.Encrypt(MPK, user_address, plaintext)
    Note right of App: No keys needed —<br/>just MPK + identity string
    App->>C: tx: StoreData { ciphertext }
    C->>C: Store ciphertext, owner = user
    C-->>App: OK (data_id)
```

**Key property**: Encryption requires zero interaction with the TEE or validators.
Anyone who knows the MPK (public, on-chain) can encrypt to any Xion address.

---

## 2. Retrieve Own Data

User authenticates via their Xion abstract account. TEE obtains the IBE
private key from validators, decrypts, and returns plaintext over ECIES.

```mermaid
sequenceDiagram
    participant U as User
    participant App as Frontend
    participant C as Contract
    participant TEE as TEE Enclave
    participant V as Validators

    U->>App: "Show me my data"
    App->>C: tx: RequestDecrypt { data_id }
    Note right of C: Sender authenticated<br/>by abstract account

    C->>TEE: Relay request (via Quartz)
    TEE->>C: Query ciphertext for data_id
    C-->>TEE: ciphertext

    Note over TEE,V: Threshold IBE Key Extraction
    TEE->>V: Request partial keys for user_address
    loop t-of-n validators
        V->>V: extract_partial_key(share_i, user_address)
        V->>V: encrypt_partial_key(partial, tee_session_pk)
        V-->>TEE: encrypted_partial_i
    end
    TEE->>TEE: recover_key_encrypted(partials) → user_ibe_sk
    TEE->>TEE: IBE.Decrypt(user_ibe_sk, ciphertext) → plaintext
    TEE->>TEE: zeroize(user_ibe_sk)

    TEE->>App: ECIES.Encrypt(user_ephemeral_pk, plaintext)
    App->>App: ECIES.Decrypt → plaintext
    App->>U: Display data
```

**Key properties**:
- No single validator sees the full IBE private key
- The TEE is the only entity that reconstructs it
- The key is zeroized immediately after use
- Plaintext only exists inside TEE and on user's device

---

## 3. Share Data with Recipient

Decrypt-and-re-encrypt inside the TEE. The TEE produces an attested
transaction proving the re-encryption happened in verified hardware.

```mermaid
sequenceDiagram
    participant U as User
    participant C as Contract
    participant TEE as TEE Enclave
    participant V as Validators
    participant ZK as ZK Module

    U->>C: tx: ShareData { data_id, recipient_address }
    C->>TEE: Relay share request

    TEE->>C: Query ciphertext for data_id
    C-->>TEE: ciphertext

    Note over TEE,V: Extract user's IBE key (same as retrieve)
    TEE->>V: Request partial keys for user_address
    V-->>TEE: encrypted_partials
    TEE->>TEE: recover_key → user_ibe_sk
    TEE->>TEE: IBE.Decrypt(user_ibe_sk, ciphertext) → plaintext
    TEE->>TEE: zeroize(user_ibe_sk)

    Note over TEE: Re-encrypt for recipient
    TEE->>TEE: IBE.Encrypt(MPK, recipient_address, plaintext) → recipient_ct
    TEE->>TEE: zeroize(plaintext)

    TEE->>C: Attested ShareResult { data_id, recipient, recipient_ct }
    C->>ZK: Verify zkdcap Groth16 proof
    ZK-->>C: verified = true
    C->>C: Store recipient_ct, record permission
    C-->>U: OK
```

**Key properties**:
- Plaintext never leaves the TEE
- Re-encryption is attested — the chain verifies it happened in genuine hardware
- Recipient didn't need to do anything — their ciphertext is ready when they want it
- Permission is recorded on-chain for auditability

---

## 4. Recipient Retrieves Shared Data

Identical to "Retrieve Own Data" — the recipient authenticates with their
own Xion account, TEE extracts their IBE key, decrypts their ciphertext.

```mermaid
sequenceDiagram
    participant R as Recipient
    participant C as Contract
    participant TEE as TEE Enclave
    participant V as Validators

    R->>C: tx: RequestDecrypt { data_id }
    C->>C: Check: recipient has permission
    C->>TEE: Relay request

    TEE->>C: Query recipient's ciphertext for data_id
    C-->>TEE: recipient_ct

    TEE->>V: Request partial keys for recipient_address
    V-->>TEE: encrypted_partials
    TEE->>TEE: recover_key → recipient_ibe_sk
    TEE->>TEE: IBE.Decrypt(recipient_ibe_sk, recipient_ct) → plaintext
    TEE->>TEE: zeroize(recipient_ibe_sk)

    TEE->>R: ECIES.Encrypt(recipient_ephemeral_pk, plaintext)
    R->>R: Decrypt → plaintext
```

---

## 5. Revoke Access

On-chain only. No TEE or validator involvement.

```mermaid
sequenceDiagram
    participant U as User
    participant C as Contract

    U->>C: tx: RevokeAccess { data_id, recipient_address }
    C->>C: Verify sender == owner
    C->>C: Delete recipient's ciphertext
    C->>C: Remove permission record
    C-->>U: OK
```

After revocation, the recipient's ciphertext no longer exists on-chain.
The TEE will refuse to decrypt because the contract will report no permission.

---

## 6. Enclave Recovery (all enclaves lost)

Every enclave crashes, is decommissioned, or loses state. No session keys
survive. **No data is lost** — ciphertexts are IBE-encrypted on-chain,
and IBE keys are derived from identity, not from any enclave state.

A new enclave spins up, re-attests, and service resumes.

```mermaid
sequenceDiagram
    participant U as User
    participant C as Contract
    participant TEE2 as New Enclave
    participant V as Validators
    participant ZK as ZK Module

    Note over C: All old enclaves are down.<br/>Contract state is intact:<br/>ciphertexts, permissions,<br/>compose_hash, zkdcap_vkey

    Note over TEE2: New enclave starts (same code, new instance)
    TEE2->>TEE2: Generate new TDX quote + new session keypair

    Note over TEE2,C: Standard Quartz Handshake (re-attestation)
    TEE2->>C: Attested SessionCreate (new nonce)
    C->>ZK: Verify zkdcap proof (same compose_hash)
    ZK-->>C: verified = true
    TEE2->>C: Attested SessionSetPubKey (new session_pk)
    Note over C: session_pk updated, compose_hash unchanged

    Note over U: User resumes normal operation
    U->>C: tx: RequestDecrypt { data_id }
    C->>TEE2: Relay to new enclave
    TEE2->>V: Request partial IBE keys (encrypted to new session_pk)
    V-->>TEE2: encrypted_partials
    TEE2->>TEE2: recover_key, decrypt, return to user
    Note over U: Data recovered. No loss.
```

**Why this works:**

```
WHAT IS LOST                          WHAT SURVIVES
─────────────                         ──────────────
Old session private key    ✗          Ciphertexts on-chain        ✓
Old TDX quote              ✗          IBE master public key       ✓
Ephemeral TEE memory       ✗          Validator IBE shares        ✓
                                      Contract state/permissions  ✓
                                      compose_hash + zkdcap_vkey  ✓
                                      User accounts/auth          ✓
```

The session key is **ephemeral by design** — it's only used for transport
encryption (ECIES) between user and enclave. The long-lived encryption is
IBE, and IBE keys are **derived from identity**, not stored anywhere.

A new enclave with the same code (same compose_hash) can re-attest, get
a new session key, and immediately serve all existing data. The validators
don't care which enclave instance is asking — they verify the attestation.

This is the fundamental difference from systems that encrypt to a specific
enclave's key: in those systems, losing the enclave means losing the data.
Here, the enclave is a **stateless processor** — it extracts keys on demand,
decrypts, and forgets.

---

## Data State Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ON-CHAIN (public)                         │
│                                                                     │
│  ┌─────────────┐  ┌──────────────────────────────────────────────┐ │
│  │ IBE Master   │  │ Contract State                               │ │
│  │ Public Key   │  │                                              │ │
│  │ (MPK)        │  │  data_id → { owner, ciphertext_owner }      │ │
│  └─────────────┘  │  data_id → { recipient, ciphertext_recipient}│ │
│                    │  data_id → { permissions: [addr, ...] }      │ │
│  ┌─────────────┐  │                                              │ │
│  │ TEE Session  │  │  All ciphertexts are IBE-encrypted.          │ │
│  │ Public Key   │  │  Readable only with IBE private key          │ │
│  │ (session_pk) │  │  extracted by t-of-n validators.             │ │
│  └─────────────┘  └──────────────────────────────────────────────┘ │
│                                                                     │
│  ┌─────────────┐                                                   │
│  │ compose_hash │  ← verified TEE code identity                    │
│  │ zkdcap_vkey  │  ← verification key for attestation proofs      │
│  └─────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     TEE ENCLAVE (ephemeral)                         │
│                                                                     │
│  Holds: session private key (ECIES), TDX attestation capability     │
│  Sees:  plaintext (transiently, during decrypt/re-encrypt)          │
│  Never: stores plaintext, logs plaintext, leaks IBE private keys    │
│  Proof: TDX quote → zkdcap Groth16 → verified by ZK module         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                   VALIDATORS (threshold trust)                      │
│                                                                     │
│  Each holds: one share of IBE master secret                         │
│  Can do:     extract_partial_key(share, identity)                   │
│  Cannot:     reconstruct full IBE key (need t shares)               │
│  Delivers:   partial keys encrypted to TEE session_pk               │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      USER DEVICE (private)                          │
│                                                                     │
│  Can do:  encrypt to any identity (IBE, using MPK)                  │
│  Can do:  request decryption via TEE (authenticated by account)     │
│  Holds:   plaintext (after decryption)                              │
│  Never:   sees IBE private keys, validator shares, or other data    │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **No per-user keys** | Users never manage encryption keys | IBE: encrypt with identity string + public MPK |
| **Data privacy** | Ciphertexts on-chain are opaque | IBE encryption; decryption requires t-of-n validators + TEE |
| **TEE integrity** | Enclave runs the exact expected code | TDX attestation → zkdcap Groth16 → on-chain ZK verification |
| **No single point of failure** | No single entity can decrypt | Threshold IBE: t-of-n validators required for key extraction |
| **Permission enforcement** | Only authorized parties decrypt | Contract enforces ACL; TEE checks permissions before decrypting |
| **Auditability** | All access is on-chain | Share/revoke are transactions; attested messages prove TEE involvement |
| **Forward secrecy (revocation)** | Revoked users lose access | Recipient ciphertext deleted; TEE refuses without permission |
| **Key ephemerality** | IBE keys don't persist | TEE extracts, uses, zeroizes — keys never stored |
| **Enclave loss tolerance** | All enclaves can die, zero data loss | Ciphertexts are IBE (identity-derived), not enclave-key-derived |

## What Each Party Knows

| | User's Plaintext | User's IBE Key | Recipient's Plaintext | Validator Share |
|---|---|---|---|---|
| **User** | Yes | Never | No | No |
| **Recipient** | No | No | Yes (after share) | No |
| **Contract** | No (ciphertext only) | No | No (ciphertext only) | No |
| **TEE** | Transiently | Transiently | Transiently | No |
| **Single Validator** | No | No (partial only) | No | Yes (1 share) |
| **t Validators** | No | Could reconstruct* | No | Yes (t shares) |

\* t validators could theoretically collude to reconstruct an IBE key, but they would
still need the ciphertext (on-chain) and would bypass the TEE's permission checks.
This is the standard threshold trust assumption — same as consensus itself.
