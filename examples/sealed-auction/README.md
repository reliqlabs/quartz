# Sealed Auction

A Vickrey (second-price sealed-bid) auction using Quartz for bid privacy.

Sponsors encrypt their bids to the enclave's session public key. The contract
stores encrypted blobs it cannot read. After the bidding deadline, the enclave
decrypts all bids, determines the winner (highest bidder, pays second-highest
price), and returns an attested result.

## Architecture

```
Sponsor                    Contract                   Enclave (TEE)
  |                          |                           |
  | query session pubkey --> |                           |
  | <-- pubkey               |                           |
  |                          |                           |
  | encrypt(bid, pubkey)     |                           |
  | SubmitBid{ciphertext} -> |                           |
  |                          | store encrypted blob      |
  |                          |                           |
  |     (bidding ends)       |                           |
  |                          |                           |
  |                          | <-- host reads bids ----> |
  |                          |                           | decrypt all bids
  |                          |                           | find winner + 2nd price
  |                          |                           | attest result
  |                          | <-- Resolve{attested} --- |
  |                          |                           |
  |                          | verify attestation        |
  |                          | store public result       |
```

## What's Private vs Public

| Data | Visibility |
|------|-----------|
| Auction config, phase, deadline | Public |
| Session public key | Public |
| Encrypted bid ciphertexts | Public (opaque bytes) |
| Bid amounts | Enclave only |
| Winner + second price | Public (after resolution) |

## Run (mock mode)

```bash
# Build
quartz contract build --contract-manifest contracts/Cargo.toml
quartz enclave build

# Deploy
quartz --mock contract deploy --contract-manifest contracts/Cargo.toml \
  --init-msg '{"auction_duration":300,"reserve_price":"100"}'

# Handshake
quartz --mock handshake --contract $CONTRACT_ADDRESS

# Start auction (admin)
xiond tx wasm execute $CONTRACT_ADDRESS '{"start_auction":{}}' ...

# Submit encrypted bid (sponsor)
# 1. Query session pubkey
# 2. Encrypt: ecies::encrypt(pubkey, json({"amount":"500"}))
# 3. Submit: {"submit_bid":{"ciphertext":"<hex>"}}
```

## Enclave Tests

The enclave's auction resolution logic has unit tests:

```bash
cd enclave && cargo test
```
