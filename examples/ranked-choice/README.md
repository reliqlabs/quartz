# Ranked Choice Voting

Private ranked choice voting (instant-runoff) using Quartz.

Voters encrypt their ranked ballots to the enclave's session public key.
The contract stores encrypted blobs. After the voting deadline, the enclave
decrypts all ballots and runs the instant-runoff algorithm. Round-by-round
tallies are published; individual ballots are never revealed.

## How Instant-Runoff Works

1. Count each voter's top remaining choice
2. If any candidate has a majority (>50%), they win
3. Otherwise, eliminate the candidate with the fewest votes
4. Voters whose top choice was eliminated have their vote transferred
   to their next choice
5. Repeat until a winner is found

## Privacy

| Data | Visibility |
|------|-----------|
| Candidates, election title | Public |
| Encrypted ballot ciphertexts | Public (opaque bytes) |
| Individual ballot rankings | Enclave only (never revealed) |
| Round-by-round vote counts | Public (after tally) |
| Winner | Public (after tally) |
| Who voted | Public (addresses on-chain) |
| How they voted | Private (encrypted, never revealed) |

## Run (mock mode)

```bash
# Build
quartz contract build --contract-manifest contracts/Cargo.toml
quartz enclave build

# Deploy
quartz --mock contract deploy --contract-manifest contracts/Cargo.toml \
  --init-msg '{"voting_duration":600}'

# Handshake
quartz --mock handshake --contract $CONTRACT_ADDRESS

# Create election
xiond tx wasm execute $CONTRACT_ADDRESS \
  '{"create_election":{"title":"Board Chair","candidates":["Alice","Bob","Carol"]}}' ...

# Open voting
xiond tx wasm execute $CONTRACT_ADDRESS '{"open_voting":{}}' ...

# Cast ballot (encrypted)
# 1. Query session pubkey
# 2. Encrypt: ecies::encrypt(pubkey, json({"ranked_choices":["Carol","Alice","Bob"]}))
# 3. Submit: {"cast_ballot":{"ciphertext":"<hex>"}}
```

## Frontend

Next.js app using `@burnt-labs/abstraxion` for Xion wallet integration:

```bash
cd frontend
cp .env.local.example .env.local
# Edit .env.local with your contract address
pnpm install
pnpm dev
```

The frontend:
- Connects via Xion abstract accounts (sessionless, gasless)
- Queries the contract for election state and enclave session pubkey
- Lets voters reorder candidates with up/down buttons
- Encrypts the ballot with ECIES to the session pubkey (client-side)
- Submits the encrypted ballot to the contract
- Displays round-by-round results after the enclave tallies

## Enclave Tests

```bash
cd enclave && cargo test
```
