# kimi-k2-6 (gateway) — verus-prototype Round D

- **Elapsed**: 119.6s
- **Finish reason**: length
- **Usage**: {"prompt_tokens": 22618, "completion_tokens": 8192, "total_tokens": 30810, "prompt_tokens_details": {"cached_tokens": 0}}

---

The user wants an adversarial review of 6 Verus prototype files against their production Rust counterparts. I need to find specific ways the Verus specs are wrong, weak, or misleading relative to the production intent.

Let me analyze each file pair carefully.

**1. Verus: contracts/core/verus-prototype/instantiate.rs vs Production: handler/instantiate.rs + state.rs**

Production `Instantiate<A>::handle` checks `self.0.msg().config().mr_enclave() != self.0.attestation().mr_enclave()` and calls `self.0.handle(deps, env, info)`.
Production `CoreInstantiate::handle` does `CONFIG.save(deps.storage, &RawConfig::from(self.config().clone()))`.

Verus model:
- Collapses `Instantiate<A>` to concrete `Instantiate` with `inner: CoreInstantiate` and `att_mr_enclave: u64`.
- `core_instantiate_handle` saves to storage.
- `instantiate_handle` checks mr_enclave equality, then calls `core_instantiate_handle`.

Issues:
- The production `Instantiate<A>` delegates to `self.0.handle(deps, env, info)` which is the `Attested<M,A>::handle` wrapper. The Verus prototype directly calls `core_instantiate_handle`, skipping the `Attested` wrapper logic entirely (user_data check, mr_enclave check in Attested, etc.). Wait, actually in production `Instantiate<A>` wraps `Attested<CoreInstantiate, A>`. So `self.0.handle()` invokes `Attested::handle`. But `Attested::handle` does its own mr_enclave check against CONFIG (conditional on CONFIG existing) and user_data check. The Verus `instantiate_handle` only checks mr_enclave between msg and attestation, then directly calls `core_instantiate_handle`. This is a refinement mismatch / stubbing drift. The production `Instantiate` handler does NOT directly call `CoreInstantiate::handle`; it calls `Attested::handle` which then calls `CoreInstantiate::handle`. The Verus comment says "we monomorphise A to CoreInstantiate... modelled by directly invoking core_instantiate_handle". This loses the Attested wrapper behavior.

Wait, looking at production instantiate.rs:
```rust
impl<A> Handler for Instantiate<A>
where
    A: Attestation + Handler + HasUserData,
{
    fn handle(self, deps: DepsMut<'_>, env: &Env, info: &MessageInfo) -> Result<Response, Error> {
        if self.0.msg().config().mr_enclave() != self.0.attestation().mr_enclave() {
            return Err(Error::MrEnclaveMismatch);
        }
        self.0.handle(deps, env, info)
    }
}
```

`self.0` is `Attested<CoreInstantiate, A>`. So `self.0.handle()` is `Attested::handle`. The Verus prototype models `self.0.handle` as directly calling `core_instantiate_handle`. But `Attested::handle` does:
1. user_data check
2. CONFIG.may_load check for mr_enclave
3. calls msg.handle (CoreInstantiate::handle)
4. calls attestation.handle

So the Verus prototype for `Instantiate` is missing the entire `Attested` wrapper logic. The comment admits this: "we monomorphise A to CoreInstantiate... modelled by directly invoking core_instantiate_handle". This means the verified property about `Instantiate` does not actually constrain the production behavior which goes through `Attested::handle`. The mr_enclave check in `Instantiate` is between msg and attestation, but `Attested::handle` also checks against CONFIG. The Verus spec claims properties about `instantiate_handle` that don't account for the `Attested` wrapper's additional checks and potential failures (UserDataMismatch, MrEnclaveMismatch from CONFIG).

Actually, looking more carefully at the Verus file, the `instantiate_handle` function checks `msg.inner.config().mr_enclave() != msg.att_mr_enclave` and returns `MrEnclaveMismatch`. Then it calls `core_instantiate_handle`. It does NOT model the `Attested` wrapper at all. The production code calls `self.0.handle(deps, env, info)` which is `Attested::handle`. So the Verus prototype proves properties about a function that skips the entire `Attested` wrapper. This is a major refinement mismatch.

Also, `CONFIG.save` in Verus is body-verified and infallible for the concrete type. But production uses `cw_storage_plus::Item::save` which is generic over `Serialize` and can return `StdError`. The Verus comment mentions this but the spec uses a concrete save that always succeeds. The `external_body` variant is mentioned but not used. The spec says "To exercise the Err path... we use an external_body `save_maybe_err`" but then the actual code uses a body-verified `save` that always returns `Ok(())`. The `core_instantiate_handle` matches on `CONFIG.save` but since `save` always returns `Ok`, the `Err` arm is dead code. The spec claims `Err(e) => e is Std && final(storage).config == old(storage).config`, but this path is unreachable in the prototype. However, the production path can fail. So the spec claims it handles errors but the proof doesn't actually exercise the error path through the real mechanism. This is a coverage gap / stubbing drift.

Another issue: Production `CoreInstantiate::handle` does `CONFIG.save(deps.storage, &RawConfig::from(self.config().clone()))`. The Verus `core_instantiate_handle` takes `Config` (not `RawConfig`) and does `msg.config().as_raw()`. But `RawConfig` in production contains `light_client_opts` and `zkdcap_vkey` too. The Verus `RawConfig` only has `mr_enclave`. So the spec doesn't model that `CONFIG.save` stores the full config including `light_client_opts` and `zkdcap_vkey`. The `CONFIG` in production is `Item<RawConfig>`. The Verus model only stores `mr_enclave`. This is stubbing drift - the abstraction loses fields.

Also, the production `Instantiate` handler takes `DepsMut`, `Env`, `MessageInfo`. The Verus prototype ignores `Env` and `MessageInfo` (fine for this property), but also `DepsMut` is split. However, the production `Attested::handle` uses `deps.branch()` for the inner msg handler. The Verus prototype doesn't model `deps.branch()` at all. In cosmwasm, `deps.branch()` creates a scoped mutable borrow. The Verus prototype passes the same `storage` reference to both. While this might be fine for the property, it doesn't model the actual borrowing structure.

Wait, the prompt asks specifically about:
- Missing CONFIG.may_load semantics at instantiate: production `Attested<M,A>::handle` conditionally skips the mr_enclave check via `if let Some(config) = CONFIG.may_load(...)`. Does the Verus prototype model this conditional? If not, what does it claim?

In the Verus `instantiate.rs`, the `instantiate_handle` does NOT model `CONFIG.may_load` at all. It only checks `msg.inner.config().mr_enclave() != msg.att_mr_enclave`. But production `Instantiate` delegates to `Attested::handle` which DOES do `CONFIG.may_load`. However, the production `Instantiate` itself does NOT do `CONFIG.may_load`. The `Attested` wrapper does. Since Verus skips the `Attested` wrapper, it doesn't model the conditional CONFIG check at all. But wait, the user prompt specifically asks: "Missing CONFIG.may_load semantics at instantiate: the production Attested<M,A>::handle (line 183) conditionally skips the mr_enclave check via if let Some(config) = CONFIG.may_load(...). Does the Verus prototype model this conditional? If not, what does it claim?"

So for `instantiate.rs`, the issue is that the production `Instantiate` handler delegates to `Attested::handle`, which has the conditional `CONFIG.may_load`. The Verus prototype bypasses `Attested::handle` entirely, so it never models this conditional. The spec claims that on `Ok`, `CONFIG now holds Some(msg.config)`, but it doesn't claim anything about the conditional mr_enclave check against existing CONFIG. Actually, looking at production `Attested::handle`, it checks `CONFIG.may_load` and compares with `attestation.mr_enclave()`. But `Instantiate` is the entry point. The Verus prototype proves properties about `instantiate_handle` that assume the inner call succeeds, but it doesn't model the `Attested` wrapper's behavior. So the property "Instantiate::handle Ok ⇒ mr_enclaves matched AND the inner CoreInstantiate ran" is true for the prototype, but the production `Instantiate::handle` actually does more (delegates to `Attested` which does user_data check and conditional CONFIG check). So the Verus spec for `Instantiate` is under-specified with respect to the actual production behavior, or rather, it proves properties about a simplified model that doesn't include the `Attested` wrapper.

Actually, the prompt says the Verus prototype mirrors `src/handler/instantiate.rs`. But `src/handler/instantiate.rs` in production has `self.0.handle(deps, env, info)` where `self.0` is `Attested<CoreInstantiate, A>`. So the Verus prototype should model calling `Attested::handle`, not directly `CoreInstantiate::handle`. By collapsing this, the spec loses the user_data check and the conditional mr_enclave check against CONFIG.

**2. Verus: contracts/core/verus-prototype/attested.rs vs Production: handler/execute/attested.rs**

Production `Attested<M,A>::handle`:
- Checks `msg.user_data() != attestation.user_data()` → `UserDataMismatch`
- `if let Some(config) = CONFIG.may_load(deps.storage)?` → if loaded, checks `config.mr_enclave() != attestation.mr_enclave()` → `MrEnclaveMismatch`
- `let res_msg = Handler::handle(msg, deps.branch(), env, info)?;`
- `let res_attest = Handler::handle(attestation, deps, env, info)?;`
- Merges responses

Verus `attested_handle`:
- Checks user_data mismatch
- `match CONFIG.may_load(storage)` → `Ok(Some(config))` checks mr_enclave; `Ok(None)` does nothing; `Err(e)` returns `e`
- Calls `wrapper.msg.handle(storage)` and `wrapper.attestation.handle(storage)` sequentially, no `deps.branch()`, no `?` propagation from inner handlers (since concrete handlers always return Ok)
- Returns `Ok(Response::new())`

Issues:
- The concrete handlers `ConcreteMsg::handle` and `ConcreteAtt::handle` are stubbed to always return `Ok`. The comment admits: "we lose the ability to prove that an inner-handler error propagates to the wrapper". The production code uses `?` which propagates any `Err` from the inner handlers. The Verus prototype cannot prove this because the stubs are total. The comment says they compensate with an `external_body` fallible variant `concrete_att_handle_maybe_err` for one of the proofs, but I don't see that function in the code. I see `concrete_att_handle_maybe_err` is mentioned in the comment but not present in the file. Wait, looking at the code: the comment says "We compensate by adding an `external_body` fallible variant `concrete_att_handle_maybe_err` for one of the proofs." But the code only has `ConcreteMsg::handle` and `ConcreteAtt::handle`, both ensuring `r is Ok`. There is no `concrete_att_handle_maybe_err`. So the compensation is missing. This is a coverage gap / stubbing drift. The spec claims properties about error propagation but the proof doesn't cover it.

- Production uses `deps.branch()` for `msg.handle` but not for `attestation.handle`. The Verus prototype passes the same `storage` to both. In cosmwasm, `deps.branch()` creates a `DepsMut` that, if the inner call fails, doesn't commit changes? Actually, `DepsMut::branch()` is defined in cosmwasm-std as:
```rust
pub fn branch(&mut self) -> DepsMut<'a> {
    DepsMut {
        storage: self.storage,
        api: self.api,
    }
}
```
It's just a reborrow. So changes to storage are not isolated. However, the production code does `let res_msg = Handler::handle(msg, deps.branch(), env, info)?;` then `let res_attest = Handler::handle(attestation, deps, env, info)?;`. If `msg.handle` fails, the `?` returns early. If it succeeds, then `attestation.handle` runs. Since `branch()` just reborrows, storage mutations in `msg.handle` are visible. But the Verus prototype models this sequentially on the same storage, which is actually accurate. However, the production code uses `deps.branch()` which is a separate `DepsMut` but shares the underlying storage. The Verus model is fine here.

- The `CONFIG.may_load` in Verus returns `Result<Option<Config>, Error>`. In production, `CONFIG.may_load(deps.storage)?` returns `StdResult<Option<RawConfig>>`. The Verus model maps `Some(raw)` to `Config { mr_enclave: raw.mr_enclave, zkdcap_vkey: raw.zkdcap_vkey }`. But production `RawConfig` also has `light_client_opts`. The Verus model loses this field. Not critical for this handler since it only checks `mr_enclave`, but it's a stubbing drift.

- Production `Attested::handle` merges responses: `res_msg.add_events(res_attest.events).add_attributes(res_attest.attributes)`. The Verus prototype ignores the responses and returns `Response::new()`. The spec doesn't mention response merging. But the prompt's attack categories include composition failure.

- The `DstackZkAttestation` handler in production:
  - `let config = CONFIG.load(deps.storage).map_err(Error::Std)?;` (load, not may_load)
  - `let Some(vkey_name) = config.zkdcap_vkey() else { return Ok(...) };`
  - Prost encode, query_grpc, decode, check `verified` field.

  Verus `dstack_zk_handle`:
  - `let config = match CONFIG.may_load(storage) { Ok(Some(c)) => c, Ok(None) => return Err(Error::Std), Err(e) => return Err(e) };`
  - `let vkey = match config.zkdcap_vkey() { Some(v) => v, None => return Ok(...) };`
  - `zk_query_verify(...)` external_body stub.

  Issues:
  - Production uses `CONFIG.load` which returns `StdError` if missing. Verus uses `CONFIG.may_load` and returns `Err(Error::Std)` if None. This changes the error semantics. In production, `CONFIG.load` failing because CONFIG is missing would return `Error::Std`. In Verus, it's also `Error::Std`. But the control flow differs: production `DstackZkAttestation` assumes CONFIG exists (load, not may_load). If CONFIG is missing, it errors. Verus models it as an explicit `Err(Error::Std)`. This is actually similar. But wait, production `CONFIG.load` vs `CONFIG.may_load`: `load` returns `StdResult<T>` and errors if not found. `may_load` returns `StdResult<Option<T>>`. The Verus prototype uses `may_load` but then maps `None` to `Err(Error::Std)`. This is semantically equivalent to `load` for the error case, but the Verus `CONFIG.may_load` spec is defined in this file to return `Ok(None)` when storage is None. So the behavior matches. However, the production code uses `CONFIG.load` which is a different method. The Verus stub is `may_load`. This is a stubbing drift but maybe not a big issue.

  - Production `DstackZkAttestation` does prost encode/decode and gRPC query. Verus collapses all this into `zk_query_verify` external_body. The spec for `zk_query_verify` says `Ok(true) => zk_query_verify_succeeded(...)`, `Ok(false) => !zk_query_verify_succeeded(...)`, `Err(_) => true`. But production can fail at encode, query_grpc, or decode steps. The Verus spec says `Err(_) => true` which is trivial. The production code returns `Error::ZkdcapVerificationFailed` for all these cases. The Verus spec doesn't constrain the Err case beyond `true`. But the ensures clause of `dstack_zk_handle` says:
    ```rust
    Err(Error::ZkdcapVerificationFailed) => {
        &&& old(storage).config matches Some(raw)
        &&& raw.zkdcap_vkey != 0
    }
    ```
    This claims that on `ZkdcapVerificationFailed`, config was Some and vkey was non-zero. But what if `zk_query_verify` returns `Err(_)` due to encode failure? The spec allows that. However, the production code would also return `ZkdcapVerificationFailed` in that case. So the Verus spec is actually weaker than production: it doesn't distinguish between verified=false and encode/decode failure, but it does witness that vkey was set. This seems okay.

  - But wait: production `DstackZkAttestation` uses `CONFIG.load(deps.storage).map_err(Error::Std)?`. If CONFIG is missing, it returns `Error::Std`. The Verus `dstack_zk_handle` returns `Err(Error::Std)` if `CONFIG.may_load` returns `Ok(None)`. This matches. But the Verus `CONFIG.may_load` is defined in `attested.rs` and also in `instantiate.rs` (different definitions). In `attested.rs`, `CONFIG.may_load` returns `Result<Option<Config>, Error>`. In production, `CONFIG` is `Item<RawConfig>`. The Verus model only has `mr_enclave` and `zkdcap_vkey` in `RawConfig`. It loses `light_client_opts`. Again, stubbing drift.

  - Production `DstackZkAttestation` constructs `QueryVerifyGnarkRequest` with `vkey_id: 0`. The Verus model doesn't have `vkey_id`. Not relevant.

  - Production `DstackZkAttestation` uses `deps.querier.query_grpc(...)`. The Verus stub `zk_query_verify` doesn't model the querier at all. This is an external_body hole.

  - The `trivial_handler` harness collapses `DstackAttestation`, `MockAttestation`, `Noop`, `DstackAnyAttestation` into one. But production `DstackAttestation` non-mock returns `Ok(Response::new().add_attribute("action", "dcap_quote_accepted"))`. `MockAttestation` returns `Ok(Response::default())`. `Noop` returns `Ok(Response::default())`. `DstackAnyAttestation` dispatches. The Verus `trivial_handler` just returns `Ok(Response::default())`. The spec doesn't distinguish them. This is under-specification if the intent cares about the response attributes, but the prompt says "the handler returns it but no caller logic depends on its shape". So maybe okay.

  - The `Attested` wrapper in production merges events and attributes from both inner handlers. The Verus prototype returns `Response::new()` and ignores the inner handler responses. This means the spec doesn't verify that the wrapper preserves events/attributes from the inner handlers. The comment says "Response is opaque; the handler returns it but no caller logic depends on its shape for the invariants we care about." But the production code DOES depend on the shape: it calls `add_events` and `add_attributes`. The Verus spec doesn't prove that these are called. This is a coverage gap.

**3. Verus: contracts/core/verus-prototype/session_create.rs vs Production: handler/execute/session_create.rs**

Production:
- `let addr = deps.api.addr_validate(self.contract())?;`
- `if addr != env.contract.address { return Err(Error::ContractAddrMismatch); }`
- `SESSION.save(deps.storage, &Session::create(self.nonce())).map_err(Error::Std)?;`

Verus:
- `let addr = match api.addr_validate(msg.contract()) { Ok(a) => a, Err(e) => return Err(e) };`
- `if addr != env.contract.address { return Err(Error::ContractAddrMismatch); }`
- `match SESSION.save(storage, &Session::create(msg.nonce())) { Ok(()) => ..., Err(e) => Err(e) }`

Issues:
- The `addr_validate` stub: production `deps.api.addr_validate(self.contract())` takes `&str` (or `String`?) and returns `StdResult<Addr>`. The Verus stub takes `u64` and returns `Result<u64, Error>`. The spec says `match (r, addr_oracle(s)) { (Ok(a), Ok(b)) => a == s && a == b, ... }`. But production `addr_validate` can return a canonical address different from the input string (e.g., bech32 normalization). The Verus model assumes `a == s` (identity). This is over-specification / stubbing drift. If production normalizes the address, the Verus model is wrong.

- Production `SESSION.save` can fail with `StdError` (serialization). Verus `SESSION.save` is body-verified and always returns `Ok(())`. The spec claims `Err(_) => final(storage).session == old(storage).session`, but the Err arm is unreachable in the prototype. The comment admits this: "the Err arm is unreachable for our types". So the spec claims error handling but never exercises it. This is similar to instantiate.rs.

- Production `SessionCreate` message has `contract()` returning some address type. Verus models it as `u64`. Fine.

- The Verus `handle` ensures clause says:
  ```rust
  Ok(_) => {
      final(storage).session == Some(Session::spec_create(msg.spec_nonce()))
      && addr_oracle(msg.spec_contract()) == Result::<u64, ()>::Ok(env.contract.address)
  }
  ```
  This says success implies the validated address equals env.contract.address. But production uses `addr_validate` which returns a canonical `Addr`. The comparison `addr != env.contract.address` compares `Addr` with `Addr`. The Verus model compares `u64 == u64`. The oracle `addr_oracle` is used to link them. But the Verus spec doesn't model that `addr_validate` can fail for invalid addresses. It says `match (r, addr_oracle(s)) { (Err(_), Err(_)) => true, _ => false }`. So if `addr_oracle` returns `Err`, then `addr_validate` must return `Err`. But `addr_oracle` is uninterpreted. The spec doesn't constrain what makes an address invalid. This is okay for a stub.

- However, the production handler returns `Error::ContractAddrMismatch` if addresses don't match. The Verus model returns `Error::ContractAddrMismatch`. Good.

- The Verus spec does NOT model the `deps.api.addr_validate` error being mapped to `Error::Std`? Wait, production does `deps.api.addr_validate(self.contract())?` which returns `StdError`. Then `?` converts to `Error::Std` via `From`? Actually, looking at the production code: `let addr = deps.api.addr_validate(self.contract())?;` The `?` would try to convert `StdError` to `Error`. If `Error` implements `From<StdError>`, then yes. The Verus model returns `Error` directly from `addr_validate`. This is a type mismatch. The production code can return `Error::Std` from addr_validate failure. The Verus model returns whatever `addr_validate` returns, which is `Error`. But the Verus `Error` enum only has `Std` and `ContractAddrMismatch`. So if `addr_validate` fails, it returns `Error::Std` (since the stub returns `Err(e)` where `e` is passed through? Wait, the stub signature is `pub fn addr_validate(&self, s: u64) -> (r: Result<u64, Error>)`. The body is `Ok(s)`. So it never returns Err in the executable code. But the spec allows it via the oracle. The oracle links it. This is fine.

- Missing SEQUENCE_NUM: production `session_create.rs` doesn't touch SEQUENCE_NUM. That's `session_set_pub_key.rs`. So no issue here.

**4. Verus: contracts/core/verus-prototype/session_set_pub_key.rs vs Production: handler/execute/session_set_pub_key.rs**

Production:
- `let session = SESSION.load(deps.storage).map_err(Error::Std)?;`
- `let (nonce, pub_key) = self.into_tuple();`
- `let session = session.with_pub_key(nonce, pub_key.clone()).ok_or(Error::BadSessionTransition)?;`
- `SESSION.save(deps.storage, &session).map_err(Error::Std)?;`
- `let sequence_num = Uint64::new(0);`
- `SEQUENCE_NUM.save(deps.storage, &sequence_num).map_err(Error::Std)?;`

Verus:
- `let loaded = match SESSION.may_load(storage) { Ok(s) => s, Err(e) => return Err(e) };`
- `let session = match loaded { Some(s) => s, None => return Err(Error::BadSessionTransition) };`
- `let updated = match session.with_pub_key(msg_nonce, msg_pub_key) { Some(u) => u, None => return Err(Error::BadSessionTransition) };`
- `match SESSION.save(storage, &updated) { Ok(()) => Ok(()), Err(e) => Err(e) }`

Issues:
- Production uses `SESSION.load` which errors if no session exists. Verus uses `SESSION.may_load` and manually returns `BadSessionTransition` if None. Semantically equivalent for this path, but the error variant differs? Production `SESSION.load` failing would return `Error::Std` (from `map_err(Error::Std)`), not `Error::BadSessionTransition`. Wait! Let's look carefully.

Production:
```rust
let session = SESSION.load(deps.storage).map_err(Error::Std)?;
```
If `SESSION.load` returns `Err(StdError)`, then `?` returns `Error::Std`. This happens if no session exists (since `load` errors on missing). So production returns `Error::Std` when session is missing!

Then:
```rust
let session = session.with_pub_key(nonce, pub_key.clone()).ok_or(Error::BadSessionTransition)?;
```
If `with_pub_key` returns `None`, then `ok_or` returns `Err(Error::BadSessionTransition)`.

So production distinguishes:
- Missing session in storage → `Error::Std`
- Session exists but nonce mismatch or pub_key already set → `Error::BadSessionTransition`

Verus:
```rust
let loaded = match SESSION.may_load(storage) {
    Ok(s) => s,
    Err(e) => return Err(e),
};
let session = match loaded {
    Some(s) => s,
    None => return Err(Error::BadSessionTransition),
};
```
So Verus returns `Error::BadSessionTransition` for BOTH missing session AND bad transition. It conflates the two error cases. The ensures clause says:
```rust
Err(_) => final(storage).session == old(storage).session,
```
It doesn't distinguish the error variants. But the production code returns different errors. The Verus spec claims `Err(BadSessionTransition)` covers all error cases, but production can return `Err(Std)` from `SESSION.load` or `SESSION.save`. The Verus `SESSION.may_load` and `SESSION.save` are body-verified and infallible (always Ok). So the only error path in Verus is `None` session or `with_pub_key` failure, both returning `BadSessionTransition`.

Wait, looking at Verus `SESSION.may_load` body:
```rust
Ok(match &storage.session {
    Some(s) => Some(Session { nonce: s.nonce, pub_key: s.pub_key }),
    None => None,
})
```
It always returns `Ok`. And `SESSION.save` always returns `Ok`. So the `Err(e)` arms in `handle` are unreachable. The only reachable errors are `BadSessionTransition` from `None` or `with_pub_key` failure.

But production `SESSION.load` can fail (missing session → `StdError`). The Verus prototype models `may_load` as infallible. So the Verus spec does not model the `Error::Std` path from missing session. This is a stubbing drift / bool-result discipline issue: production returns `Result<T, E>` with multiple error variants, Verus collapses them.

- SEQUENCE_NUM: Production initializes `SEQUENCE_NUM` to 0. The Verus prototype does NOT model `SEQUENCE_NUM` at all. The `Storage` struct only has `session: Option<Session>`. The spec doesn't mention sequence numbers. This is a coverage gap. The prompt specifically asks: "Sequence number / replay protection: session_create + session_set_pub_key prototypes — do they model the SEQUENCE_NUM bookkeeping that the production handlers depend on for replay protection?" The answer is no. The Verus `session_set_pub_key.rs` completely ignores `SEQUENCE_NUM`. So the spec proves properties about session transitions but misses the replay protection initialization.

- Production `SESSION.save` and `SEQUENCE_NUM.save` can both fail. Verus `SESSION.save` is infallible. No `SEQUENCE_NUM` exists.

- Production `pub_key` is `Vec<u8>` (HexBinary). Verus models it as `u64`. Fine for control flow.

**5. Verus: enclave/core/verus-prototype/encryption.rs vs Production: enclave/core/encryption.rs**

Production:
- `encrypt(pubkey, plaintext)` → `ecies::encrypt(...)`
- `decrypt(privkey, ciphertext)` → `ecies::decrypt(...)`
- `encrypt_json(pubkey, value)` → `serde_json::to_vec` then `encrypt`
- `decrypt_json(privkey, ciphertext)` → `decrypt` then `serde_json::from_slice`

Verus:
- `encrypt`, `decrypt`, `encrypt_json`, `decrypt_json` are wrappers around external_body stubs.
- Proves roundtrip theorems using axioms.

Issues:
- The production functions return `Result<Vec<u8>, String>` (error type is `String`). Verus returns `Result<Vec<u8>, CryptoError>` where `CryptoError` is an enum `{ Ecies, Serde }`. The Verus spec doesn't model the `String` error content. But more importantly, the production `encrypt_json` returns `Err(format!("JSON serialize failed: {e}"))` or `Err(format!("ECIES encrypt failed: {e}"))`. The Verus model returns `CryptoError::Serde` or `CryptoError::Ecies`. This is a type mismatch but maybe acceptable for spec level.

- The `encrypt_json` Verus function:
  ```rust
  pub fn encrypt_json(pubkey: &VerifyingKey, value: &Message) -> (r: Result<Vec<u8>, CryptoError>)
      ensures
          match r {
              Ok(c) => exists |bytes: Seq<u8>| #![auto]
                  serde_to_vec_spec(*value) == Result::<Seq<u8>, CryptoError>::Ok(bytes)
                  && ecies_encrypt_spec(*pubkey, bytes) == Result::<Seq<u8>, CryptoError>::Ok(c@),
              Err(_) => true,
          },
  ```
  The `Err(_) => true` means the spec imposes NO constraint on error cases. But production `encrypt_json` can fail in two places: `serde_json::to_vec` or `ecies::encrypt`. The Verus spec doesn't specify which error is returned or any relationship between the error and the inputs. This is under-specification.

- Similarly, `decrypt_json` has `Err(_) => true`.

- The `encrypt` and `decrypt` wrappers have tight ensures matching the external_body stubs. But the stubs themselves are uninterpreted. The spec says "we do NOT prove secp256k1 hardness... those remain trust-boundary axioms". This is honest.

- However, the `ecies_roundtrip_axiom` says:
  ```rust
  ecies_encrypt_spec(verifying_key_spec(sk), pt) is Ok,
  match ecies_encrypt_spec(verifying_key_spec(sk), pt) {
      Ok(bytes) => ecies_decrypt_spec(sk, bytes) == Result::<Seq<u8>, CryptoError>::Ok(pt),
      Err(_)    => false,
  }
  ```
  This axiom asserts that encryption ALWAYS succeeds for ANY plaintext. But production `ecies::encrypt` can fail (e.g., invalid public key, internal errors). The axiom makes the roundtrip theorem vacuously inapplicable to real failure cases. More importantly, the axiom is false if `ecies::encrypt` can fail. The Verus comment says "Match Lean's `roundtrip` axiom (total: encrypt succeeds and decrypt recovers the plaintext)." But if the production function can return `Err`, the axiom that it always succeeds is a mismatch. This is an over-specification / impossibility-hypothesis vacuity issue? Actually, it's an unsound axiom relative to production behavior. If `ecies::encrypt` can fail, the axiom is false. The spec builds on a false premise. This is critical.

Wait, does `ecies::encrypt` ever fail? Looking at the `ecies` crate (commonly `ecies-rs` or similar), `encrypt` usually returns `Result<Vec<u8>, EciesError>`. It can fail for invalid public keys or other reasons. The production code handles this with `?`. So yes, it can fail. The axiom that it always succeeds is unsound.

Similarly, `serde_roundtrip_axiom` asserts `serde_to_vec_spec(v) is Ok` for all `v`. But `serde_json::to_vec` can fail? Actually, `serde_json::to_vec` returns `Result<Vec<u8>, serde_json::Error>`. It can fail if the type cannot be serialized (e.g., contains a map with non-string keys, or a float NaN). The Verus comment says "serde_json is similarly assumed total on Message (no NaN floats, no nonstring map keys — the discipline serde_json honours on small records of primitives)." But `Message` in Verus is `struct Message { pub a: u64, pub b: u64 }`. This is safe. But the axiom is stated for ALL `Message` values. Since `Message` only has u64 fields, `serde_json::to_vec` is indeed total. So that's okay.

But for ECIES, the axiom is `forall sk, pt. ecies_encrypt_spec(verifying_key_spec(sk), pt) is Ok`. Is this true? If `pt` is any `&[u8]`, and `pubkey` is a valid verifying key, `ecies::encrypt` generally returns `Ok`. But if the pubkey is invalid (e.g., point at infinity), it might fail. The Verus `VerifyingKey` type is opaque with `id: u64`. There's no constraint that `id` corresponds to a valid key. The `verifying_key_spec` is uninterpreted. So the axiom quantifies over all `VerifyingKey`s, including those that might not be valid curve points. If the production `ecies::encrypt` can fail on some pubkeys, the axiom is false. This is an impossibility-hypothesis vacuity? No, it's an unsound axiom. The category might be "Over-specification" or "Contradiction" with production behavior.

Actually, looking at the production code: `encrypt(pubkey: &VerifyingKey, plaintext: &[u8]) -> Result<Vec<u8>, String>`. It calls `ecies::encrypt(&pubkey.to_sec1_bytes(), plaintext)`. `pubkey.to_sec1_bytes()` produces a valid SEC1 encoding of a point on secp256k1. Since `VerifyingKey` from `k256` is always a valid point (it's impossible to construct an invalid one through safe APIs), `ecies::encrypt` should succeed for all valid inputs. But can `ecies::encrypt` still fail? Possibly due to RNG failure or other internal errors. But assuming the `ecies` crate is well-behaved, it might always succeed for valid keys. However, the axiom is still stronger than necessary and might be unsound if the underlying implementation has any failure mode.

More importantly, the `encrypt_json_decrypt_json_roundtrip` theorem proves:
```rust
serde_to_vec_spec(msg) is Ok,
match serde_to_vec_spec(msg) {
    Ok(bytes) => {
        &&& ecies_encrypt_spec(verifying_key_spec(sk), bytes) is Ok
        &&& (match ecies_encrypt_spec(verifying_key_spec(sk), bytes) {
            Ok(ct) => ecies_decrypt_spec(sk, ct) == Result::<Seq<u8>, CryptoError>::Ok(bytes),
            Err(_) => false,
        })
        &&& serde_from_slice_spec(bytes) == Result::<Message, CryptoError>::Ok(msg)
    }
    Err(_) => false,
}
```
This is a proof function, not an exec function. It uses axioms. The issue is that the theorem doesn't actually constrain the production wrappers `encrypt_json` and `decrypt_json` because those are exec functions with weak ensures (`Err(_) => true`). The roundtrip theorem is a `proof fn` that proves a property about the spec functions, but the exec functions' specs don't inherit this. So the verified property is about the axioms, not about the executable wrappers. This is a refinement mismatch: the proof functions prove properties that don't connect back to the executable code's contracts.

Wait, the exec functions `encrypt_json` and `decrypt_json` have ensures clauses