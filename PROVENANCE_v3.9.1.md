# Deployment Provenance — adn-processor v3.9.1

Binds source to artifact. v3.9.1 adds issuer-pinned authorization (C-00 fix) on top of v3.9.0 crypto.

| Field | Value |
|---|---|
| Contract version | 3.9.1 |
| WASM SHA-256 (unpinned/fail-closed default) | `ccc4a0be5b1943836d19c5e99484adc3388f6116293436f3b4232b439a11abf1` |
| WASM size | 411,644 bytes |
| Rust toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Target | wasm32-wasip2 |
| Build profile | release, opt-level="s", lto=true, codegen-units=1, panic=abort, strip=true |
| Crypto deps | k256 0.13 (ecdsa+arithmetic), sha3 0.10, sha2 0.10 |
| Tests | 19/19 (`cargo test --lib`): 7 crypto-vector + 12 contract-level delegate_task |

## IMPORTANT — the committed WASM SHA is the UNPINNED build

Built without `ADN_TRUSTED_ISSUER`, the contract **fails closed**: every `delegate-task`
is rejected ("trusted issuer not pinned"). This is the secure default. To run the live
demo, the operator must build pinned to their tenant issuer address, which yields a
DIFFERENT (and operator-recorded) SHA-256.

## Reproduce + pin

```bash
# 1. Derive your tenant issuer address (local, deterministic — needs only the key)
cd t3n-bridge
T3N_API_KEY=0x<key> node scripts/derive_issuer.mjs

# 2. Build the contract pinned to that issuer
cd ../contract
ADN_TRUSTED_ISSUER=<addr-hex> cargo build --target wasm32-wasip2 --release
sha256sum target/wasm32-wasip2/release/adn_processor.wasm   # record this for your proof

# 3. Verify logic
cargo test --lib   # 19/19

# 4. Live deploy + proof (registers the pinned WASM at v3.9.1, then invokes)
cd ../t3n-bridge
T3N_API_KEY=0x<key> node --loader ts-node/esm src/index.ts 2>&1 | tee ../proof/live_run_v3.9.1.txt
```

## What v3.9.1 enforces on delegate-task

- mandatory `user_sig` recovered (EIP-191) to the **pinned tenant issuer** — self-issued credential rejected
- `agent_sig` (secp256k1) verified over the invocation preimage — agent possession proof
- issuer-signed `adn_authorization_v1` policy binds target, action, max TTL
- `request_hash` recomputed and bound to `to_agent_id`/`action`
- nonce exactly 16 bytes; credential TTL ≤ 300s; envelope mandatory (C-01)

## Still NOT claimed (genuinely runtime-blocked)

- Durable replay prevention: `generic-input` WIT world imports no KV/storage; consumed
  nonces cannot be persisted in this contract. Exact-invocation replay within the ≤300s
  TTL is not contract-prevented. Needs a state-capable world or a sole-path gateway.