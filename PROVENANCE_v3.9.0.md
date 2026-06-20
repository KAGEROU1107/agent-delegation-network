# Deployment Provenance — adn-processor v3.9.0

This manifest binds the source to the built artifact so an evaluator can reproduce it.

| Field | Value |
|---|---|
| Contract version | 3.9.0 |
| Source commit (pre-build) | 521319d08138a45fd08d9ab530ad2a892ca46509 |
| WASM SHA-256 | `d04048fad022687bafa03353b0daf4eb4d59d51f058fe83a386204557c050506` |
| WASM size | 400,995 bytes |
| Cargo.lock SHA-256 | `06efcc3637727c262eb62cf3986052006b43765f68b41542fe41cf6dce169092` |
| Rust toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Target | wasm32-wasip2 |
| Build profile | release, opt-level="s", lto=true, codegen-units=1, panic=abort, strip=true |
| Crypto deps | k256 0.13 (ecdsa+arithmetic), sha3 0.10, sha2 0.10 |

## Reproduce

```bash
cd contract
cargo build --target wasm32-wasip2 --release
sha256sum target/wasm32-wasip2/release/adn_processor.wasm
# expect: d04048fad022687bafa03353b0daf4eb4d59d51f058fe83a386204557c050506
cargo test --lib          # 7/7 crypto verification tests
```

## Ground-truth crypto vectors

Generated from the installed `@terminal3/t3n-sdk` (no hand-authored signatures):

```bash
cd t3n-bridge
node scripts/gen_vectors.mjs    # agent_sig / preimage / request_hash
node scripts/gen_jcs.mjs        # credential JCS + user_sig + recovered address
```

The Rust unit tests in `contract/src/crypto.rs` hardcode these vectors and assert
byte-for-byte agreement, so SDK-produced signatures verify in the contract.

## Live deployment (operator step)

Redeploy requires a T3N API key and network, so it is run by the operator, not in CI:

```bash
cd t3n-bridge
# T3N register() uploads contract/target/wasm32-wasip2/release/adn_processor.wasm
# at version 3.9.0 (must be > deployed 3.8.1), then invokes it.
T3N_API_KEY=0x<key> node --loader ts-node/esm src/index.ts 2>&1 | tee ../proof/live_run_v3.9.0.txt
```

After the run, the committed live proof must show the WASM SHA-256 above and the
v3.9.0 negative matrix (forged agent_sig, altered target/action, short/empty nonce,
missing request_hash) each REJECTED by the live contract.