# Deployment Provenance — adn-processor v3.9.2

Builds on v3.9.1 (issuer-pinned authorization) with: mandatory policy TTL (H-01) and
coordinator-side worker-result verification in the Python flow (H-05).

| Field | Value |
|---|---|
| Contract version | 3.9.2 |
| WASM SHA-256 (unpinned/fail-closed default) | `c7dfcac7ae174765b69dc765824545396b1e5cac2e47129cf0c696c8690369a9` |
| WASM size | 411,644 bytes |
| Rust toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Target | wasm32-wasip2 |
| Tests | Rust 22/22 (`cargo test --lib`); Python 45/45 (`pytest tests/negative_security.py tests/test_result_verifier.py`) |

## The committed WASM SHA is the UNPINNED build (fails closed)

Built without `ADN_TRUSTED_ISSUER`, every `delegate-task` is rejected. To run the demo,
build pinned to your tenant issuer (different SHA, operator-recorded):

```bash
cd t3n-bridge && T3N_API_KEY=0x<key> node scripts/derive_issuer.mjs
cd ../contract && ADN_TRUSTED_ISSUER=<addr> cargo build --target wasm32-wasip2 --release
cargo test --lib   # 22/22
python -m pytest tests/negative_security.py tests/test_result_verifier.py -v --tb=short   # 45/45
cd ../t3n-bridge && T3N_API_KEY=0x<key> node --loader ts-node/esm src/index.ts 2>&1 | tee ../proof/live_run_v3.9.2.txt
```

## v3.9.2 enforcement summary

delegate-task (Rust/WASM):
- mandatory issuer-pinned `user_sig` (EIP-191) — self-issued credential rejected
- `agent_sig` (secp256k1) verified over the invocation preimage
- issuer-signed `adn_authorization_v1` binds target, action; `max_ttl_secs` mandatory 1..=300
- `request_hash` recomputed and bound to to_agent_id/action; nonce exactly 16 bytes

Python multi-agent flow:
- coordinator verifies each worker result (Ed25519 sig, signer, data_hash binding,
  delegation_id, audience, COMPLETED status, lock-guarded single-use result nonce
  with bounded in-memory retention) before consuming it

## Still NOT claimed (runtime-blocked)

- Durable replay prevention at the contract layer: this `generic-input` WIT world imports
  no KV/storage capability. Needs a state-capable world or a sole-path gateway.
