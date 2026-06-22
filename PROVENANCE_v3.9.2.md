# Deployment Provenance — adn-processor v3.9.2

Builds on v3.9.1 (issuer-pinned authorization) with: mandatory policy TTL (H-01) and
coordinator-side worker-result verification in the Python flow (H-05).

| Field | Value |
|---|---|
| Contract version | 3.9.2 |
| WASM SHA-256 (committed unpinned/fail-closed default) | `8a90dee4b1e45da34e32243c71de0ceccb4f6be9e408a50816c19c0b84afb147` |
| WASM size | 411,778 bytes |
| Rust toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Target | wasm32-wasip2 |
| Tests | Rust contract tests (`cargo test --locked`, including digest delegation ID and pinned/unpinned production-path coverage); Python security suite (`pytest tests/negative_security.py tests/test_result_verifier.py tests/test_audit_guards.py`) |

## The committed WASM SHA is the UNPINNED build (fails closed)

Built without `ADN_TRUSTED_ISSUER`, every `delegate-task` is rejected. The contract emits a `build_config_id` derived from source/config metadata only: contract version, commit, Rust version, trusted issuer, and tenant DID. It does not embed the final WASM hash in itself; the bridge records the actual post-build artifact hash, pending/final manifest digest, registration response digest, and first invocation digest in `proof/deployment_manifest_v3.9.2.local.json`.

To run the demo, build pinned to your tenant issuer (different SHA, operator-recorded):

```bash
cd t3n-bridge && T3N_API_KEY=0x<key> node scripts/derive_issuer.mjs
cd ../contract
BUILD_COMMIT=$(git rev-parse HEAD)
RUSTC_VERSION="$(rustc --version)"
ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION="$RUSTC_VERSION" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo test --locked
ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION="$RUSTC_VERSION" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo build --locked --target wasm32-wasip2 --release
ADN_TRUSTED_ISSUER=58da990a8f4a3a6ca7cb6315d68a140105917352 ADN_TENANT_DID=did:t3n:fixture cargo test --locked
python -m pytest tests/negative_security.py tests/test_result_verifier.py tests/test_audit_guards.py -v --tb=short
cd ../t3n-bridge && T3N_API_KEY=0x<key> ADN_RUNTIME_MODE=live ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION="$RUSTC_VERSION" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> ADN_GATEWAY_PRIVATE_KEY_HEX=<32-byte-ed25519-seed-hex> ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX=<matching-ed25519-pubkey-hex> ADN_GATEWAY_KEY_ID=<gateway-key-id> ADN_REPLAY_LEDGER_DIR=../runtime/replay_ledger ADN_REPLAY_LEDGER_KEY_REF=file:/var/lib/adn/replay-hmac.key node --loader ts-node/esm src/index.ts 2>&1 | tee ../proof/live_run_v3.9.2.txt
```

## v3.9.2 enforcement summary

delegate-task (Rust/WASM):
- mandatory issuer-pinned `user_sig` (EIP-191) — self-issued credential rejected
- `agent_sig` (secp256k1) verified over the invocation preimage
- issuer-signed `adn_authorization_v1` binds target, action; `max_ttl_secs` mandatory 1..=300
- `request_hash` recomputed and bound to to_agent_id/action; nonce exactly 16 bytes
- digest-derived `delegation_id`; `build_config_id` emitted in delegate-task output; final WASM SHA recorded externally in the deployment manifest

Python multi-agent flow:
- bridge prepares exact Python worker identities, obtains real `delegate-task`
  authorization for those targets, and passes the typed T3N results into Python
- dedicated pinned gateway signer issues the worker receipt; workers and the
  coordinator both require the pinned gateway public key, exact `gateway_key_id`,
  exact `build_config_id`, and `authorization_expires_at`
- worker request replay is recorded in a durable on-disk ledger keyed by
  `SHA-256(delegation_id || request_hash || receipt_fingerprint)`; completed
  requests remain single-use across restart, running tasks renew a lease while
  active with an execution-token fence, and handler failures are marked
  `RETRYABLE_FAILURE` so the same authorization can be retried before expiry up
  to a bounded cap
- coordinator verifies each worker result (Ed25519 sig, signer, data_hash binding,
  delegation_id, audience, COMPLETED status, signed gateway TEE authorization
  receipt, lock-guarded nonce cache, and a durable result replay ledger keyed by
  worker key, coordinator, delegation ID, result nonce, and receipt fingerprint)
  before consuming it
- live bridge execution requires `ADN_REPLAY_LEDGER_DIR` outside the temp tree
  and `ADN_REPLAY_LEDGER_KEY_REF=file:<0600-hex-key-path>`; raw
  `ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX` is test/demo only; request/result replay
  rows are MACed with domain-separated HMAC keys

## Still NOT claimed (runtime-blocked)

- Durable replay prevention at the contract layer: this `generic-input` WIT world imports
  no KV/storage capability. Needs a state-capable world or a sole-path gateway.
- T3N-attested TEE-to-worker dispatch: Python workers require a signed gateway
  `TEE_AUTHORIZATION` receipt locally, but no fresh live proof yet shows a T3N-attested
  receipt consumed by a worker.
