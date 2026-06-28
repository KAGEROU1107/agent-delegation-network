# Agent Delegation Network
**Terminal 3 Agent Dev Kit Bounty Challenge Submission**

[![Tests](https://github.com/KAGEROU1107/agent-delegation-network/actions/workflows/ci.yml/badge.svg)](https://github.com/KAGEROU1107/agent-delegation-network/actions/workflows/ci.yml)

A multi-agent delegation system built on the Terminal 3 ADK. A T3N-authenticated bridge passes session context to an ephemeral Ed25519 Python coordinator, which delegates tasks to ephemeral Ed25519 sub-agents and verifies signed worker results.

---

## Live Proof

All phases in the current committed live proof run against the real T3N testnet using `adn-processor` contract v3.8.1 with hardened structural delegation enforcement. The v3.9.2 cryptographic path is built and unit-tested, but still needs a pinned live deployment proof.

Full output: [`proof/live_run_v3.8.1_final_88b7b88.txt`](proof/live_run_v3.8.1_final_88b7b88.txt) · [`proof/live_run_v3.8.1_c01_proof.txt`](proof/live_run_v3.8.1_c01_proof.txt)

```
[Phase 0] Agent Auth SDK — delegation credential + enforcement cycle...
  [+] credential built: vc_id=<16-byte-id>
  [+] granted functions: delegate-task, process-data
  [+] signed with EIP-191: user_sig=<sig-prefix>...
  [+] envelope: agent_sig=<agent-sig>... nonce=<nonce>...
  [+] pre-revocation call:  ACCEPTED: {"delegation_id":...,"status":"ROUTED",...}
  [+] revocation: SUCCESS (tee:delegation/contracts::revoke)
  [35s sleep — credential window expires]
  [+] post-revocation call: REJECTED: delegate-task: credential expired (TEE contract layer v3.8.1)
  [+] missing agent_sig:    REJECTED: delegate-task: agent_sig missing from envelope
  [+] short nonce (4 bytes): REJECTED: delegate-task: nonce too short (< 8 bytes)

[Phase 1] T3N Auth
  [+] handshake() complete
  [+] authenticate() complete
  [+] Authenticated DID: did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
  [+] TenantClient initialized

[Phase 2] Python ADN — Multi-Agent Delegation
  [+] Unique cryptographic identities: 4/4
  [+] Records processed: 30
  [+] Quality score: 1 | passed: true
  [+] T3N DID injected as session context: true

[Phase 3] TEE Contract (v3.8.1 — real computation + hardened delegation enforcement)
  [+] Registered: tail=adn-processor version=3.8.1
  [+] Sending 30 sale records into TEE enclave for computation
  [+] TEE result: 30 records | total=$13253 | avg=$441.77 | min=$198.25 | max=$687.75 | trend=increasing
  [+] processed_in_tee: true
  [+] validate-quality → score=1 | validated_in_tee: true
  [+] Negative test — empty records → TEE rejected: process-data: records cannot be empty

[Phase 4] Full Feature Contract Coverage — all 20 WIT exports invoked
  [+] delegate-task, submit-bid, resolve-auction, record-completion, get-reputation
  [+] send-personalized-outreach, issue-time-grant, check-grant
  [+] kyc-submit-step, kyc-get-status, store-secret, invoke-with-secret
  [+] cast-vote, tally-votes, log-decision, audit-decisions, lock-bond, verify-and-settle
  [+] All 20 WIT exports invoked via live T3N TEE bridge.

WASM contract: REGISTERED + INVOKED (v3.8.1, 20/20 WIT functions)
```

**Real enclave computation**: 30 CSV sale records are sent into the TEE at runtime. The Rust contract computes `total`, `avg`, `min`, `max`, and `trend` inside the hardware-isolated enclave. No hardcoded result values are used for the core computation path.

**Negative live test**: Phase 3 sends an empty `records: []` payload to `process-data` and confirms the TEE rejects it with `process-data: records cannot be empty`.

> **Note on the Python feature demo**: `demo/features_demo.py` demonstrates interaction patterns using a local TEE simulation. The authoritative live proof is the TypeScript bridge run above: every WIT export is invoked against the real T3N testnet.

---

## Artifact Provenance

```
SDK:    @terminal3/t3n-sdk@3.5.2
WASM:   adn_processor.wasm v3.8.1 — hardened envelope validation + SHA-256 credential fingerprint
Proof:  proof/live_run_v3.8.1_final_88b7b88.txt
Run:    ADN_RUNTIME_MODE=live T3N_API_KEY=0x<key> ADN_GATEWAY_PRIVATE_KEY_HEX=<ed25519-seed-hex> ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX=<ed25519-pubkey-hex> npm run live  (from t3n-bridge/)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  t3n-bridge/  TypeScript — real Terminal 3 ADK          │
│                                                         │
│  T3nClient.handshake()       → encrypted channel to T3N │
│  T3nClient.authenticate()    → real DID from testnet    │
│  TenantClient                → contract + map tooling   │
│  tenant.contracts.register() → TEE contract deployment  │
│  t3n.executeAndDecode()      → live TEE invocation      │
└────────────────────┬────────────────────────────────────┘
                     │ passes real DID into Python flow as session context
┌────────────────────▼────────────────────────────────────┐
│  src/  Python — Agent Delegation Network                │
│                                                         │
│  Coordinator: ephemeral Ed25519 agent in T3N session    │
│  Workers:     ephemeral Ed25519 keys per session        │
│  Protocol:    signed delegation requests + data_hash    │
│  Policy:      role-based authorization engine           │
└────────────────────┬────────────────────────────────────┘
                     │ separate TEE authorization/computation calls
┌────────────────────▼────────────────────────────────────┐
│  contract/  Rust WASM — runs inside T3N TEE             │
│                                                         │
│  WIT interface: z:adn-processor@0.1.0                   │
│  process-data: enclave aggregation over runtime records │
│  validate-quality: quality scoring in TEE               │
│  delegate-task: contract-layer delegation enforcement   │
└─────────────────────────────────────────────────────────┘
```

---

## Stack

| Layer | Technology | T3N Integration |
|---|---|---|
| Auth | `@terminal3/t3n-sdk` | `handshake()` + `authenticate()` → real DID |
| Tenant | `TenantClient` | contract registration and map setup |
| TEE Contract | Rust + `wasm32-wasip2` | registered and invoked on T3N testnet |
| WIT Interface | `z:adn-processor@0.1.0` | `contracts` interface, `generic-input` record |
| Delegation | Python Ed25519 | Coordinator and workers: ephemeral keys within T3N session context |

---

## Agent Identity Model

The Python coordinator is an ephemeral Ed25519 agent operating within a T3N-authenticated session context.

**Workers and validators** also use ephemeral Ed25519 keys generated per session. This is intentional: sub-agents in the delegation network are short-lived. Their outputs are checked by the coordinator-side verifier; the T3N DID remains session context, not the coordinator's signing identity.

Each agent has a **distinct cryptographic identity**. Every delegation request is signed and carries a `data_hash` over the payload, making post-signing mutation detectable.

---

## Agent Auth Enforcement

The TypeScript bridge demonstrates the Agent Auth credential lifecycle:

1. Build a scoped `DelegationCredential`.
2. Sign it with EIP-191.
3. Build a per-call `DelegationEnvelope` (includes `agent_sig`, `nonce`, `request_hash`).
4. Submit the envelope to `delegate-task`.
5. Accept the delegated call while the credential is valid.
6. Revoke the credential through T3N delegation infrastructure.
7. Wait for the short TTL window to expire.
8. Confirm the TEE contract rejects the expired delegated call.

The `adn-processor` v3.8.1 contract validates inside the TEE:
- Credential time window and temporal consistency (`not_before < not_after`)
- Function scope (`delegate-task` must be in `functions`)
- Credential field completeness (`vc_id`, `agent_pubkey` presence)
- Envelope completeness (`nonce` ≥8 bytes decoded, `agent_sig` present)
- Emits `credential_fingerprint` (SHA-256 of validated credential bytes)

**Boundary**: real-time revocation registry lookup from inside a `generic-input` WASM contract is not yet available through a documented ADK host primitive. The demo uses short-lived credentials plus contract-layer expiry enforcement.

---

## TEE Contract

The Rust WASM contract follows the T3N WIT format:

```wit
package z:adn-processor@0.1.0;

interface contracts {
  record generic-input {
    input:        option<list<u8>>,
    user-profile: option<list<u8>>,
    context:      option<list<u8>>,
  }

  process-data:               func(req: generic-input) -> result<list<u8>, string>;
  validate-quality:           func(req: generic-input) -> result<list<u8>, string>;
  delegate-task:              func(req: generic-input) -> result<list<u8>, string>;
  submit-bid:                 func(req: generic-input) -> result<list<u8>, string>;
  resolve-auction:            func(req: generic-input) -> result<list<u8>, string>;
  record-completion:          func(req: generic-input) -> result<list<u8>, string>;
  get-reputation:             func(req: generic-input) -> result<list<u8>, string>;
  send-personalized-outreach: func(req: generic-input) -> result<list<u8>, string>;
  issue-time-grant:           func(req: generic-input) -> result<list<u8>, string>;
  check-grant:                func(req: generic-input) -> result<list<u8>, string>;
  kyc-submit-step:            func(req: generic-input) -> result<list<u8>, string>;
  kyc-get-status:             func(req: generic-input) -> result<list<u8>, string>;
  store-secret:               func(req: generic-input) -> result<list<u8>, string>;
  invoke-with-secret:         func(req: generic-input) -> result<list<u8>, string>;
  cast-vote:                  func(req: generic-input) -> result<list<u8>, string>;
  tally-votes:                func(req: generic-input) -> result<list<u8>, string>;
  log-decision:               func(req: generic-input) -> result<list<u8>, string>;
  audit-decisions:            func(req: generic-input) -> result<list<u8>, string>;
  lock-bond:                  func(req: generic-input) -> result<list<u8>, string>;
  verify-and-settle:          func(req: generic-input) -> result<list<u8>, string>;
}

world adn-processor {
  export contracts;
}
```

Default fail-closed build: `cd contract && cargo build --locked --target wasm32-wasip2 --release`. For a live v3.9.2 deployment, use the pinned issuer/tenant sequence below so the contract emits a non-self-referential `build_config_id` and the bridge records the final WASM SHA-256 in an external deployment manifest.

---

## Quickstart

**Prerequisites**: Node.js 18+, Python 3.10+, Rust + `wasm32-wasip2` target, Terminal 3 testnet API key

```bash
# Install TypeScript dependencies
cd t3n-bridge && npm install

# Derive the public issuer address from your Terminal 3 key
T3N_API_KEY=0x<your_key> node scripts/derive_issuer.mjs

# Build and test v3.9.2 pinned to that issuer and tenant DID
cd ../contract
BUILD_COMMIT=$(git rev-parse HEAD)
RUSTC_VERSION="$(rustc --version)"
ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION="$RUSTC_VERSION" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo test --locked
ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION="$RUSTC_VERSION" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo build --locked --target wasm32-wasip2 --release

# Deploy/invoke the pinned artifact and capture fresh proof
cd ../t3n-bridge
T3N_API_KEY=0x<your_key> ADN_RUNTIME_MODE=live ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION="$RUSTC_VERSION" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> ADN_GATEWAY_PRIVATE_KEY_HEX=<32-byte-ed25519-seed-hex> ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX=<matching-ed25519-pubkey-hex> ADN_GATEWAY_KEY_ID=<gateway-key-id> ADN_RELEASE_OPERATOR_PRIVATE_KEY_HEX=<32-byte-ed25519-release-seed-hex> ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX=<matching-ed25519-release-pubkey-hex> ADN_REPLAY_LEDGER_DIR=../runtime/replay_ledger ADN_REPLAY_LEDGER_KEY_REF=file:/var/lib/adn/replay-hmac.key npm run live 2>&1 | tee ../proof/live_run_v3.9.2.txt
```

**Judge-facing command:** use `npm run live` from `t3n-bridge/` with `ADN_RUNTIME_MODE=live`. `npm run demo` remains only as a legacy alias for the same TypeScript bridge entrypoint; it is not the local Python feature-pattern demo.

The bridge writes `proof/release/deployment_manifest.json` first as a pending manifest with the actual post-build `local_wasm_sha256`, then finalizes it after registration with `raw_registration_response_digest`, `registered_at`, optional `remote_contract_id`, and the first validated invocation digest. The legacy `proof/deployment_manifest_v3.9.2.local.json` path is kept only as a compatibility copy. This remains operator evidence rather than remote byte attestation until a pinned v3.9.2 proof bundle is committed, `Release Proof Input` completes, `Release Proof Attest` generates the final `ci_release_sha.json`, `python scripts/verify_release.py proof/release` passes, `python scripts/verify_release_remote.py proof/release` verifies the retained GitHub Actions artifact against the completed workflow-run metadata, and `python scripts/verify_release_asset.py <downloaded-release-asset-dir>` verifies the signed durable GitHub Release asset bundle.

### Optional: LLM text generation

The Python feature agents (`blind_auction.py`, `reputation_ledger.py`, etc.) use a generic LLM client for cognitive tasks (writing task specs, audit summaries, personalization messages). **The demo runs without it** — the client stubs out deterministic responses when no key is set.

For local demo/test LLM calls, copy `.env.example` to `.env` and fill in your credentials. Live bridge mode intentionally skips repository `.env` loading; provide production secrets through the service environment or key-provider references instead.

```bash
cp .env.example .env
# Edit .env:
#   LLM_API_KEY=sk-your-key
#   LLM_BASE_URL=https://api.openai.com/v1/chat/completions  # or any OpenAI-compatible endpoint
#   LLM_MODEL=gpt-4o-mini
```

The demo:
1. Authenticates with T3N testnet via `handshake()` + `authenticate()`.
2. Builds and tests an Agent Auth delegation credential.
3. Spawns Python ADN with the authenticated DID passed in as session context.
4. Runs multi-agent delegation with 4 distinct identities.
5. Registers the Rust/WASM contract after the pinned issuer preflight passes.
6. Invokes all 20 WIT exports through the live T3N bridge.
7. Runs a negative TEE validation test.

---

## Creative Features

> **Phase 2–11 are TEE computation patterns.** Inputs are caller-supplied; the contract is stateless between calls (no WIT storage imports). TEE executes the computation; authoritative persistence requires persistent map storage not implemented in this version.

| Phase | Feature Label | WIT Functions | Behavior |
|---|---|---|---|
| 0 | Agent Auth SDK | (SDK calls) | Live credential lifecycle on T3N; envelope mandatory on delegate-task |
| 1 | Core ADN + T3N Auth | process-data, validate-quality, delegate-task | Real T3N session context; ephemeral Ed25519 coordinator/workers; TEE authorization decision for delegated calls |
| 2 | TEE Auction-Resolution Pattern | submit-bid, resolve-auction | TEE computes winner from caller-supplied bids; no sealed bid store or commit/reveal |
| 3 | TEE Reputation-Score Pattern | record-completion, get-reputation | TEE computes score from caller-supplied history; no persistent ledger |
| 4 | TEE Personalization Pattern | send-personalized-outreach | Customer segmentation computed in enclave over caller-supplied records |
| 5 | TEE Temporal-Grant Pattern | issue-time-grant, check-grant | TEE validates caller-supplied epoch; no persistent grant store |
| 6 | TEE Cross-Input Computation | process-data | Multi-party inputs aggregated in a single TEE call |
| 7 | TEE KYC-Status Pattern | kyc-submit-step, kyc-get-status | TEE computes status from caller-supplied step list; no verified evidence store |
| 8 | TEE Secret-Vault Interaction Pattern | store-secret, invoke-with-secret | Validates non-empty permission proof; no persistent secret storage (no WIT KV import) |
| 9 | TEE Vote-Tally Pattern | cast-vote, tally-votes | TEE tallies caller-supplied votes; no persistent ballot store or duplicate prevention |
| 10 | TEE Decision-Audit Hash | log-decision, audit-decisions | Deterministic hash over caller-supplied records |
| 11 | TEE Settlement-Calculation Pattern | lock-bond, verify-and-settle | Computes payout from caller-supplied bond facts; no persistent escrow |

Run the local feature-pattern demo: `T3N_API_KEY=0x<key> python demo/features_demo.py`

---

## Contract Capabilities (v3.9.2)

**Current scope — stateless TEE computation:**
- Delegation decision: verifies tenant DID, gateway authorization receipt, and worker identity
- Process data: executes worker 1 with authorized parameters
- Validate quality: verifies worker 2 result against process receipt hash binding

**Not yet implemented (planned):**
- Persistent nonce tracking (requires wasi:keyvalue)
- Bond registry
- KYC vault
- Reputation ledger
- DAO governance

Claims about persistent contract state will be updated only after actual wasi:keyvalue integration and corresponding WIT capability imports.

---

## Security

**What is enforced in the current live v3.8.1 proof:** T3N authentication, SDK-native credential construction, Rust/WASM TEE structural validation of envelope presence, credential domain, TTL, delegated function scope, nonce format (≥8 bytes), and `agent_sig` presence. Delegation envelope is **mandatory** on `delegate-task` in v3.8.1 source. Trust policy requires both action rule AND explicit trust relationship (dual default-deny).

**Explicit live-proof boundaries:** v3.9.2 source adds issuer-pinned cryptographic verification, request binding, digest-derived delegation IDs, and a prepare -> authorize -> execute Python bridge that requires real `delegate-task` outputs for exact prepared worker IDs plus a dedicated pinned gateway signer. Workers now require the exact gateway public key, `gateway_key_id`, `build_config_id`, and `authorization_expires_at` carried by the typed authorization bundle. Worker request replay is recorded in a durable on-disk ledger keyed by delegation ID, request hash, and receipt fingerprint; completed requests stay single-use across restarts, running tasks renew their replay lease with an execution-token fence, and handler crashes become bounded retryable failures. Coordinator-side worker-result verification also persists accepted result fingerprints in a durable replay ledger so restarts do not re-accept the same signed result. Live bridge execution requires `ADN_RUNTIME_MODE=live`, `ADN_REPLAY_LEDGER_DIR` outside the temp tree, and `ADN_REPLAY_LEDGER_KEY_REF=file:<0600-hex-key-path>`; raw `ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX` is accepted only outside live mode. Request/result replay rows are MACed with domain-separated HMAC keys. It is still not backed by a pinned live deployment proof, and the receipt remains gateway-linked local evidence rather than a T3N-attested worker-dispatch primitive. Durable contract-layer nonce replay registry, persistent workflow state, and immediate revocation-registry lookup remain unproven in the current `generic-input` contract world. See [security-invariants.md](docs/architecture/security-invariants.md), [release criteria](docs/release/criteria.md), and [claim matrix](docs/security/claim-matrix.md).

Python security tests cover adapter/policy negative-security checks, worker-result verification, gateway receipts, request/result replay, bridge hardening, and audit guardrails.
Tests cover Python signing adapter, policy logic, coordinator-side result verification, TypeScript bridge buildability, and Rust/WASM contract enforcement. The committed live T3N proof remains the v3.8.1 structural proof until a pinned v3.9.2 run is captured.

```
python -m pytest tests/negative_security.py tests/test_result_verifier.py tests/test_audit_guards.py -v --tb=short
```

---

## Project Structure

```
agent-delegation-network/
├── t3n-bridge/                  # TypeScript — real T3N ADK integration
│   ├── src/
│   │   ├── t3n_auth.ts          # handshake() + authenticate() → DID
│   │   ├── agent_auth.ts        # Agent Auth credential + envelope demo
│   │   ├── contract_bridge.ts   # TEE contract registration + invocation v3.8.1
│   │   ├── map_setup.ts         # KV map creation with BUG-001 fallback
│   │   ├── adn_runner.ts        # spawns Python ADN with real DID
│   │   └── index.ts             # main entry point
│   ├── package.json             # @terminal3/t3n-sdk@3.5.2
│   └── tsconfig.json
├── contract/                    # Rust WASM TEE contract
│   ├── wit/world.wit            # WIT interface — 20 exported functions
│   ├── src/lib.rs               # all 20 functions implemented
│   └── Cargo.toml
├── src/                         # Python application orchestration layer (not ADK — TypeScript bridge is the ADK layer)
│   ├── agent_identity.py        # Ed25519 identity per agent
│   ├── delegation_protocol.py   # signed delegation requests
│   ├── delegation_policy.py     # role/trust/action policy engine
│   ├── agent_delegation_network.py
│   ├── blind_auction.py
│   ├── reputation_ledger.py
│   ├── secret_vault_agent.py
│   ├── temporal_delegation.py
│   ├── agent_dao.py
│   ├── decision_audit_agent.py
│   ├── kyc_pipeline.py
│   ├── performance_bond.py
│   ├── personalization_agent.py
│   └── cross_tenant_collab.py
├── demo/
│   ├── adn_demo.py              # core multi-agent workflow
│   └── features_demo.py         # local pattern demo for feature modules
├── tests/
│   ├── negative_security.py     # 34 Python signing and policy tests
│   └── test_result_verifier.py  # 11 worker-result verifier tests
├── proof/
│   ├── live_run_v3.6.0.txt      # v3.6.0 baseline proof
│   └── live_run_v3.5.0.txt      # v3.5.0 baseline proof
├── llm/
│   └── client.py                # generic LLM client (OpenAI-compatible, stubs when no key)
├── data/
│   └── sales_Q1-2026_US_premium.csv
├── .env.example                 # environment variable template
├── PHASES.md
├── SUBMISSION_REPORT.md
└── t3n_bridge_proof.txt         # live testnet output v3.8.1
```

---

## Sandbox Test Tokens

Sandbox API keys are available at: **https://www.terminal3.io/claim-page**

> **Security**: Do not commit `.env` or any real API key. Use `.env.example` as your
> template. All keys in this repo use `REDACTED_API_KEY` or `replace_me` placeholders.

---

## SDK Bugs & Documentation Gaps

Seven bugs and four documentation gaps were discovered and committed as structured
snapshots during development. These are bounty Track 2 evidence.

See `docs/bugs/` and `docs/doc-gaps/` for full details.

| ID | Title | Severity | Status |
|---|---|---|---|
| BUG-001 | `tenant.contracts.register()` returns no numeric contractId | MEDIUM | WORKAROUND_FOUND |
| BUG-002 | Agent Auth grant APIs not at top level | MEDIUM | UPSTREAM |
| BUG-003 | `buildDelegationCredential` rejects long `z:{tenant}:{tail}` format | LOW | WORKAROUND_FOUND |
| BUG-004 | Testnet `fuel_per_minute` quota limits Phase 4 in a single run | MEDIUM | WORKAROUND_FOUND |
| BUG-005 | Delegation envelope not validated at T3N transport layer for generic-input | HIGH | FIXED (v3.8.1) |
| BUG-006 | CI red X: `Post commit status` step failed the job | MEDIUM | FIXED (0c7b10b) |
| BUG-007 | Testnet credits exhausted during development | HIGH | OPEN |

| ID | Title | Status |
|---|---|---|
| DOCGAP-001 | DelegationCredential primitives undocumented in ADK overview | OPEN |
| DOCGAP-002 | `script_name` vs `contract` field distinction not documented | OPEN |
| DOCGAP-003 | `tee:delegation/contracts::is-live` host primitive not exposed | OPEN |
| DOCGAP-004 | Sandbox token claim process and credit limits not documented | OPEN |

---

## Known Boundaries

- The Python coordinator and workers are ephemeral Ed25519 agents within a T3N-authenticated session context, not independent T3N tenants.
- The Agent Auth revocation proof uses short-lived credential expiry for contract-layer rejection. Immediate revocation-registry lookup from inside `generic-input` WASM is documented as a current ADK gap.
- TEE Secret Vault is implemented as a secure-pattern demo, not a production persistent vault.
- Tenant map setup is skipped unless the current contract registration returns a numeric `contractId`; no historical ID or open ACL fallback is used.







