# Agent Delegation Network
**Terminal 3 Agent Dev Kit Bounty Challenge Submission**

[![Tests](https://github.com/KAGEROU1107/agent-delegation-network/actions/workflows/ci.yml/badge.svg)](https://github.com/KAGEROU1107/agent-delegation-network/actions/workflows/ci.yml)

A multi-agent delegation system built on the Terminal 3 ADK. A coordinator authenticates with T3N, delegates tasks to ephemeral Ed25519 sub-agents, and executes/verifies workloads through a Rust/WASM TEE contract on the T3N testnet.

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
Run:    T3N_API_KEY=0x<key> node --loader ts-node/esm src/index.ts  (from t3n-bridge/)
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
│  Coordinator: T3N-authenticated DID from session        │
│  Workers:     ephemeral Ed25519 keys per session        │
│  Protocol:    signed delegation requests + data_hash    │
│  Policy:      role-based authorization engine           │
└────────────────────┬────────────────────────────────────┘
                     │ outputs flow into TEE contract
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
| Delegation | Python Ed25519 | Coordinator: T3N DID; workers: ephemeral keys |

---

## Agent Identity Model

The **coordinator** is authenticated through the T3N ADK. Its DID comes directly from `t3n.authenticate()` against the testnet.

**Workers and validators** use ephemeral Ed25519 keys generated per session. This is intentional: sub-agents in the delegation network are short-lived. Their outputs flow into the TEE contract, which is bound to the coordinator's authenticated T3N identity.

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

Build: `cd contract && cargo build --target wasm32-wasip2 --release`

---

## Quickstart

**Prerequisites**: Node.js 18+, Python 3.10+, Rust + `wasm32-wasip2` target, Terminal 3 testnet API key

```bash
# Install TypeScript dependencies
cd t3n-bridge && npm install

# Run full live demo
T3N_API_KEY=0x<your_key> node --loader ts-node/esm src/index.ts
```

### Optional: LLM text generation

The Python feature agents (`blind_auction.py`, `reputation_ledger.py`, etc.) use a generic LLM client for cognitive tasks (writing task specs, audit summaries, personalization messages). **The demo runs without it** — the client stubs out deterministic responses when no key is set.

To enable live LLM calls, copy `.env.example` to `.env` and fill in your credentials:

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
5. Registers the Rust/WASM contract.
6. Invokes all 20 WIT exports through the live T3N bridge.
7. Runs a negative TEE validation test.

---

## Creative Features

> **Phase 2–11 are TEE computation patterns.** Inputs are caller-supplied; the contract is stateless between calls (no WIT storage imports). TEE executes the computation; authoritative persistence requires persistent map storage not implemented in this version.

| Phase | Feature Label | WIT Functions | Behavior |
|---|---|---|---|
| 0 | Agent Auth SDK | (SDK calls) | Live credential lifecycle on T3N; envelope mandatory on delegate-task |
| 1 | Core ADN + T3N Auth | process-data, validate-quality, delegate-task | Real T3N session; authenticated DID; TEE computation + structural delegation enforcement |
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

## Security

**What is enforced in the current live v3.8.1 proof:** T3N authentication, SDK-native credential construction, Rust/WASM TEE structural validation of envelope presence, credential domain, TTL, delegated function scope, nonce format (≥8 bytes), and `agent_sig` presence. Delegation envelope is **mandatory** on `delegate-task` in v3.8.1 source. Trust policy requires both action rule AND explicit trust relationship (dual default-deny).

**Explicit live-proof boundaries:** v3.9.2 source adds issuer-pinned cryptographic verification and request binding, but it is not yet backed by a pinned live deployment proof. Durable nonce replay registry, persistent workflow state, and immediate revocation-registry lookup remain unproven in the current `generic-input` contract world.

45 Python security tests across 10 categories: structural tamper, replay attack,
expired proof, wrong audience, forged key, missing required fields, agent identity
distinctness, delegation policy enforcement, credential TTL window validation,
worker-result verification, and result nonce retention/concurrency.
Tests cover Python signing adapter, policy logic, and coordinator-side result verification — TypeScript bridge and WASM contract enforcement are proven via live T3N proof artifacts.

```
python -m pytest tests/negative_security.py tests/test_result_verifier.py -v --tb=short
# 45 passed
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

- Workers are ephemeral Ed25519 sub-agents, not independent T3N tenants.
- The Agent Auth revocation proof uses short-lived credential expiry for contract-layer rejection. Immediate revocation-registry lookup from inside `generic-input` WASM is documented as a current ADK gap.
- TEE Secret Vault is implemented as a secure-pattern demo, not a production persistent vault.
- When the SDK does not return a numeric `contractId`, tenant map ACL setup falls back to `writers/readers: "all"` as a documented BUG-001 workaround.







