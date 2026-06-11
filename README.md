# Agent Delegation Network
**Terminal 3 Agent Dev Kit Bounty Challenge Submission**

A multi-agent delegation system built on the Terminal 3 ADK. A coordinator authenticates with T3N, delegates tasks to ephemeral Ed25519 sub-agents, and executes/verifies workloads through a Rust/WASM TEE contract on the T3N testnet.

---

## Live Proof

All phases run against the real T3N testnet using `adn-processor` contract v3.6.0 with contract-layer delegation enforcement.

Full output: [`t3n_bridge_proof.txt`](t3n_bridge_proof.txt) · [`proof/live_run_v3.6.0.txt`](proof/live_run_v3.6.0.txt)

```
[Phase 0] Agent Auth SDK — delegation credential + enforcement cycle...
  [+] credential built: vc_id=<16-byte-id>
  [+] granted functions: delegate-task, process-data
  [+] signed with EIP-191: user_sig=<sig-prefix>...
  [+] envelope: agent_sig=<agent-sig>... nonce=<nonce>...
  [+] pre-revocation call:  ACCEPTED: {"delegation_id":...,"status":"ROUTED",...}
  [+] revocation: SUCCESS (tee:delegation/contracts::revoke)
  [35s sleep — credential window expires]
  [+] post-revocation call: REJECTED: delegate-task: credential expired (TEE contract layer v3.6.0)

[Phase 1] T3N Auth
  [+] handshake() complete
  [+] authenticate() complete
  [+] Authenticated DID: did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
  [+] TenantClient initialized

[Phase 2] Python ADN — Multi-Agent Delegation
  [+] Unique cryptographic identities: 4/4
  [+] Records processed: 30
  [+] Quality score: 1 | passed: true
  [+] Coordinator DID matches session: true

[Phase 3] TEE Contract (v3.6.0 — real computation + delegation enforcement)
  [+] Registered: tail=adn-processor version=3.6.0
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

WASM contract: REGISTERED + INVOKED (v3.6.0, 20/20 WIT functions)
```

**Real enclave computation**: 30 CSV sale records are sent into the TEE at runtime. The Rust contract computes `total`, `avg`, `min`, `max`, and `trend` inside the hardware-isolated enclave. No hardcoded result values are used for the core computation path.

**Negative live test**: Phase 3 sends an empty `records: []` payload to `process-data` and confirms the TEE rejects it with `process-data: records cannot be empty`.

> **Note on the Python feature demo**: `demo/features_demo.py` demonstrates interaction patterns using a local TEE simulation. The authoritative live proof is the TypeScript bridge run above: every WIT export is invoked against the real T3N testnet.

---

## Artifact Provenance

```
SDK:    @terminal3/t3n-sdk@3.5.2
WASM:   sha256:3b1fbb73a73f7cc8aa7bb2f65fc68c9d764a0b767a2bac53d370d1e1bdf53a99
        adn_processor.wasm v3.6.0 — with contract-layer delegation enforcement
Head:   e40e7fe
Proof:  c3a952c
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
                     │ injects real DID as coordinator identity
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
3. Build a per-call `DelegationEnvelope`.
4. Submit the envelope to `delegate-task`.
5. Accept the delegated call while the credential is valid.
6. Revoke the credential through T3N delegation infrastructure.
7. Wait for the short TTL window to expire.
8. Confirm the TEE contract rejects the expired delegated call.

The `adn-processor` v3.6.0 contract validates the credential time window and function scope inside the TEE contract.

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

The demo:
1. Authenticates with T3N testnet via `handshake()` + `authenticate()`.
2. Builds and tests an Agent Auth delegation credential.
3. Spawns Python ADN with the authenticated DID as coordinator identity.
4. Runs multi-agent delegation with 4 distinct identities.
5. Registers the Rust/WASM contract.
6. Invokes all 20 WIT exports through the live T3N bridge.
7. Runs a negative TEE validation test.

---

## Creative Features

| Phase | Feature | TEE Functions | Status |
|---|---|---|---|
| 0 | Agent Auth SDK — User Delegation | SDK-native credential lifecycle | Live on T3N testnet |
| 1 | Core ADN + Auth + TEE | process-data, validate-quality, delegate-task | Live on T3N testnet |
| 2 | Blind Multi-Agent Auction | submit-bid, resolve-auction | TEE-invoked via bridge |
| 3 | Agent Reputation Ledger | record-completion, get-reputation | TEE-invoked via bridge |
| 4 | Privacy-Preserving Personalization | send-personalized-outreach | TEE-invoked via bridge |
| 5 | Temporal Agent Delegation | issue-time-grant, check-grant | TEE-invoked via bridge |
| 6 | Cross-Tenant Verified Computation | process-data | TEE-invoked via bridge |
| 7 | Agentic KYC Pipeline | kyc-submit-step, kyc-get-status | TEE-invoked via bridge |
| 8 | TEE Secret Vault Pattern | store-secret, invoke-with-secret | TEE-invoked via bridge |
| 9 | Autonomous Agent DAO | cast-vote, tally-votes | TEE-invoked via bridge |
| 10 | Verifiable AI Decision Audit | log-decision, audit-decisions | TEE-invoked via bridge |
| 11 | Agent Performance Bond | lock-bond, verify-and-settle | TEE-invoked via bridge |

Run the local feature-pattern demo: `T3N_API_KEY=0x<key> python demo/features_demo.py`

---

## Security

33 negative security tests across 8 categories: structural tamper, replay attack,
expired proof, wrong audience, forged key, missing required fields, agent identity
distinctness, delegation policy enforcement, and credential TTL window validation.

```
python -m pytest tests/negative_security.py -v
# 33 passed
```

---

## Project Structure

```
agent-delegation-network/
├── t3n-bridge/                  # TypeScript — real T3N ADK integration
│   ├── src/
│   │   ├── t3n_auth.ts          # handshake() + authenticate() → DID
│   │   ├── agent_auth.ts        # Agent Auth credential + envelope demo
│   │   ├── contract_bridge.ts   # TEE contract registration + invocation v3.6.0
│   │   ├── map_setup.ts         # KV map creation with BUG-001 fallback
│   │   ├── adn_runner.ts        # spawns Python ADN with real DID
│   │   └── index.ts             # main entry point
│   ├── package.json             # @terminal3/t3n-sdk@3.5.2
│   └── tsconfig.json
├── contract/                    # Rust WASM TEE contract
│   ├── wit/world.wit            # WIT interface — 20 exported functions
│   ├── src/lib.rs               # all 20 functions implemented
│   └── Cargo.toml
├── src/                         # Python agent delegation network
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
│   └── negative_security.py     # 33 negative security tests
├── proof/
│   ├── live_run_v3.6.0.txt      # v3.6.0 live proof
│   └── live_run_v3.5.0.txt      # v3.5.0 baseline proof
├── data/
│   └── sales_Q1-2026_US_premium.csv
├── PHASES.md
├── SUBMISSION_REPORT.md
└── t3n_bridge_proof.txt         # live testnet output v3.6.0
```

---

## Known Boundaries

- Workers are ephemeral Ed25519 sub-agents, not independent T3N tenants.
- The Agent Auth revocation proof uses short-lived credential expiry for contract-layer rejection. Immediate revocation-registry lookup from inside `generic-input` WASM is documented as a current ADK gap.
- TEE Secret Vault is implemented as a secure-pattern demo, not a production persistent vault.
- When the SDK does not return a numeric `contractId`, tenant map ACL setup falls back to `writers/readers: "all"` as a documented BUG-001 workaround.
