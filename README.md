# Agent Delegation Network
**Terminal 3 Agent Dev Kit Bounty Challenge Submission**

A multi-agent delegation system built on the Terminal 3 ADK. Agents authenticate with T3N, delegate tasks with Ed25519-signed payloads, and execute workloads inside a hardware-secured TEE contract.

---

## Live Proof

All three phases run against the real T3N testnet:

```
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

[Phase 3] TEE Contract (v3.4.0 — real computation)
  [+] Registered: tail=adn-processor version=3.4.0
  [+] Sending 30 sale records into TEE enclave for computation
  [+] TEE result: 30 records | total=$13253 | avg=$441.77 | min=$198.25 | max=$687.75 | trend=increasing
  [+] processed_in_tee: true
  [+] validate-quality → score=1 | validated_in_tee: true

WASM contract: REGISTERED + INVOKED (v3.4.0)
```

Full output: [`t3n_bridge_proof.txt`](t3n_bridge_proof.txt) · [`proof/live_run_2026-06-11.txt`](proof/live_run_2026-06-11.txt)

**Real enclave computation**: 30 CSV sale records are sent into the TEE at runtime. The Rust contract computes `total`, `avg`, `min`, `max`, and `trend` inside the hardware-isolated enclave — no hardcoded values.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  t3n-bridge/  (TypeScript — real Terminal 3 ADK)        │
│                                                         │
│  T3nClient.handshake()   → encrypted channel to T3N     │
│  T3nClient.authenticate()→ real DID from testnet        │
│  TenantClient            → contract + map management    │
│  tenant.contracts.register(wasm) → TEE deployment       │
│  t3n.executeAndDecode()  → live TEE invocation          │
└────────────────────┬────────────────────────────────────┘
                     │ injects real DID as coordinator identity
┌────────────────────▼────────────────────────────────────┐
│  src/  (Python — Agent Delegation Network)              │
│                                                         │
│  Coordinator: T3N-authenticated DID (from session)      │
│  Workers:     ephemeral Ed25519 keys (per-session)      │
│  Protocol:    signed delegation requests + data_hash    │
│  Policy:      role-based authorization engine           │
└────────────────────┬────────────────────────────────────┘
                     │ outputs flow into TEE contract
┌────────────────────▼────────────────────────────────────┐
│  contract/  (Rust WASM — runs inside T3N TEE)           │
│                                                         │
│  WIT interface: z:adn-processor@0.1.0                   │
│  process-data: verifiable aggregation in enclave        │
│  validate-quality: tamper-proof quality scoring         │
│  delegate-task: TEE-enforced routing                    │
└─────────────────────────────────────────────────────────┘
```

---

## Stack

| Layer | Technology | T3N Integration |
|---|---|---|
| Auth | `@terminal3/t3n-sdk` | `handshake()` + `authenticate()` → real DID |
| Tenant | `TenantClient` | `tenant.claim()`, contract registration |
| TEE Contract | Rust + `wasm32-wasip2` | Registered + invoked on T3N testnet |
| WIT Interface | `z:adn-processor@0.1.0` | `contracts` interface, `generic-input` record |
| Delegation | Python Ed25519 | Coordinator: T3N DID · Workers: ephemeral keys |

---

## Agent Identity Model

The **coordinator** is authenticated via the T3N ADK — its DID comes directly from `t3n.authenticate()` against the testnet. No hardcoding, no env-var injection.

**Workers and validators** use ephemeral Ed25519 keys generated per session. This is intentional: sub-agents in a delegation network are short-lived. Their outputs flow into the TEE contract, which is bound to the coordinator's authenticated T3N identity.

Each agent has a **distinct cryptographic identity** — no key sharing. Every delegation request is signed and carries a `data_hash` over the payload, making post-signing mutation detectable.

---

## TEE Contract

The Rust WASM contract follows the official T3N WIT format:

```wit
package z:adn-processor@0.1.0;

interface contracts {
  record generic-input {
    input:        option<list<u8>>,
    user-profile: option<list<u8>>,
    context:      option<list<u8>>,
  }

  process-data:     func(req: generic-input) -> result<list<u8>, string>;
  validate-quality: func(req: generic-input) -> result<list<u8>, string>;
  delegate-task:    func(req: generic-input) -> result<list<u8>, string>;
}

world adn-processor {
  export contracts;
}
```

Build: `cd contract && cargo build --target wasm32-wasip2 --release`

---

## Quickstart

**Prerequisites**: Node.js 18+, Python 3.10+, Rust + `wasm32-wasip2` target

```bash
# Install TS dependencies
cd t3n-bridge && npm install

# Run full demo (Phases 1 + 2 + 3)
T3N_API_KEY=0x<your_key> node --loader ts-node/esm src/index.ts
```

The demo:
1. Authenticates with T3N testnet via `handshake()` + `authenticate()`
2. Spawns Python ADN with the authenticated DID as coordinator identity
3. Runs multi-agent delegation (4 agents, Ed25519 signing, tamper detection)
4. Registers the Rust WASM contract and invokes `process-data` + `validate-quality` in TEE

---

## Project Structure

```
agent-delegation-network/
├── t3n-bridge/                  # TypeScript — real T3N ADK integration
│   ├── src/
│   │   ├── t3n_auth.ts          # handshake() + authenticate() → DID
│   │   ├── contract_bridge.ts   # TEE contract registration + invocation
│   │   ├── adn_runner.ts        # spawns Python ADN with real DID
│   │   └── index.ts             # main entry point
│   ├── package.json             # @terminal3/t3n-sdk@3.5.2
│   └── tsconfig.json
├── contract/                    # Rust WASM TEE contract
│   ├── wit/world.wit            # WIT interface (z:adn-processor@0.1.0)
│   ├── src/lib.rs               # process-data, validate-quality, delegate-task
│   └── Cargo.toml
├── src/                         # Python agent delegation network
│   ├── agent_identity.py        # Ed25519 identity per agent
│   ├── delegation_protocol.py   # signed request/response protocol
│   ├── delegation_policy.py     # role-based authorization
│   └── agent_delegation_network.py
├── demo/
│   └── adn_demo.py              # multi-agent workflow
├── data/
│   └── sales_Q1-2026_US_premium.csv
└── t3n_bridge_proof.txt         # live testnet output
```
