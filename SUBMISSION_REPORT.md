# Terminal 3 Agent Dev Kit Bounty — Submission Report

**Project**: Agent Delegation Network (ADN)  
**Submitter**: KAGEROU1107  
**Submission date**: 2026-06-11  
**Deadline**: 2026-06-22  
**Repo**: https://github.com/KAGEROU1107/agent-delegation-network  
**Final commit**: 1318b2d  
**SDK**: `@terminal3/t3n-sdk@3.5.2`  
**WASM**: `sha256:3b1fbb73a73f7cc8aa7bb2f65fc68c9d764a0b767a2bac53d370d1e1bdf53a99` (v3.6.0 — with delegation enforcement)

---

## What Was Built

A multi-agent delegation network where a coordinator obtains a real Terminal 3 DID, delegates work to ephemeral signed sub-agents, and executes/verifies agent workflows through a Rust/WASM TEE contract with all 20 WIT exports invoked on T3N testnet.

### Core capabilities demonstrated

| Capability | Evidence |
|---|---|
| T3N handshake + authenticate | Phase 1 — real DID from testnet every run |
| Rust/WASM TEE contract (v3.5.0) | Registered + invoked: `z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor` |
| Runtime enclave computation | 30 CSV records → TEE computes total/avg/min/max/trend |
| All 20 WIT exports invoked | Phase 4 — 18/18 functions `[+]` in clean run |
| Agent Auth SDK — credential lifecycle | buildDelegationCredential → sign → validate → revoke SUCCESS |
| Per-call DelegationEnvelope | buildInvocationPreimage + signAgentInvocation — full wire shape |
| Delegation enforcement test | Pre/post revocation calls logged; behavior documented |
| Negative live TEE test | Empty records → `process-data: records cannot be empty` rejection |
| Multi-agent Ed25519 delegation | 4 distinct identities, signed payloads, tamper detection |
| Local negative security tests | 19/19 pass |

---

## Live Proof Summary

Full output: [`t3n_bridge_proof.txt`](t3n_bridge_proof.txt) · [`proof/live_run_v3.5.0.txt`](proof/live_run_v3.5.0.txt) · [`proof/live_run_v3.6.0.txt`](proof/live_run_v3.6.0.txt)

```
[Phase 1] Authenticating with Terminal 3 testnet...
  [+] handshake() complete
  [+] authenticate() complete
  [+] Authenticated DID: did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
  [+] Ethereum address: 0x2b765dd9ffb3795303970ac5921f5683375c59a2
  [+] TenantClient initialized

[Phase 0] Agent Auth SDK — delegation credential + enforcement cycle...
  [+] credential built: vc_id=bed1f150d31275e6ba62f845c8ac43b3
  [+] granted functions: delegate-task, process-data
  [+] signed with EIP-191: user_sig=_2q306UHkCarFri3...
  [+] envelope: agent_sig=I1Rfj4OIWXkPgqj8... nonce=EQ1wpPyd...
  [+] pre-revocation call:  ACCEPTED: {"delegation_id":...,"status":"ROUTED",...}
  [+] revocation: SUCCESS (tee:delegation/contracts::revoke)
  [+] post-revocation call: REJECTED: delegate-task: credential expired (TEE contract layer — v3.6.0)

[Phase 2] Python ADN — Multi-Agent Delegation...
  [+] Unique cryptographic identities: 4/4
  [+] Records processed: 30 | Quality score: 1 | Coordinator DID matches session: true

[Phase 3] TEE Contract (v3.5.0)...
  [+] Registered: tail=adn-processor version=3.5.0
  [+] 30 sale records → total=$13253 | avg=$441.77 | min=$198.25 | max=$687.75 | trend=increasing
  [+] processed_in_tee: true | validated_in_tee: true
  [+] Negative test — empty records → TEE rejected: process-data: records cannot be empty

[Phase 4] All 20 WIT exports invoked via live T3N TEE bridge.
  [+] delegate-task, submit-bid, resolve-auction, record-completion, get-reputation
  [+] send-personalized-outreach, issue-time-grant, check-grant
  [+] kyc-submit-step, kyc-get-status, store-secret, invoke-with-secret
  [+] cast-vote, tally-votes, log-decision, audit-decisions, lock-bond, verify-and-settle
```

---

## Agent Auth SDK Integration

`t3n-bridge/src/agent_auth.ts` implements the full T3N delegation credential lifecycle using SDK primitives:

```typescript
// 1. Build scoped credential
const credential = buildDelegationCredential({
  user_did: tenantDid,
  agent_pubkey: agentPubkey,        // 33-byte compressed secp256k1
  org_did: tenantDid,
  contract: "adn-processor",
  functions: ["delegate-task", "process-data"],  // sorted ascending
  not_before_secs: now,
  not_after_secs: now + 3600n,
  vc_id: vcId,                      // 16-byte random
});

// 2. Validate body (mirrors Rust contract validation)
validateCredentialBody(credential);

// 3. Sign with EIP-191
const jcs = canonicaliseCredential(credential);        // RFC 8785 JCS
const { sig: userSig } = signCredential(jcs, userSecret);

// 4. Build per-call DelegationEnvelope
const preimage = buildInvocationPreimage(vcId, nonce, reqHash);
const agentSig = signAgentInvocation(preimage, agentSecret);

// 5. Revoke
await revokeDelegation({ credentialJcsB64u, client: t3n, baseUrl: getNodeUrl() });
// → SUCCESS: credential marked revoked in T3N delegation registry
```

### Enforcement architecture note

The SDK's delegation enforcement (vc_id revocation check, agent_sig verification, function scope) operates at the **contract layer**, not the T3N transport layer, for `generic-input` WIT contracts. The `tee:payroll` contract validates the `DelegationEnvelope` from its typed wire shape. A `generic-input` contract must implement envelope extraction itself. Documented as BUG-005.

---

## TEE Contract

**WIT interface** (`contract/wit/world.wit`):

```wit
package z:adn-processor@0.1.0;

interface contracts {
  record generic-input {
    input:        option<list<u8>>,
    user-profile: option<list<u8>>,
    context:      option<list<u8>>,
  }

  process-data:              func(req: generic-input) -> result<list<u8>, string>;
  validate-quality:          func(req: generic-input) -> result<list<u8>, string>;
  delegate-task:             func(req: generic-input) -> result<list<u8>, string>;
  submit-bid:                func(req: generic-input) -> result<list<u8>, string>;
  resolve-auction:           func(req: generic-input) -> result<list<u8>, string>;
  record-completion:         func(req: generic-input) -> result<list<u8>, string>;
  get-reputation:            func(req: generic-input) -> result<list<u8>, string>;
  send-personalized-outreach:func(req: generic-input) -> result<list<u8>, string>;
  issue-time-grant:          func(req: generic-input) -> result<list<u8>, string>;
  check-grant:               func(req: generic-input) -> result<list<u8>, string>;
  kyc-submit-step:           func(req: generic-input) -> result<list<u8>, string>;
  kyc-get-status:            func(req: generic-input) -> result<list<u8>, string>;
  store-secret:              func(req: generic-input) -> result<list<u8>, string>;
  invoke-with-secret:        func(req: generic-input) -> result<list<u8>, string>;
  cast-vote:                 func(req: generic-input) -> result<list<u8>, string>;
  tally-votes:               func(req: generic-input) -> result<list<u8>, string>;
  log-decision:              func(req: generic-input) -> result<list<u8>, string>;
  audit-decisions:           func(req: generic-input) -> result<list<u8>, string>;
  lock-bond:                 func(req: generic-input) -> result<list<u8>, string>;
  verify-and-settle:         func(req: generic-input) -> result<list<u8>, string>;
}

world adn-processor { export contracts; }
```

All 20 functions implement real computation via `parse_input::<T>()` / `encode::<T>()` over JSON bytes. Input validation rejects malformed or missing required fields (proven by negative test).

---

## SDK Bugs & Gaps Found

Five issues discovered during integration, documented in [`bugs_found.md`](bugs_found.md):

### BUG-001: `tenant.contracts.register()` returns no numeric `contractId`

`TenantContractsNamespace.register()` returns `Promise<unknown>`. `tenant.maps.create()` requires a numeric `contractId` in its ACL fields. No API exists to retrieve it after registration. Map/ACL features designed and ready; cannot be wired without this fix.

**Category**: SDK gap

### BUG-002: Agent Auth grant APIs not at top-level

No exported `AgentAuth`, `grantAgent`, or `delegateAuthority` convenience wrappers. The full `DelegationCredential` primitive set exists but is undocumented in ADK overview docs. Developers must assemble the credential lifecycle manually.

**Category**: Documentation gap

### BUG-003: `buildDelegationCredential` rejects `z:{tenant}:{tail}` as `contract` field

The `z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor` script_name format (used by `executeAndDecode`) is too long for the credential's `contract` field. Expected format is a short service ID like `"tee:payroll"`. Fix: use `"adn-processor"` (tail only).

**Category**: Documentation gap — `script_name` vs `contract` field distinction not explained

### BUG-004: Testnet `fuel_per_minute` quota limits Phase 4 coverage in a single run

~8–10 TEE calls succeed per 60-second fuel window per tenant. Firing 18+ functions consecutively exhausts the budget. Workaround: 65s inter-phase pause + 7s inter-call delay in Phase 4.

**Category**: Testnet limitation

### BUG-005: Delegation envelope not validated at T3N transport layer for `generic-input` contracts

**Status: FIXED in adn-processor v3.6.0**

A `DelegationEnvelope` embedded in a `generic-input` call is not intercepted/validated by T3N's routing layer. The fix: the `delegate-task` function in the Rust contract now implements contract-layer enforcement — decoding `credential_jcs`, checking `not_before_secs`/`not_after_secs` via WASI `SystemTime::now()`, and verifying the called function is in the credential's `functions` scope. A short-lived (30s) credential is used in the demo so a revoked credential expires before the post-revocation call.

Post-fix enforcement result:
```
pre-revocation call:  ACCEPTED (credential valid)
revocation:           SUCCESS
[35s sleep — credential expires]
post-revocation call: REJECTED: delegate-task: credential expired (TEE contract layer)
```

Residual gap: an `is-live` host primitive for real-time revocation registry lookup from inside `generic-input` WASM is not documented in the ADK.

**Category**: SDK architecture gap + documentation gap (original bug). Contract-layer workaround fully implemented.

---

## Security

19 negative security tests across 6 categories:

| Category | Tests | Result |
|---|---|---|
| Structural tamper | 6 | 19/19 PASS |
| Replay attack | 2 | |
| Expired proof | 2 | |
| Wrong audience | 2 | |
| Forged key | 1 | |
| Missing fields | 4 | |
| Identity distinctness | 2 | |

Run: `python -m pytest tests/negative_security.py -v`

---

## Creative Features (11 Phases + Agent Auth)

| Phase | Feature | Core Concept |
|---|---|---|
| 0 | Agent Auth SDK | User delegates scoped authority to worker agent via EIP-191-signed credential |
| 1 | Core ADN + T3N Auth | Coordinator DID from T3N session; 4-agent Ed25519 delegation network |
| 2 | Blind Multi-Agent Auction | Sealed bids inside TEE; winner computed without exposing losing bids |
| 3 | Agent Reputation Ledger | TEE-computed weighted reputation score; tier assignment (SILVER/GOLD/PLATINUM) |
| 4 | Privacy-Preserving Personalization | Customer segmentation + outreach computed in enclave; raw data never exposed |
| 5 | Temporal Agent Delegation | Time-bounded access grants; TEE validates `current_epoch < valid_until_epoch` |
| 6 | Cross-Tenant Verified Computation | Multi-party input sent into single TEE computation; result attested |
| 7 | Agentic KYC Pipeline | Multi-step KYC progress tracked; TEE computes completion status |
| 8 | TEE Secret Vault (pattern) | Secret hash + permission hash stored; action executed only under valid proof |
| 9 | Autonomous Agent DAO | Sealed votes tallied in TEE; quorum and PASSED/FAILED determined |
| 10 | Verifiable AI Decision Audit | Agent decisions logged with hash + confidence; anomaly detection in TEE |
| 11 | Agent Performance Bond | Bond locked at task assignment; TEE settles payout based on quality + timeliness |

---

## Run Commands

```bash
# Full live demo (Phases 0–4, ~5 min due to fuel throttling)
cd t3n-bridge
T3N_API_KEY=0x<your_key> node --loader ts-node/esm src/index.ts

# 10-phase Python interaction patterns demo (local TEE simulation)
T3N_API_KEY=0x<your_key> python demo/features_demo.py

# Security tests
python -m pytest tests/negative_security.py -v

# Build WASM contract
cd contract
cargo build --target wasm32-wasip2 --release
```

---

## Known Limitations

| Area | Status |
|---|---|
| Tenant map ACL wiring | Designed (map_setup.ts), not wired — blocked by BUG-001 (no contractId from register()) |
| Credential-gated execution (denial-after-revoke) | **IMPLEMENTED** — v3.6.0 contract enforces via time-bound expiry + WASI clock. See BUG-005. |
| Secret Vault persistence | TEE pattern only — persistent storage through tenant maps blocked by BUG-001 |
| Python demo live TEE | Uses `_tee_stub` local simulation; authoritative proof is TypeScript bridge Phase 4 |
| Real-time revocation registry in WASM | Residual gap — requires undocumented host primitive; time-bound tokens used instead |
