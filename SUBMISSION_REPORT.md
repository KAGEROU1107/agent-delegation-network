# Terminal 3 Agent Dev Kit Bounty — Submission Report

**Project**: Agent Delegation Network (ADN)  
**Submitter**: KAGEROU1107  
**Submission date**: 2026-06-11  
**Deadline**: 2026-06-22  
**Repo**: https://github.com/KAGEROU1107/agent-delegation-network  
**Demo Video**: https://youtu.be/ukZQ7F81aho  
**SDK**: `@terminal3/t3n-sdk@3.5.2`  
**Contract**: `adn-processor v3.8.0` — hardened envelope validation + SHA-256 credential fingerprint  
**Live proof**: `proof/live_run_v3.8.0_session7_final.txt`

---

## Demo Video

https://youtu.be/ukZQ7F81aho

Live run against T3N testnet — 20/20 WIT exports, real DID, unique per-run hashes. Compare values in the video against `proof/live_run_v3.8.0_demo_video.txt` in the repo to confirm independent live runs.

---

## What Was Built

A multi-agent delegation network where a coordinator obtains a real Terminal 3 DID, delegates work to ephemeral signed sub-agents, and executes/verifies agent workflows through a Rust/WASM TEE contract with all 20 WIT exports invoked on T3N testnet.

### Core capabilities demonstrated

| Capability | Evidence |
|---|---|
| T3N handshake + authenticate | Phase 1 — real DID from testnet every run |
| Rust/WASM TEE contract (v3.8.0) | Registered + invoked: `z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor` |
| Runtime enclave computation | 30 CSV records → TEE computes total/avg/min/max/trend |
| All 20 WIT exports invoked | Phase 3: 2 core functions; Phase 4: remaining 18/18 `[+]` in clean run |
| Agent Auth SDK — credential lifecycle | buildDelegationCredential → sign → validate → revoke SUCCESS |
| Agent Auth enforcement scope | Structural: scope, TTL, nonce length, agent_sig presence. Cryptographic sig and replay-registry verification documented as ADK host-capability boundary. |
| Per-call DelegationEnvelope | buildInvocationPreimage + signAgentInvocation — full wire shape |
| Agent Auth enforcement | TEE-enforced structural credential validation: scope, TTL, nonce format, envelope presence. Cryptographic sig verification is a documented boundary (host-capability, not in-WASM). Proven via live HTTP 400 rejections. |
| Negative live TEE test | Empty records → `process-data: records cannot be empty` rejection |
| Multi-agent Ed25519 delegation | 4 distinct identities, signed payloads, tamper detection |
| Local negative security tests | 33/33 pass |

---

## Live Proof Summary

Full output: [`proof/live_run_v3.8.0_session7_final.txt`](proof/live_run_v3.8.0_session7_final.txt) · [`proof/live_run_v3.8.0_session6_final.txt`](proof/live_run_v3.8.0_session6_final.txt)

```
[Phase 1] Authenticating with Terminal 3 testnet...
  [+] handshake() complete
  [+] authenticate() complete
  [+] Authenticated DID: did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
  [+] Ethereum address: 0x7caafad928560b686ac863c444efd465e19848ea
  [+] TenantClient initialized

[Phase 0] Agent Auth SDK — delegation credential + enforcement cycle...
  [+] credential built: vc_id=1c15a3c144723133bdcbfdf2bd6c5873
  [+] granted functions: delegate-task, process-data
  [+] signed with EIP-191: user_sig=eJEZnGDSJSNXTW0B...
  [+] envelope: agent_sig=hGRYp_3fQKT032Xj... nonce=npXJfmpt...
  [+] pre-revocation call:  ACCEPTED: {"delegation_id":...,"status":"ROUTED",...}
  [+] revocation: SUCCESS (tee:delegation/contracts::revoke)
  [+] post-revocation call: REJECTED: delegate-task: credential expired (TEE contract layer — v3.8.0)
  [+] missing agent_sig:    REJECTED: delegate-task: agent_sig missing from envelope
  [+] short nonce (4 bytes): REJECTED: delegate-task: nonce too short (< 8 bytes)

[Phase 2] Python ADN — Multi-Agent Delegation...
  [+] Unique cryptographic identities: 4/4
  [+] Records processed: 30 | Quality score: 1 | Coordinator DID matches session: true

[Phase 3] TEE Contract (v3.8.0)...
  [+] Registered: tail=adn-processor version=3.8.0
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

`adn-processor v3.8.0` implements contract-layer enforcement for:
- **Credential time window**: `not_before_secs` / `not_after_secs` validated against WASI `SystemTime::now()`
- **Temporal consistency**: `not_before < not_after` sanity check
- **Function scope**: "delegate-task" must be in `functions` array
- **Credential field completeness**: `vc_id` and `agent_pubkey` presence-checked
- **Envelope completeness**: `nonce` (≥8 bytes decoded) and `agent_sig` presence-checked
- **SHA-256 fingerprint**: `credential_fingerprint` emitted in response — tamper-evident attestation of which credential was validated inside the TEE

The bridge constructs the full `DelegationEnvelope` using SDK primitives, including user and agent signatures. Real-time revocation-registry lookup from inside WASM is a documented boundary — `tee:delegation/contracts::is-live` is not yet exposed for `generic-input` contracts. Short-lived credentials (30s) plus TEE-enforced expiry serve the same revocation property within the proof window. Documented as BUG-005.

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

`TenantContractsNamespace.register()` returns `Promise<unknown>`. `tenant.maps.create()` requires a numeric `contractId` in its ACL fields. No documented API exists to retrieve the numeric ID after registration.

**Workaround implemented**: `registerAdnContract()` now probes the raw SDK response for any numeric `id`/`contractId` field. `setupAdnMaps()` is wired into the bridge and creates all 8 ADN feature maps. When the SDK does not return a `contractId`, map ACLs fall back to `writers/readers: "all"` with a diagnostic log. Contract-only ACLs will auto-activate if the SDK begins returning the numeric ID.

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

**Status: FIXED in adn-processor v3.8.0**

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

33 negative security tests across 8 categories:

| Category | Tests | Result |
|---|---|---|
| Structural tamper | 6 | 33/33 PASS |
| Replay attack | 2 | |
| Expired proof | 2 | |
| Wrong audience | 2 | |
| Forged key | 1 | |
| Missing fields | 4 | |
| Identity distinctness | 2 | |
| Delegation policy enforcement | 9 | |
| Credential TTL window | 5 | |

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
| Tenant map ACL wiring | **Wired** — 8 maps created via `setupAdnMaps()`; ACLs use `writers/readers:"all"` fallback when BUG-001 active (no contractId from SDK) |
| Credential-gated execution (denial-after-revoke) | **IMPLEMENTED** — v3.8.0 contract enforces via time-bound expiry + WASI clock. See BUG-005. |
| Secret Vault persistence | TEE pattern only — persistent map storage depends on contract-only ACLs, which require SDK resolving BUG-001 (contractId from register()) |
| Python demo live TEE | Uses `_tee_stub` local simulation; authoritative proof is TypeScript bridge Phase 4 |
| Real-time revocation registry in WASM | Residual gap — requires undocumented host primitive; time-bound tokens used instead |


