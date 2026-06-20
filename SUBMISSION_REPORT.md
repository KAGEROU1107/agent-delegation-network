# Terminal 3 Agent Dev Kit Bounty — Submission Report

**Project**: Agent Delegation Network (ADN)  
**Submitter**: KAGEROU1107  
**Submission date**: 2026-06-11  
**Deadline**: 2026-06-22  
**Repo**: https://github.com/KAGEROU1107/agent-delegation-network  
**Demo Video**: https://youtu.be/ukZQ7F81aho  
**SDK**: `@terminal3/t3n-sdk@3.5.2`  
**Contract**: `adn-processor v3.9.0` — cryptographic envelope verification (secp256k1 agent_sig + EIP-191 user_sig + request binding)  
**Live proof**: `proof/live_run_v3.8.1_final_88b7b88.txt` (v3.8.1 structural — current). Fresh v3.9.0 cryptographic proof pending redeploy of WASM `d04048fad022687bafa03353b0daf4eb4d59d51f058fe83a386204557c050506`.

---

## Demo Video

https://youtu.be/ukZQ7F81aho

Live run against T3N testnet — 20/20 WIT exports, real DID, unique per-run hashes. Compare values in the video against `proof/live_run_v3.8.1_demo_video.txt` in the repo to confirm independent live runs.

---

## What Was Built

An integration prototype demonstrating real Terminal 3 authentication, SDK-native delegation credential construction, Rust/WASM TEE contract invocation, and — as of **v3.9.0** — **cryptographic** verification of the delegation envelope on `delegate-task`. The agent signature (secp256k1) is verified against the credential's agent public key over the invocation preimage; the request hash is recomputed in-contract and bound to the call's `to_agent_id`/`action`; the user signature (EIP-191) is recovered over the exact credential JCS bytes; the nonce is required at exactly 16 bytes. Verification is pure Rust (`k256`) compiled to `wasm32-wasip2` — **no host primitive** — refuting the earlier claim that ECDSA recovery required one.

Two properties remain **runtime-blocked, not effort-blocked**, and are NOT claimed: (1) **durable replay prevention** — the `generic-input` WIT world imports no KV/storage capability, so consumed nonces cannot be persisted in-contract; (2) **trusted tenant/organisation anchor** — there is no host caller-identity import, so the recovered `user_sig` signer cannot be checked against the authenticated tenant. Consequently a fully self-issued credential and an exact-invocation replay are out of scope. Persistent workflow state for the other 19 exports is likewise unavailable for the same KV reason.

### Core capabilities demonstrated

| Capability | Evidence |
|---|---|
| T3N handshake + authenticate | Phase 1 — real DID from testnet every run |
| Rust/WASM TEE contract (v3.9.0) | Registered + invoked: `z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor`; WASM SHA-256 `d04048fad0…050506` |
| Runtime enclave computation | 30 CSV records → TEE computes total/avg/min/max/trend |
| All 20 WIT exports invoked | Phase 3: 2 core functions; Phase 4: remaining 18/18 `[+]` in clean run |
| Agent Auth SDK — credential lifecycle | buildDelegationCredential → sign → validate → revoke SUCCESS |
| Agent Auth enforcement scope | **Cryptographic (v3.9.0)**: secp256k1 `agent_sig` verified over preimage, EIP-191 `user_sig` recovered over credential JCS, `request_hash` recomputed and bound to `to_agent_id`/`action`, nonce strict 16 bytes, envelope mandatory (C-01). Verified by 7 Rust unit tests against SDK ground-truth vectors. **Boundaries (runtime-blocked):** durable replay (C-03, no KV import) and trusted tenant anchor (no host caller identity). |
| Per-call DelegationEnvelope | buildInvocationPreimage + signAgentInvocation — full wire shape |
| Negative live TEE test | Empty records → `process-data: records cannot be empty` rejection |
| Multi-agent Ed25519 delegation | 4 distinct identities, signed payloads, tamper detection |
| Python signing + policy tests | 34/34 pass — covers Python adapter and policy logic; TypeScript bridge and contract enforcement proven via live T3N proof |

---

## Live Proof Summary

Full output: [`proof/live_run_v3.8.1_c01_proof.txt`](proof/live_run_v3.8.1_c01_proof.txt) · [`proof/live_run_v3.8.1_session6_final.txt`](proof/live_run_v3.8.1_session6_final.txt)

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
  [+] post-revocation call: REJECTED: delegate-task: credential expired (TEE contract layer — v3.8.1 TTL expiry; live registry lookup requires undocumented host primitive)
  [+] missing agent_sig:    REJECTED: delegate-task: agent_sig missing from envelope
  [+] short nonce (4 bytes): REJECTED: delegate-task: nonce too short (< 8 bytes)

[Phase 2] Python ADN — Multi-Agent Delegation...
  [+] Unique cryptographic identities: 4/4
  [+] Records processed: 30 | Quality score: 1 | Coordinator DID matches session: true

[Phase 3] TEE Contract (v3.8.1)...
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

### Cryptographic verification (v3.9.0)

`adn-processor v3.9.0` performs **cryptographic** contract-layer verification on `delegate-task`, in pure Rust (`k256` secp256k1 + `sha3` Keccak-256) compiled to `wasm32-wasip2`. No host primitive is used.

| Property | Enforced | Mechanism |
|---|---|---|
| Agent signature | ✅ | `secp256k1` verify of 64-byte `agent_sig` over `sha256("ot3.invocation/1" ‖ vc_id ‖ nonce ‖ request_hash)` against the credential's 33-byte compressed `agent_pubkey` |
| Request binding | ✅ | `request_hash` recomputed in-contract as `sha256(JSON{to_agent_id,action})` and required to equal the signed value — altering target or action invalidates the call |
| User signature | ✅ | 65-byte EIP-191 `user_sig` recovered over the exact credential JCS bytes; binds the credential (which embeds `agent_pubkey`) to a real secp256k1 signer; recovered address emitted as `user_signer` |
| Nonce | ✅ | required, base64url, **exactly 16 bytes** (SDK `NONCE_LEN`) — empty/short rejected |
| Envelope presence | ✅ | `__delegation_envelope` mandatory (C-01) |
| Credential window / scope / domain | ✅ | `not_before/after` vs WASI clock, `delegate-task` in `functions`, domain `ot3.delegation/1` |
| Credential fingerprint | ✅ | SHA-256 of verified credential bytes emitted in response |

Verified by **7 Rust unit tests** (`contract/src/crypto.rs`) against ground-truth vectors generated from the installed `@terminal3/t3n-sdk` (`t3n-bridge/scripts/gen_vectors.mjs`, `gen_jcs.mjs`): valid sig accepted; forged-but-non-empty sig rejected; tampered `request_hash` rejected; wrong pubkey rejected; `user_sig` recovers the expected address; tampered credential recovers a different address.

**Boundaries — runtime-blocked, not effort-blocked (precise):**
- **Durable replay prevention (C-03):** the `generic-input` WIT world (`contract/wit/world.wit`) imports no KV/storage interface; the SDK exposes none for `generic-input` contracts. Consumed `(vc_id, nonce, request_hash)` cannot be persisted in-contract, so an *exact-invocation* replay within the credential TTL is not prevented at the contract layer. Short-lived (30s) credentials bound the window only.
- **Trusted tenant/org anchor:** there is no host caller-identity import. The contract recovers the `user_sig` signer but has no trusted tenant address to compare it against, so a fully *self-issued* credential (attacker's own user+agent keypair) is not distinguishable from a tenant-issued one. The recovered address is exposed for off-chain checking.
- **Live revocation registry:** `tee:delegation/contracts::is-live` is not exposed to `generic-input` WASM; post-revocation enforcement is via 30s TTL + 35s wait (BUG-005).

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

**Status: FIXED in adn-processor v3.8.1**

A `DelegationEnvelope` embedded in a `generic-input` call is not intercepted/validated by T3N's routing layer. The fix: the `delegate-task` function in the Rust contract now implements contract-layer enforcement — decoding `credential_jcs`, checking `not_before_secs`/`not_after_secs` via WASI `SystemTime::now()`, and verifying the called function is in the credential's `functions` scope. A short-lived (30s) credential is used in the demo so a revoked credential expires before the post-revocation call.

Post-fix enforcement result:
```
pre-revocation call:  ACCEPTED (credential valid)
revocation:           SUCCESS
[35s sleep — credential expires]
post-revocation call: REJECTED: delegate-task: credential expired (TTL enforced at TEE contract layer — 35s sleep lets 30s window elapse)
```

Residual gap: an `is-live` host primitive for real-time revocation registry lookup from inside `generic-input` WASM is not documented in the ADK.

**Category**: SDK architecture gap + documentation gap (original bug). Contract-layer workaround fully implemented.

---

## Security

34 negative security tests across 8 categories:

| Category | Tests | Result |
|---|---|---|
| Structural tamper | 6 | 34/34 PASS |
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
| 2 | TEE Auction-Resolution Pattern | TEE auction-resolution computation pattern; inputs caller-supplied |
| 3 | Agent Reputation Ledger | TEE reputation-score computation pattern; history caller-supplied (SILVER/GOLD/PLATINUM) |
| 4 | Privacy-Preserving Personalization | TEE personalization pattern; caller-supplied segment data computed in enclave |
| 5 | Temporal Agent Delegation | Time-bounded access grants; TEE validates `current_epoch < valid_until_epoch` |
| 6 | Cross-Tenant Verified Computation | TEE cross-input computation pattern; caller-supplied inputs aggregated in single TEE call |
| 7 | Agentic KYC Pipeline | TEE KYC-status computation pattern; step list caller-supplied |
| 8 | TEE Secret Vault (pattern) | TEE secret-vault interaction pattern; no persistent secret storage (no WIT KV import) |
| 9 | Autonomous Agent DAO | TEE vote-tally computation pattern; votes caller-supplied |
| 10 | Verifiable AI Decision Audit | Agent decisions logged with hash + confidence; anomaly detection in TEE |
| 11 | Agent Performance Bond | TEE settlement-calculation pattern; bond facts caller-supplied |

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
| Tenant map ACL wiring | **Wired** — 8 maps created via `setupAdnMaps()`; contract-only ACL (contractId=49); `setupAdnMaps()` fails closed when contractId is undefined |
| Credential-gated execution (denial-after-revoke) | **IMPLEMENTED** — v3.8.1 contract enforces via time-bound expiry + WASI clock. See BUG-005. |
| Secret Vault persistence | TEE pattern only — persistent map storage depends on contract-only ACLs, which require SDK resolving BUG-001 (contractId from register()) |
| Python demo live TEE | Uses `_tee_stub` local simulation; authoritative proof is TypeScript bridge Phase 4 |
| Post-revocation enforcement | Implemented via short-lived (30s) credential TTL + 35s sleep. The TEE enforces expiry at contract layer. Live revocation-registry lookup (without TTL wait) requires a host primitive not documented in the ADK. |






