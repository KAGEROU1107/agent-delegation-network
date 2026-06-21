# Terminal 3 Agent Dev Kit Bounty — Submission Report

**Project**: Agent Delegation Network (ADN)  
**Submitter**: KAGEROU1107  
**Submission date**: 2026-06-11  
**Deadline**: 2026-06-22  
**Repo**: https://github.com/KAGEROU1107/agent-delegation-network  
**Demo Video**: https://youtu.be/ukZQ7F81aho  
**SDK**: `@terminal3/t3n-sdk@3.5.2`  
**Contract**: `adn-processor v3.9.2` — issuer-authenticated delegated execution + verified worker results + mandatory policy TTL  
**Live proof**: `proof/live_run_v3.8.1_final_88b7b88.txt` (v3.8.1 structural — current). v3.9.2 is built + unit-tested (Rust 24/24, Python 50/50) but **not yet deployed**; the last *deployed/invoked* contract is the v3.8.1 structural build in that proof. Operator must build v3.9.2 with `ADN_TRUSTED_ISSUER` (see `t3n-bridge/scripts/derive_issuer.mjs`) and run a fresh live proof.

---

## Demo Video

https://youtu.be/ukZQ7F81aho

Live run against T3N testnet — 20/20 WIT exports, real DID, unique per-run hashes. Compare values in the video against `proof/live_run_v3.8.1_demo_video.txt` in the repo to confirm independent live runs.

---

## What Was Built

An integration prototype demonstrating real Terminal 3 authentication, SDK-native delegation credential construction, Rust/WASM TEE contract invocation, and — as of **v3.9.2** — **issuer-authenticated, cryptographically verified** delegated execution on `delegate-task`. The agent signature (secp256k1) is verified against the credential's agent public key over the invocation preimage; the request hash is recomputed in-contract and bound to the call's `to_agent_id`/`action`; the user signature (EIP-191) is recovered over the exact credential JCS bytes; the nonce is required at exactly 16 bytes; and issuer policy TTL is mandatory in `1..=300`. Verification is pure Rust (`k256`) compiled to `wasm32-wasip2` — **no host primitive** — refuting the earlier claim that ECDSA recovery required one.

Authorization root (current v3.9.2 path, introduced in v3.9.1): a tenant-controlled issuer Ethereum address is pinned into the contract at build time (`ADN_TRUSTED_ISSUER`). `user_sig` is **mandatory**, recovered via EIP-191 over the credential JCS, and required to equal the pinned issuer — so a self-issued credential is rejected. The issuer-signed credential also carries an authorization policy (`adn_authorization_v1`) binding target, action, and max TTL. The pinned address is public (not secret); rotation is a new contract version. **One property remains runtime-blocked, not effort-blocked, and is NOT claimed: durable replay prevention** — this `generic-input` WIT world imports no KV/storage capability, so consumed nonces cannot be persisted *in this contract*. (This bounds the present world; it does not assert Terminal 3 offers no state-capable contract model.) An exact-invocation replay within the credential TTL is therefore not prevented at the contract layer; short (≤300s) TTLs bound the window. Persistent workflow state for the other 19 exports is unavailable for the same KV reason.

### Core capabilities demonstrated

| Capability | Evidence |
|---|---|
| T3N handshake + authenticate | Phase 1 — real DID from testnet every run |
| Rust/WASM TEE contract | **Deployed + invoked: v3.8.1 structural** (`z:ad146e6861…:adn-processor`, committed live proof). **v3.9.2 cryptographic: built + Rust 24/24 tests, not yet deployed** (unpinned WASM SHA-256 `c7dfcac7ae…0369a9`; operator builds pinned). |
| Runtime enclave computation | 30 CSV records → TEE computes total/avg/min/max/trend |
| All 20 WIT exports invoked | Phase 3: 2 core functions; Phase 4: remaining 18/18 `[+]` in clean run |
| Agent Auth SDK — credential lifecycle | buildDelegationCredential → sign → validate → revoke SUCCESS |
| Agent Auth enforcement scope | **v3.9.2**: mandatory `user_sig` recovered to a **build-time-pinned trusted issuer**; secp256k1 `agent_sig` verified over preimage; issuer-signed `adn_authorization_v1` policy binds target/action/TTL; `request_hash` recomputed and bound to `to_agent_id`/`action`; nonce strict 16 bytes; TTL <= 300s; envelope mandatory (C-01). **24/24 Rust tests** (crypto vectors, contract-level accept/reject, SDK-generated policy fixture, and pinned/unpinned production-path checks). **Boundary:** durable replay (C-03) — no KV import in this world. |
| Per-call DelegationEnvelope | buildInvocationPreimage + signAgentInvocation — full wire shape |
| Negative live TEE test | Empty records → `process-data: records cannot be empty` rejection |
| Multi-agent Ed25519 delegation | 4 distinct identities, signed payloads, tamper detection |
| Python security tests | 50/50 pass — 34 adapter/policy tests, 11 worker-result verifier tests, and 5 audit-guard tests |
| Worker-result verification (v3.9.2; H-05/06/07) | Coordinator verifies each worker result before consuming it: Ed25519 signature (`verify_action_request`, `TASK_RESULT`); signer pinned by **exact worker public key** (H-06), with `agent_id` as auxiliary check; `result_data` bound to signed `data_hash`; outer envelope nonce == body nonce (H-07); originating `delegation_id`; audience == coordinator; status `COMPLETED`; lock-guarded single-use result nonce with bounded in-memory retention. `src/result_verifier.py`. **Scope (H-09):** the single-use check is per-process (in-memory); durable duplicate-result rejection across restarts requires a persistent coordinator-side ledger. Direct matrix `tests/test_result_verifier.py` (H-08): accept + 8 fail-closed cases (other worker key, wrong delegation id, wrong audience, modified body, missing data_hash, inconsistent nonce, stale proof, second use) plus bounded retention and concurrent duplicate checks. |

---

## Live Proof Summary

Full output: [`proof/live_run_v3.8.1_c01_proof.txt`](proof/live_run_v3.8.1_c01_proof.txt) · [`proof/live_run_v3.8.1_final_88b7b88.txt`](proof/live_run_v3.8.1_final_88b7b88.txt)

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
  [+] Records processed: 30 | Quality score: 1 | T3N DID injected as session context: true

[Phase 3] TEE Contract (v3.8.1)...
  [+] Registered: tail=adn-processor version=3.8.1
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

### Cryptographic verification + issuer authorization (v3.9.2)

`adn-processor v3.9.2` performs **issuer-authenticated cryptographic** contract-layer verification on `delegate-task`, in pure Rust (`k256` secp256k1 + `sha3` Keccak-256) compiled to `wasm32-wasip2`. No host primitive is used. Verification logic is a pure, host-testable function (`verify_delegate_task`).

| Property | Enforced | Mechanism |
|---|---|---|
| Agent signature | ✅ | `secp256k1` verify of 64-byte `agent_sig` over `sha256("ot3.invocation/1" ‖ vc_id ‖ nonce ‖ request_hash)` against the credential's 33-byte compressed `agent_pubkey` |
| Request binding | ✅ | `request_hash` recomputed in-contract as `sha256(JSON{to_agent_id,action})` and required to equal the signed value — altering target or action invalidates the call |
| User signature (issuer auth) | ✅ | 65-byte EIP-191 `user_sig` is **mandatory**, recovered over the exact credential JCS, and **required to equal the build-time-pinned tenant issuer** (`ADN_TRUSTED_ISSUER`). A self-issued credential is rejected. |
| Authorization policy | ✅ | issuer-signed `adn_authorization_v1` in credential metadata binds `to_agent_id`, allowed `actions`, and `max_ttl_secs`; mismatched target/action rejected |
| Credential TTL cap | ✅ | global: `not_after - not_before ≤ 300s`; `not_before ≤ now + 120s` skew |
| Policy TTL (mandatory) | ✅ | `adn_authorization_v1.max_ttl_secs` must be in `1..=300`; zero/missing/over-cap rejected; credential TTL must be ≤ policy TTL |
| Tenant pin (optional) | ✅ | when `ADN_TENANT_DID` set, credential `org_did`/`user_did` must match |
| Nonce | ✅ | required, base64url, **exactly 16 bytes** (SDK `NONCE_LEN`) — empty/short rejected |
| Envelope presence | ✅ | `__delegation_envelope` mandatory (C-01) |
| Credential window / scope / domain | ✅ | `not_before/after` vs WASI clock, `delegate-task` in `functions`, domain `ot3.delegation/1` |
| Credential fingerprint | ✅ | SHA-256 of verified credential bytes emitted in response |

Verified by **22 Rust tests** — 7 crypto-vector tests (vs SDK ground truth from `gen_vectors.mjs`/`gen_jcs.mjs`); 14 contract-level `verify_delegate_task` tests (valid-trusted-issuer accepted; rejected — missing/empty `user_sig`, untrusted issuer, issuer-not-pinned, wrong contract, wrong tenant DID, wrong signed target, wrong signed action, modified request field, TTL over max, zero policy TTL, forged `agent_sig`, missing envelope); and 1 end-to-end test that runs a **real @terminal3/t3n-sdk-generated** credential (policy in JCS metadata + pinned-issuer `user_sig`, `gen_policy_fixture.mjs`) through `verify_delegate_task`, proving the bridge-to-contract wire format round-trips.

**Resolved in the v3.9.x path:** the trusted-issuer anchor (previously mislabelled "runtime-blocked") is implemented by pinning the tenant issuer address at build time — no host caller-identity import is required. A self-issued credential is now rejected.

**Boundary that remains (genuinely runtime-blocked):**
- **Durable replay prevention (C-03):** the `generic-input` WIT world (`contract/wit/world.wit`) imports no KV/storage interface, so consumed `(vc_id, nonce, request_hash)` cannot be persisted *in this contract*. This bounds the present world; it is not a claim that Terminal 3 offers no state-capable contract model. An exact-invocation replay within the (≤300s) TTL is therefore not prevented at the contract layer. A durable fix needs either a state-capable contract world or a gateway that is the sole path to the TEE.
- **Live revocation registry:** `is-live` lookup is not exposed to `generic-input` WASM; post-revocation enforcement is via TTL + wait (BUG-005).

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

**Workaround implemented**: `registerAdnContract()` now probes the raw SDK response for any numeric `id`/`contractId` field. `setupAdnMaps()` is wired into the bridge and creates ADN feature maps only when the current registration returns a numeric contract ID. When the SDK does not return a `contractId`, map setup is skipped; no historical ID or open ACL fallback is used.

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

50 Python security tests across 11 categories:

| Category | Tests | Result |
|---|---|---|
| Structural tamper | 6 | PASS |
| Replay attack | 2 | |
| Expired proof | 2 | |
| Wrong audience | 2 | |
| Forged key | 1 | |
| Missing fields | 4 | |
| Identity distinctness | 2 | |
| Delegation policy enforcement | 9 | |
| Credential TTL window | 5 | |
| Worker-result verifier matrix | 9 | |
| Result nonce retention and concurrency | 2 | |
| Audit guardrails | 5 | |

Run: `python -m pytest tests/negative_security.py tests/test_result_verifier.py tests/test_audit_guards.py -v --tb=short`

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
# Pinned v3.9.2 live deployment/invocation path (Phases 0–4, ~5 min due to fuel throttling)
cd t3n-bridge
T3N_API_KEY=0x<your_key> node scripts/derive_issuer.mjs

cd ../contract
ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo test --locked
ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo build --locked --target wasm32-wasip2 --release

cd ../t3n-bridge
T3N_API_KEY=0x<your_key> ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> node --loader ts-node/esm src/index.ts 2>&1 | tee ../proof/live_run_v3.9.2.txt

# 10-phase Python interaction patterns demo (local TEE simulation)
T3N_API_KEY=0x<your_key> python demo/features_demo.py

# Security tests
python -m pytest tests/negative_security.py tests/test_result_verifier.py tests/test_audit_guards.py -v --tb=short

# Default fail-closed WASM contract build
cd contract
cargo build --locked --target wasm32-wasip2 --release
```

---

## Known Limitations

| Area | Status |
|---|---|
| Tenant map ACL wiring | **Guarded** — `setupAdnMaps()` uses contract-only ACLs only when the current registration returns a numeric `contractId`; otherwise map setup is skipped |
| Credential-gated execution (denial-after-revoke) | **IMPLEMENTED** — v3.8.1 contract enforces via time-bound expiry + WASI clock. See BUG-005. |
| Secret Vault persistence | Not implemented — current contract has no storage import; durable storage requires a storage-capable contract world and a resolved current contract ID |
| Python demo live TEE | Uses `_tee_stub` local simulation; authoritative proof is TypeScript bridge Phase 4 |
| Post-revocation enforcement | Implemented via short-lived (30s) credential TTL + 35s sleep. The TEE enforces expiry at contract layer. Live revocation-registry lookup (without TTL wait) requires a host primitive not documented in the ADK. |
