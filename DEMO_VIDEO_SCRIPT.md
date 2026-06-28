# ADN Bounty — Demo Video Script v2
# Terminal 3 Agent Delegation Network
# Version: 88b7b88 (2026-06-20) — v3.8.1 C-01 proof + lifecycle assertions

---

## WHAT THIS VIDEO NEEDS TO PROVE

1. **C-01 is live** — the v3.8.1 contract hard-rejects four malformed inputs: missing sig, short nonce, no envelope, expired credential. All four are HTTP rejections from the real T3N server — the demo code exits with code 1 if any passes.
2. **The DID is live** — `did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02` fetched from T3N handshake, not hardcoded.
3. **Phase 2 Python ADN works** — 4 distinct Ed25519 identities, 30 records processed, DID injected from session.
4. **20 WIT exports invoked** — Phase 3 (2 core) + Phase 4 (18 remaining). Server-generated receipt hashes change every run.
5. **Commit binding** — show `git log --oneline -1` (should be `88b7b88`) before running.

---

## BEFORE YOU RECORD — Setup

1. **Font size 16-18** — Terminal > Settings > Appearance.
2. **Wide terminal** — drag to fill at least 2/3 of screen. Lines are long.
3. **Clear terminal** — type `cls` and press Enter before recording.
4. **Pre-type these two commands** (don't press Enter yet):
   ```
   cd "E:/LLM SHARED MEMORY PROJECT/PROJECT/Terminal 3 Agent Dev Kit Bounty Challenge (Launch Ed)/agent-delegation-network" && git log --oneline -1
   ```
   Then separately:
   ```
   cd t3n-bridge && node --loader ts-node/esm src/index.ts
   ```
5. **Close notifications** — phone on silent.

---

## SCRIPT — Shot by Shot

Total target: **4-5 minutes** (cut Phase 4 gaps and 35s sleep in editing).
Real recording time: ~10 minutes.

---

### SHOT 1 — INTRO + COMMIT BINDING (0:00 - 0:25)

**Screen:** Clean terminal.

**Narration:**
"This is a live demo of the Agent Delegation Network — my Terminal 3 ADK Bounty submission.
Before running, let me show the current commit to link this video to the source code."

**Action:** Press Enter on first command.

**Expected:**
```
88b7b88 fix: audit round-11 — agent auth lifecycle assertions, doc fixes
```

**Narration:**
"Commit 88b7b88 — verifiable on GitHub. Let's run it."

**Action:** Press Enter on second command.

---

### SHOT 2 — PHASE 1: Real T3N Auth (0:25 - 0:50)

**What appears:**
```
[Phase 1] Authenticating with Terminal 3 testnet...
  [+] handshake() complete
  [+] authenticate() complete
  [+] Authenticated DID (from session): did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
  [+] Ethereum address: 0x7caafad928560b686ac863c444efd465e19848ea
  [+] TenantClient initialized
```

**Narration:**
"Phase 1 — real T3N authentication. The DID is fetched live from the T3N handshake
API — it is not hardcoded anywhere in the source. TenantClient initialized. Every
subsequent call flows through this authenticated session."

**Pause briefly on the DID line. Move your mouse to it.**

---

### SHOT 3 — PHASE 0: Credential Lifecycle + C-01 Proof (0:50 - 2:30)

**This is the headline section.** There is a 35-second sleep inside it — narrate during the wait.

**First block appears:**
```
[Phase 0] Agent Auth SDK — delegation credential + enforcement cycle...
  [+] credential built: vc_id=<random 32-hex>
  [+] granted functions: delegate-task, process-data
  [+] signed with EIP-191: user_sig=<prefix>...
  [+] envelope: agent_sig=<prefix>... nonce=<prefix>...
  [+] pre-revocation call:  ACCEPTED: {"delegation_id":...,"status":"ROUTED",...}
  [+] revocation: SUCCESS (tee:delegation/contracts::revoke)
```

**Narration while the code sleeps 35 seconds:**
"Phase 0 — Agent Auth SDK. A DelegationCredential is built fresh this run.
See the vc_id — 16 random bytes, different from the proof file. That proves
this is an independent live run.

Signed with EIP-191, Ethereum personal-sign standard. A per-call DelegationEnvelope
is attached — agent signature over a SHA-256 request hash plus a 16-byte random nonce.

Pre-revocation call — ACCEPTED. The TEE validated the credential window and scope.
Then we revoke — SUCCESS. The T3N delegation registry marks it revoked.

The code is sleeping 35 seconds now. The credential window is 30 seconds. When
the sleep ends, the WASI clock inside the enclave will see it expired."

**Second block appears after sleep:**
```
  [-] post-revocation call: REJECTED: delegate-task: credential expired ...
```

**Narration:**
"REJECTED. The TEE contract decoded the credential JCS, compared not_after_secs to
WASI SystemTime — expired. Rejected at the contract layer. This is a hard assertion
in the code. If that line doesn't start with REJECTED, the process exits with code 1."

**Third block — negative tests:**
```
  [+] Negative envelope tests — proving v3.8.1 contract-layer hardening...
  [+]   missing agent_sig:    REJECTED: delegate-task: agent_sig missing from envelope
  [+] short nonce (4 bytes): REJECTED: delegate-task: nonce too short (< 8 bytes)
  [+]   no envelope at all:   REJECTED: delegate-task: __delegation_envelope is required
```

**Narration — slow down here, this is the C-01 proof:**
"Three more negative tests against the live v3.8.1 contract.

Missing agent_sig — REJECTED.
Short nonce, 4 bytes instead of the minimum 8 — REJECTED.
No envelope at all — REJECTED.

These are HTTP 400 responses from the real T3N server. The code exits with
status 1 if any of them passes. Four rejections, four hard assertions. C-01 live."

**PAUSE and move your mouse to highlight all four REJECTED lines.**

---

### SHOT 4 — PHASE 2: Python ADN (2:30 - 3:00)

**What appears:**
```
[Phase 2] Running Python ADN with authenticated DID...
  DID injected into coordinator: did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
  [+] Unique cryptographic identities: 4/4
  [+] Records processed: 30
  [+] Total revenue: $13253
  [+] Quality score: 1 | passed: true
  [+] Session DID injected correctly: true
```

**Narration:**
"Phase 2 — Python multi-agent delegation network. Same DID from Phase 1 injected
into the coordinator. Four agents, each with a distinct ephemeral Ed25519 key.
30 sales records processed. Quality check passes.

Session DID injected correctly: true. The T3N authenticated identity drives the
Python agent layer."

---

### SHOT 5 — PHASE 3: TEE Contract (3:00 - 3:40)

**What appears:**
```
[Phase 3] TEE Contract...
  [+] Registered: tail=adn-processor version=3.8.1
  [+] Script: z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor
  [+] TEE result: 30 records | total=$13253 | avg=$441.77 | min=$198.25 | max=$687.75 | trend=increasing
  [+] processed_in_tee: true
  [+] TEE quality: score=1 | validated_in_tee: true
  [+] TEE correctly rejected empty records: HTTP 400: Invalid params...
```

**Narration:**
"Phase 3 — Rust/WASM TEE contract, adn-processor v3.8.1. 30 sales records
into the TEE enclave. Total, average, min, max, trend computed inside the enclave.
processed_in_tee: true. validated_in_tee: true.

Negative test: empty records — TEE rejects it. Input validation enforced from
inside the enclave."

**Pause on processed_in_tee: true and validated_in_tee: true.**

---

### SHOT 6 — PHASE 4 START + CUT (3:40 - 3:50 in video)

**What appears:**
```
[Phase 4] Full Feature Contract Coverage — invoking all 20 WIT exports...
  (waiting 65s for fuel window reset, then 7s/call)
```

**Narration:**
"Phase 4 — all 20 WIT exports. Testnet fuel quota is about 8-10 calls per minute.
The code waits 65 seconds to reset the window, then spaces calls 7 seconds apart.
Cutting the wait here."

**In editing:** Cut to when `[+] delegate-task:` appears.

---

### SHOT 7 — PHASE 4: 18/18 WIT Functions (3:50 - 5:20 in video)

Narrate as groups appear:

**delegate-task:** "delegate-task. The worker DID suffix is a Unix timestamp from
this run — different number in the proof file. Independent live calls."

**submit-bid / resolve-auction:** "Blind auction. bid_hash from the enclave —
sealed_in_tee: true. Auction resolves with winner and amount."

**record-completion / get-reputation:** "Agent reputation — recorded_in_tee: true.
Score and tier computed inside the enclave."

**store-secret / invoke-with-secret:** "TEE vault. vault_id unique this run.
tee_attested: true. raw_secret_exposed: false."

**cast-vote / tally-votes:** "DAO voting. vote_receipt from the enclave.
tallied_in_tee: true. Result PASSED."

**lock-bond / verify-and-settle:** "Agent performance bond — locked 500, settled
FULL payout, EXCELLENT_DELIVERY. Settlement logic inside the enclave."

**When "All 20 WIT exports invoked" appears:**
"All 20. Every WIT export invoked against the live T3N TEE."

---

### SHOT 8 — DEMO SUMMARY (5:20 - 5:50)

**What appears:**
```
=======================================================
DEMO SUMMARY
=======================================================
Real T3N auth:             YES
DID from session:          did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02
Agent Auth credential:     BUILT + SIGNED + ENFORCED (EIP-191, SDK-native, C-01 live)
Distinct agent identities: 4/4
Multi-agent delegation:    PASSED
Tamper detection:          ACTIVE (data_hash in signed payload)
WASM contract:             REGISTERED + INVOKED (20/20 WIT functions)
=======================================================
```

**Narration:**
"Summary.

Real T3N auth — yes, same DID across all four phases.
Agent Auth credential — BUILT, SIGNED, AND ENFORCED. C-01 live means all four
negative tests rejected by the live contract, and all lifecycle assertions passed.
If any had failed, this line would say FAILED and the process would have exited 1.

4/4 identities. Delegation passed. 20/20 WIT functions.

Commit 88b7b88. Proof log at proof/live_run_v3.8.1_c01_proof.txt in the repo.
The receipt hashes in that file are different from this run — independent live calls.
That is the Agent Delegation Network."

**Pause 3 seconds on summary. Stop recording.**

---

## EDITING GUIDE

### Required cut: 65s fuel wait (Phase 4)
1. Find: `(waiting 65s for fuel window reset...)`
2. Cut right after it
3. Jump to: `[+] delegate-task: {`
4. Cut right before it
5. Delete the middle piece

### Optional: cut or shorten the 35s sleep in Phase 0
Keep it with narration (shows real timing) or cut to just before `post-revocation call` appears.

### Keep all `[+]` Phase 4 lines — they are the proof.

### Text overlays (optional)
| Moment | Overlay |
|---|---|
| DID line | "Live from T3N API" |
| pre-revocation ACCEPTED | "TEE validates credential window" |
| post-revocation REJECTED | "TTL enforced at contract layer" |
| 3x REJECTED neg tests | "C-01: mandatory envelope enforcement" |
| processed_in_tee: true | "TEE attestation field" |
| Summary ENFORCED line | "process.exit(1) if assertion fails" |

**Export: 1080p MP4**

---

## CHECKLIST BEFORE UPLOAD

- [ ] `git log --oneline -1` shows `88b7b88` at the start of the video
- [ ] `vc_id` in video is DIFFERENT from proof file (independent run confirmed)
- [ ] `pre-revocation call: ACCEPTED` visible
- [ ] `post-revocation call: REJECTED` visible
- [ ] All 3 REJECTED negative tests visible (missing sig, short nonce, no envelope)
- [ ] `Agent Auth credential: BUILT + SIGNED + ENFORCED` in summary
- [ ] `WASM contract: REGISTERED + INVOKED (20/20 WIT functions)` in summary
- [ ] All 18 `[+]` lines in Phase 4 visible (none cut out)
- [ ] 65-second fuel wait cut or briefly narrated

---

## IF THE RUN FAILS

**`AgentAuth: pre-revocation call not accepted`** — pre-revocation call rejected. Wait 60 seconds and retry.

**`AgentAuth: post-expiry call not rejected`** — post-expiry call was accepted. The 30s TTL did not expire. Edit `not_after_secs: now + 20n` in `agent_auth.ts`, rebuild, retry.

**`C-01: missing envelope was ACCEPTED`** — contract regression. Do not record. Verify contract version is 3.8.1 and rebuild WASM if needed.

**Phase 4 stops partway** — fuel exhausted. Wait 2 minutes and re-run.

**Network timeout** — T3N slow. Restart. Usually self-resolves.

Use the best clean full run. Do not submit a partial run.