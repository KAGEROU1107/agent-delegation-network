# ADN Session State — 2026-06-11

## Current Head
`8f3831c` — Session 6 final proof: negative envelope tests + contractId fallback

## Contract
`adn-processor v3.8.0` — SHA-256 credential fingerprint + hardened envelope validation

## 10/10 Checklist
- [x] CI green — workflow posts to statuses API
- [x] contractId=49 logged in map setup (BUG-001 fallback)
- [x] Negative envelope tests live: missing agent_sig REJECTED, short nonce REJECTED
- [x] Session 6 as primary proof reference
- [x] v3.6.0 secondary link removed
- [x] Docs consistent at v3.8.0
- [ ] **20/20 WIT exports in Phase 4** — T3N credits exhausted 2026-06-11; session 5 has 20/20

## Pending Final Step
T3N testnet credits refill (~24h). Run full demo again:
```
cd t3n-bridge
T3N_API_KEY=0x96717ba47776f2812fec2307942c7fae0d71b66aa8d9ec63fce7d10e7514ee04 node --loader ts-node/esm src/index.ts
```
Save as `proof/live_run_v3.8.0_session7_final.txt`.
Update README + SUBMISSION_REPORT primary proof link. Push.

## Proof Files
- `proof/live_run_v3.8.0_session6_final.txt` — current primary (10/20 Phase 4, credits exhausted)
- `proof/live_run_v3.8.0_session5.txt` — 20/20 Phase 4 confirmed (same contract, same DID)

## Key Numbers
- DID: `did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02`
- contractId: 49 (known stable, BUG-001 fallback)
- Security tests: 33/33 pass
- Deadline: 2026-06-22
