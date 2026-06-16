# ADN Session State — 2026-06-16

## Current Head
`8f3831c` — Session 6 final proof: negative envelope tests + contractId fallback

## Contract
`adn-processor v3.8.0` — SHA-256 credential fingerprint + hardened envelope validation

## 10/10 Checklist
- [x] CI green — workflow posts to statuses API
- [x] contractId=49 logged in map setup (BUG-001 fallback)
- [x] Negative envelope tests live: missing agent_sig REJECTED, short nonce REJECTED
- [x] Session 7 as primary proof reference
- [x] v3.6.0 secondary link removed
- [x] Docs consistent at v3.8.0
- [x] **20/20 WIT exports in Phase 4** — confirmed session 7: 2026-06-16

## Status
COMPLETE. All 20 WIT exports invoked on T3N testnet. Primary proof: `proof/live_run_v3.8.0_session7_final.txt`.

## Proof Files
- `proof/live_run_v3.8.0_session7_final.txt` — **PRIMARY** (20/20 Phase 4, 2026-06-16)
- `proof/live_run_v3.8.0_session6_final.txt` — session 6 (10/20 Phase 4, credits exhausted)
- `proof/live_run_v3.8.0_session5.txt` — 20/20 Phase 4 confirmed (same contract, same DID)

## Key Numbers
- DID: `did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02`
- contractId: 49 (known stable, BUG-001 fallback)
- Security tests: 33/33 pass
- Deadline: 2026-06-22
