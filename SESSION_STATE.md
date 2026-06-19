# ADN Session State — 2026-06-19

## Current Head
`2b0fae5` — session 7 final proof: 20/20 WIT exports clean run 2026-06-16

## Contract
`adn-processor v3.8.0` — SHA-256 credential fingerprint + hardened envelope validation

## 10/10 Checklist
- [x] CI green — workflow posts to statuses API
- [x] contractId=49 logged in map setup (BUG-001 fallback)
- [x] Negative envelope tests live: missing agent_sig REJECTED, short nonce REJECTED
- [x] Session 8 as primary proof reference (new token, 2026-06-19)
- [x] v3.6.0 secondary link removed
- [x] Docs consistent at v3.8.0
- [x] **20/20 WIT exports in Phase 4** — confirmed session 8: 2026-06-19

## Status
COMPLETE. All 20 WIT exports invoked on T3N testnet (new token verified).
Primary proof: `proof/live_run_v3.8.0_session8_newtoken.txt`.

## Proof Files
- `proof/live_run_v3.8.0_session8_newtoken.txt` — **PRIMARY** (20/20 Phase 4, 2026-06-19, new token)
- `proof/live_run_v3.8.0_session7_final.txt` — session 7 (20/20 Phase 4, 2026-06-16)
- `proof/live_run_v3.8.0_session6_final.txt` — session 6 (10/20 Phase 4, credits exhausted)
- `proof/live_run_v3.8.0_session5.txt` — session 5 (20/20 Phase 4 confirmed)

## Key Numbers
- DID: `did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02`
- ETH address (session 8, new token): `0xb5a5808b97bdef6b053bb110be63af0deec60ed9`
- contractId: 49 (known stable, BUG-001 fallback)
- Security tests: 33/33 pass
- Deadline: 2026-06-22
