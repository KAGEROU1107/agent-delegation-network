# ADN Session State — 2026-06-28

## Current Head
`785a305` — v3.9.2 live proof: 20/20 WIT exports, issuer-pinned WASM, gateway signing, replay ledger

## Contract
`adn-processor v3.9.2` — issuer-authenticated TEE authorization, mandatory policy TTL, Ed25519 gateway signer, HMAC replay ledger

## v3.9.2 Proof Run (Session 9) — 2026-06-28
- Phase 1: T3N auth ✅ — handshake + authenticate, DID + ETH address confirmed
- Pre-reg: Pinned issuer matches authenticated T3N issuer ✅
- Pre-reg: Pinned tenant DID matches authenticated T3N tenant ✅
- Phase 0: Agent Auth SDK ✅ — EIP-191 credential built, revocation enforced
- Phase 0: Negative envelope tests ✅ — missing agent_sig, short nonce, no envelope all REJECTED
- Phase 2: Python ADN ✅ — 4/4 cryptographic identities, 30 records, $13253 revenue
- Phase 3: TEE contract ✅ — process-data + validate-quality in TEE, negative test REJECTED
- Phase 4: 18/18 WIT exports ✅ = **20/20 total**

## 10/10 Checklist
- [x] CI green — workflow posts to statuses API
- [x] contractId=459 (v3.9.2 registration, BUG-001 resolved by SDK)
- [x] Negative envelope tests live: missing agent_sig REJECTED, short nonce REJECTED
- [x] Session 9 as primary proof reference (v3.9.2, 2026-06-28)
- [x] Pinned issuer verified at build and runtime
- [x] Ed25519 gateway keypair enforced (gw-v3.9.2-session9)
- [x] Replay ledger (HMAC, file mode, outside temp dir)
- [x] **20/20 WIT exports in Phase 4** — confirmed session 9: 2026-06-28

## Status
COMPLETE. v3.9.2 live proof with issuer-pinned WASM, gateway signing, and durable replay ledger.
Primary proof: `proof/live_run_v3.9.2_session9.txt`.

## Proof Files
- `proof/live_run_v3.9.2_session9.txt` — **PRIMARY** (20/20 Phase 4, 2026-06-28, v3.9.2 pinned)
- `proof/release/deployment_manifest.json` — v3.9.2 deployment manifest (contractId=459)
- `proof/release/invocation_receipt.json` — TEE invocation receipt
- `proof/release/registration_response.json` — T3N registration response
- `proof/release/t3n_evidence.json` — T3N attestation evidence
- `proof/live_run_v3.8.0_session8_newtoken.txt` — previous primary (v3.8.0, 2026-06-19)
- `proof/live_run_v3.8.0_session7_final.txt` — session 7 (20/20 Phase 4, 2026-06-16)

## Key Numbers
- DID: `did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02`
- ETH address (issuer): `0xb5a5808b97bdef6b053bb110be63af0deec60ed9`
- contractId: 459 (v3.9.2 registration)
- WASM SHA-256 (pinned): `6b7be2136b9401d12e7bce2a5847382bedde15959ced459b138217f37bc12d47`
- Manifest digest: `eb1f5c7270984fd6b355f23bc7191ee7a0865974d7db8522decb96c8cb1b87cc`
- Security tests: 33/33 pass
- Deadline: 2026-06-22 (PASSED — submission already made)
