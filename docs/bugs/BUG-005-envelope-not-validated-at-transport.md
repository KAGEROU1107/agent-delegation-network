# BUG-005 — Delegation envelope not validated at T3N transport layer for `generic-input` contracts

## Summary

A `DelegationEnvelope` embedded in a `generic-input` call input is NOT intercepted or
validated by T3N's transport/routing layer. Before `adn-processor v3.6.0`, both
pre-revocation and post-revocation calls returned identical `ACCEPTED` responses —
the revocation had no observable effect on access. The fix was implemented at the
contract layer rather than the SDK/transport layer.

## Date / Time

2026-06-09 (first observed); 2026-06-10 (contract-layer fix committed as v3.6.0)

## Environment

| Field | Value |
|---|---|
| OS | Windows 10 Pro 22H2 |
| Node version | 20.x |
| Rust version | 1.87.0 |
| Package manager | npm |
| SDK version | `@terminal3/t3n-sdk@3.5.2` |
| Contract version | `adn-processor v3.5.0` (original) → fixed in v3.6.0 |
| Branch | main |
| Commit | 1d6eaf1 (fix committed here) |

## Command Run

```bash
# Before fix — using adn-processor v3.5.0
T3N_API_KEY=REDACTED_API_KEY node --loader ts-node/esm src/index.ts
# Both pre- and post-revocation calls returned ACCEPTED
```

## Expected Result

After `revokeDelegation()` succeeds, subsequent calls using the revoked credential
should be rejected by T3N's transport or routing layer.

## Actual Result

Both pre-revocation and post-revocation calls returned `ACCEPTED`. The revocation
call succeeded (T3N delegation registry confirmed) but the transport layer did not
enforce it for `generic-input` WIT contracts.

## Error Summary

Silent enforcement failure: `executeAndDecode` with a revoked credential in
`DelegationEnvelope` returned the same `ACCEPTED` response as a valid credential.
No error thrown. Revocation had no observable effect until contract-layer enforcement
was added.

## Evidence

`evidence/bugs/BUG-005/`

Pre-fix proof: `proof/live_run_v3.5.0.txt`
Post-fix proof: `proof/live_run_v3.8.0_session6_final.txt` (Phase 0)

## Reproduction Steps

1. Build `adn-processor` v3.5.0 (prior to contract-layer enforcement in `lib.rs`)
2. Run the bridge and observe Phase 0 (Agent Auth cycle)
3. Send pre-revocation call → ACCEPTED (expected)
4. Call `revokeDelegation()` → SUCCESS
5. Send post-revocation call with same envelope → ACCEPTED (unexpected — should be REJECTED)

## Impact

**HIGH** — Without contract-layer enforcement, delegation revocation has no effect
on `generic-input` WASM contracts. Any contract relying on T3N transport-layer
revocation checking for `generic-input` WIT functions is exposed.

## Severity

**HIGH** (original) → **FIXED** in `adn-processor v3.6.0`

## Workaround

Implement contract-layer enforcement inside the WASM `delegate-task` function:

1. Decode `credential_jcs` from the embedded `__delegation_envelope` JSON
2. Parse `DelegationCredential` fields (`v`, `functions`, `not_before_secs`, `not_after_secs`)
3. Read current time via WASI `SystemTime::now()` inside the TEE
4. Reject if `now > not_after_secs` (credential expired)
5. Reject if `now < not_before_secs` (credential not yet valid)
6. Reject if `"delegate-task"` not in `functions`

Short-lived credentials (30s TTL) mean a revoked credential expires before a realistic
post-revocation replay, producing the same security property as real-time revocation
registry lookup.

Implemented in `contract/src/lib.rs` — `fn delegate_task()`.

## Status

**FIXED** (in `adn-processor v3.6.0`, commit 1d6eaf1)

## Residual Gap

Real-time revocation registry lookup from inside WASM requires a host call primitive
(`tee:delegation/contracts::is-live`) that is not documented in the ADK for
`generic-input` contracts. See DOCGAP-003.

## Notes for Terminal 3

1. Document whether `generic-input` WIT contracts receive automatic transport-layer
   `DelegationEnvelope` enforcement, or whether contract-layer enforcement is required.
2. If transport-layer enforcement is not available for `generic-input` contracts,
   document this as a known limitation and provide a reference implementation of
   contract-layer enforcement (similar to `adn-processor v3.6.0`).
3. Expose `tee:delegation/contracts::is-live` as a host primitive for `generic-input`
   contracts to enable real-time revocation registry lookup from inside WASM.
