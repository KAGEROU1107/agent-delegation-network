# BUG-004 — Testnet `fuel_per_minute` quota limits Phase 4 coverage in a single run

## Summary

The T3N testnet enforces a per-tenant `fuel_per_minute` rate limit (~8–10 TEE calls
per 60-second window). Firing all 18+ Phase 4 WIT exports consecutively exhausts the
budget mid-run, causing transient `429`-equivalent failures. The testnet does not
document this limit in the ADK docs or sandbox onboarding guide.

## Date / Time

2026-06-10 (during Phase 4 integration — 20 WIT function coverage run)

## Environment

| Field | Value |
|---|---|
| OS | Windows 10 Pro 22H2 |
| Node version | 20.x |
| Package manager | npm |
| SDK version | `@terminal3/t3n-sdk@3.5.2` |
| Branch | main |
| Commit | 8f3831c |

## Command Run

```bash
T3N_API_KEY=REDACTED_API_KEY node --loader ts-node/esm src/index.ts
```

## Expected Result

All 20 WIT function invocations complete in a single run without hitting rate limits.

## Actual Result

After ~8–10 rapid `executeAndDecode` calls, `kyc-submit-step` receives a transient
fuel-exceeded error. The testnet replenishes the quota at the 60-second boundary, but
a naive sequential run without delays will hit the cap mid-phase.

## Error Summary

Fuel quota exceeded during Phase 4 sequential invocation of 18 WIT functions.
One transient failure observed on `kyc-submit-step` at the replenishment boundary.

## Evidence

`evidence/bugs/BUG-004/`

See: `proof/live_run_v3.8.0_session5.txt` — Phase 4 output with 65s inter-phase
pause and 7s inter-call delay to stay within fuel budget.

## Reproduction Steps

1. Run `t3n-bridge` with Phase 4 enabled
2. Send 18+ `executeAndDecode` calls in rapid succession (no delay)
3. Observe failure around call 9–10 with a fuel/rate-limit error
4. Add 65s pause before Phase 4 and 7s delay between calls to reproduce success path

## Impact

Developers building multi-function TEE workflows will hit this limit without warning.
A clean multi-function demo requires explicit inter-call pacing logic that is not
mentioned in the ADK docs or sandbox guide.

## Severity

**MEDIUM** — Workaround is straightforward but not documented. Blocking for demos
that invoke many WIT functions in a single run.

## Workaround

Add a 65-second pause before Phase 4 (phase boundary) and 7-second delays between
each `executeAndDecode` call within Phase 4. This spreads invocations across 2+
60-second fuel windows, staying within the per-minute quota.

Implemented in `t3n-bridge/src/contract_bridge.ts`:
```typescript
await sleep(7000); // inter-call delay to stay within fuel_per_minute
```

## Status

**WORKAROUND_FOUND**

## Notes for Terminal 3

1. Document `fuel_per_minute` quota in the ADK sandbox guide with the exact limit value.
2. Include a recommended inter-call delay recommendation for multi-function workflows.
3. Consider returning a `Retry-After`-style header or error code so SDKs can auto-backoff
   rather than requiring manual delay tuning.
