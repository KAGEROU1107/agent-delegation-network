# BUG-004 Evidence — Testnet `fuel_per_minute` quota limits Phase 4 coverage

## Observed behavior

From `proof/live_run_v3.8.0_session5.txt`, Phase 4 output shows 7-second inter-call
delays and a 65-second pre-phase pause. Without these delays, `kyc-submit-step` received
a transient fuel-exceeded error at the 60-second replenishment boundary.

## Workaround implemented

`t3n-bridge/src/contract_bridge.ts` — `runPhase4Coverage()`:
```typescript
await sleep(65000);  // Wait for fuel_per_minute window to reset before Phase 4
// ...
await sleep(7000);   // Inter-call delay within Phase 4
```

## Related

- `docs/bugs/BUG-004-testnet-fuel-quota.md`
- `t3n-bridge/src/contract_bridge.ts`
- `proof/live_run_v3.8.0_session5.txt` — Phase 4 output with delays
