# BUG-001 Evidence — `tenant.contracts.register()` returns no numeric `contractId`

## Diagnostic log from live run

The `registerAdnContract()` function in `t3n-bridge/src/contract_bridge.ts` probes
the raw SDK response for any numeric `id` or `contractId` field and emits:

```
[ADN Bridge] contractId probe: none found (raw keys: ...)
[ADN Bridge] Map ACL: writers/readers=all (BUG-001 workaround active)
```

This log line appears in every live proof run. See `proof/live_run_v3.8.0_session5.txt`
and `proof/live_run_v3.8.0_session6_final.txt`.

## Type declaration evidence

From `node_modules/@terminal3/t3n-sdk/dist/index.d.ts`:
```typescript
declare class TenantContractsNamespace {
  register(input: ContractPublishInput): Promise<unknown>;
}
```

The return type `Promise<unknown>` provides no typed `contractId` field.

## Related

- `docs/bugs/BUG-001-contractid-not-returned.md`
- `t3n-bridge/src/contract_bridge.ts` — `registerAdnContract()` and `setupAdnMaps()`
