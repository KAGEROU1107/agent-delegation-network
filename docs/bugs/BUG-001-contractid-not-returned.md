# BUG-001 — `tenant.contracts.register()` returns no numeric `contractId`

## Summary

`TenantContractsNamespace.register()` returns `Promise<unknown>`. The TypeScript type
declaration exposes no typed `id` or `contractId` field. `tenant.maps.create()` requires
a numeric `contractId` in its ACL `writers`/`readers` fields — but there is no documented
API to retrieve that numeric ID after registration.

## Date / Time

2026-06-09 (first encountered during integration of map setup)

## Environment

| Field | Value |
|---|---|
| OS | Windows 10 Pro 22H2 |
| Node version | 20.x |
| Rust version | 1.87.0 |
| Package manager | npm |
| SDK version | `@terminal3/t3n-sdk@3.5.2` |
| Branch | main |
| Commit | 1d6eaf1 |

## Command Run

```typescript
const reg = await tenant.contracts.register({
  tail: "adn-processor",
  wasm: wasmBytes,
  wit: witSource,
  version: "3.8.0",
});
console.log(reg); // → {} or opaque object with no contractId field
```

## Expected Result

`register()` should return an object with a numeric `contractId` (or `id`) field
that can be passed directly into `tenant.maps.create()` ACL configuration.

## Actual Result

Return type is `Promise<unknown>`. No numeric `contractId` field present in any
documented or observable property of the response. The SDK has no `tenant.contracts.get()`
or `tenant.contracts.list()` method that returns a numeric ID.

## Error Summary

No thrown error. Silent failure: maps are created but cannot be scoped to the
specific contract. Current bridge behavior skips map setup when no numeric
contract ID is returned.

## Evidence

`evidence/bugs/BUG-001/`

See also: `t3n-bridge/src/contract_bridge.ts` — `registerAdnContract()` function
probes the raw SDK response for any numeric `id`/`contractId` key and logs a
diagnostic when not found.

## Reproduction Steps

1. Install `@terminal3/t3n-sdk@3.5.2` (`npm install` in `t3n-bridge/`)
2. Run `T3N_API_KEY=REDACTED_API_KEY node --loader ts-node/esm src/index.ts`
3. Observe Phase 3 output: `contractId probe: none found (raw keys: ...)`
4. Observe map setup skipped because no numeric `contractId` was returned.

## Impact

Tenant KV maps cannot be scoped to the registered WASM contract via ACL.
Current bridge behavior skips all 8 ADN feature maps (`auction-bids`,
`reputation-ledger`, etc.) when the SDK does not return a numeric contract ID, preserving the intended contract-only ACL model.

## Severity

**MEDIUM** — Workaround available; demo runs. ACL correctness is affected but
functional output is not blocked.

## Workaround

`registerAdnContract()` probes all numeric fields in the raw SDK response. Map ACLs
are skipped when no `contractId` is found. Contract-only ACLs will
auto-activate once the SDK returns the numeric ID.

## Status

**WORKAROUND_FOUND**

## Notes for Terminal 3

`TenantContractsNamespace.register()` should be typed as:
```typescript
register(input: ContractPublishInput): Promise<{ contractId: number; tail: string; version: string }>;
```
Alternatively, add `tenant.contracts.list()` or `tenant.contracts.get(tail)` returning
the numeric ID for post-registration lookup.
