# BUG-003 — `buildDelegationCredential` rejects `z:{tenant}:{tail}` as `contract` field

## Summary

`buildDelegationCredential` (and `validateCredentialBody`) throws `ContractTooLong` when
the `contract` field is set to the full `z:{40-hex}:{tail}` script_name format used by
`executeAndDecode`. The SDK uses a different (shorter) format for this field but does not
document the distinction.

## Date / Time

2026-06-09 (during Agent Auth + TEE bridge wiring)

## Environment

| Field | Value |
|---|---|
| OS | Windows 10 Pro 22H2 |
| Node version | 20.x |
| Package manager | npm |
| SDK version | `@terminal3/t3n-sdk@3.5.2` |
| Branch | main |
| Commit | 1d6eaf1 |

## Command Run

```typescript
const credential = buildDelegationCredential({
  contract: "z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor",
  // ↑ full executeAndDecode script_name format — 50+ chars
  functions: ["delegate-task"],
  ...
});
```

## Expected Result

`buildDelegationCredential` accepts the same `script_name` format used by
`executeAndDecode` without throwing.

## Actual Result

```
Error: ContractTooLong
```
Thrown by `validateCredentialBody` when `contract` length exceeds the internal limit.

## Error Summary

`ContractTooLong` — contract field must be a short service identifier (e.g., `"tee:payroll"`),
not the full `z:{tenant_hex}:{tail}` format used for `executeAndDecode`.

## Evidence

`t3n-bridge/src/agent_auth.ts` — uses `"adn-processor"` (tail only) as the contract field

## Reproduction Steps

1. Call `buildDelegationCredential` with `contract: "z:<40-char-hex>:adn-processor"`
2. Observe `ContractTooLong` error
3. Retry with `contract: "adn-processor"` — succeeds

## Impact

First-time integrators will assume the `contract` field in `buildDelegationCredential`
should match the `script_name` passed to `executeAndDecode`. This produces a cryptic
`ContractTooLong` error with no documentation explaining the expected format.

## Severity

**LOW** — Easy to work around once discovered, but error message does not guide the fix.

## Workaround

Use only the contract tail (e.g., `"adn-processor"`) as the `contract` value in
`buildDelegationCredential` — not the full `z:{tenant}:{tail}` format.

## Status

**WORKAROUND_FOUND**

## Notes for Terminal 3

1. Document the distinction between `script_name` (for `executeAndDecode`) and
   `contract` (for `buildDelegationCredential`) in the Agent Auth SDK guide.
2. Improve the `ContractTooLong` error message to include the expected format:
   `"Expected short service ID like 'tee:payroll' or 'adn-processor', not a full z:{tenant}:{tail} script_name."`
