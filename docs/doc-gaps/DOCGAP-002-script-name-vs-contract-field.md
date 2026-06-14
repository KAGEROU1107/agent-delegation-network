# DOCGAP-002 — `script_name` (for `executeAndDecode`) vs `contract` (for `buildDelegationCredential`) distinction not documented

## Summary

`executeAndDecode` requires a `script_name` in `z:{tenant}:{tail}` format.
`buildDelegationCredential` requires a `contract` field in a short identifier format
(e.g., `"adn-processor"` or `"tee:payroll"`). These are different formats for what
appears to be the "same" contract reference, but the distinction is not documented.

## Where Found

When wiring `agent_auth.ts` to use the same contract reference as `contract_bridge.ts`.

## Missing / Confusing Information

No documentation explains:
1. What format is expected for `contract` in `buildDelegationCredential`
2. Why `z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor` (script_name) is not
   valid in the `contract` field
3. How the credential's `contract` field maps to the TEE contract being invoked
4. Whether there is a semantic relationship between the two formats

## Expected Documentation

A table or note in the Agent Auth guide:

| Context | Format | Example |
|---|---|---|
| `executeAndDecode({ script_name })` | `z:{tenant_hex}:{tail}` | `z:ad146e...96dad3:adn-processor` |
| `buildDelegationCredential({ contract })` | short service ID | `adn-processor` or `tee:payroll` |

## Actual Documentation

Neither format is documented. The credential `contract` field constraint is only
discoverable by triggering a `ContractTooLong` error and trial-erroring shorter values.

## Impact on Developer Onboarding

**MEDIUM** — Produces a cryptic `ContractTooLong` error with no self-documenting fix.
Every developer wiring Agent Auth to a `generic-input` WASM contract will hit this.

## Suggested Fix

Document both formats in the Agent Auth guide. Improve the `ContractTooLong` error
message to include the expected format and a reference to the docs.

## Evidence

BUG-003 (`docs/bugs/BUG-003-delegation-credential-contract-too-long.md`)

## Status

**OPEN**
