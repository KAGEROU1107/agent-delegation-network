# BUG-002 — Agent Auth grant APIs not exposed at top level

## Summary

The SDK exports a complete `DelegationCredential` primitive set but no higher-level
convenience wrapper (e.g., `grantAgentAuthority()`, `grantAgent()`, `delegateAuthority()`).
The ADK landing page and overview documentation do not mention or describe the
`DelegationCredential` primitives at all, only a payroll-specific wrapper.

## Date / Time

2026-06-09 (during Agent Auth SDK integration)

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

```bash
# Searched for Agent Auth entry point
grep -r "grantAgent\|delegateAuthority\|AgentAuth\|issueGrant" node_modules/@terminal3/t3n-sdk/
```

## Expected Result

A single callable like:
```typescript
const grant = await grantAgentAuthority({
  agentPubkey, contract: "adn-processor", functions: ["delegate-task"],
  ttlSeconds: 3600,
});
```

## Actual Result

No top-level convenience wrapper exists. Developers must call:
`buildDelegationCredential()` → `validateCredentialBody()` → `canonicaliseCredential()` →
`signCredential()` → `buildInvocationPreimage()` → `signAgentInvocation()` manually,
assembling each step from SDK primitives. None of these are documented in the ADK overview.

## Error Summary

No error thrown. Discovery failure: developers reading the ADK docs have no path to
find these primitives without reading SDK source or type declarations.

## Evidence

`t3n-bridge/src/agent_auth.ts` — full manually-assembled credential lifecycle

## Reproduction Steps

1. Read the T3N ADK documentation (landing page / overview)
2. Search for "Agent Auth", "grant", "delegate", "DelegationCredential"
3. Find only payroll-specific `buildPayrollInvocation` wrapper
4. Discover `DelegationCredential` primitives only by reading SDK type declarations

## Impact

High developer friction during onboarding. New integrators will not discover the
delegation credential system without reading SDK source or type files.

## Severity

**MEDIUM** — Functionality exists; only discoverability is broken.

## Workaround

Read the TypeScript type declarations in `@terminal3/t3n-sdk`:
- `buildDelegationCredential`
- `signCredential`
- `canonicaliseCredential`
- `validateCredentialBody`
- `buildInvocationPreimage`
- `signAgentInvocation`
- `revokeDelegation`
- `DelegationCustodialClient`

## Status

**UPSTREAM**

## Notes for Terminal 3

Add an "Agent Auth" section to the ADK overview docs showing the full credential
lifecycle (build → sign → envelope → revoke). A higher-level convenience function
covering the common case (TTL-scoped grant + revoke) would significantly reduce
integration effort.
