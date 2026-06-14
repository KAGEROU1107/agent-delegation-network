# DOCGAP-001 — DelegationCredential primitives undocumented in ADK overview

## Summary

The T3N ADK documentation describes `buildPayrollInvocation` as the primary Agent Auth
entry point. The full `DelegationCredential` primitive suite — which is required for
building non-payroll agent authorization flows — is not mentioned or documented in the
ADK landing page, README, or any linked guide.

## Where Found

ADK documentation / `@terminal3/t3n-sdk@3.5.2` TypeScript type declarations.

## Missing / Confusing Information

The following SDK exports are undocumented in the ADK overview:

- `buildDelegationCredential(options)` — construct a user-to-agent scoped credential
- `signCredential(jcs, privateKey)` — EIP-191 sign the canonical credential bytes
- `canonicaliseCredential(credential)` — RFC 8785 JCS canonicalization
- `validateCredentialBody(credential)` — body validation (mirrors Rust contract logic)
- `buildInvocationPreimage(vcId, nonce, reqHash)` — per-call signing preimage
- `signAgentInvocation(preimage, agentKey)` — agent-side envelope signing
- `revokeDelegation(options)` — revoke a credential via T3N delegation registry
- `DelegationCustodialClient` — TEE-custodial signing for OIDC users

## Expected Documentation

An "Agent Auth" section in the ADK guide explaining:
1. When to use `buildDelegationCredential` vs `buildPayrollInvocation`
2. The full credential lifecycle (build → validate → sign → revoke)
3. The per-call envelope flow (preimage → agentSig → DelegationEnvelope)
4. What `contract` field format is expected (see also DOCGAP-002)
5. How `DelegationEnvelope` is embedded in `executeAndDecode` call input

## Actual Documentation

ADK overview only documents payroll-specific `buildPayrollInvocation`. The broader
`DelegationCredential` system is only discoverable by reading `.d.ts` type files.

## Impact on Developer Onboarding

**HIGH** — Developers building non-payroll agent authorization (the primary bounty use
case) have no documented path to the delegation credential system. They must reverse-engineer
the SDK by reading type declarations.

## Suggested Fix

Add "Agent Auth SDK — Delegation Credential Guide" to ADK docs covering:
- Full primitive list with signatures and parameter descriptions
- Example: build + sign + embed + revoke
- `DelegationEnvelope` wire format and how to pass it in `executeAndDecode` input
- Format requirements for each field (`contract`, `agent_pubkey`, `functions` sort order)

## Evidence

`t3n-bridge/src/agent_auth.ts` — reference implementation of the undocumented flow,
assembled from SDK type declarations alone.

## Status

**OPEN**
