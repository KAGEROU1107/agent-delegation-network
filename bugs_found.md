# SDK Gaps Found During T3N ADN Integration

Bugs and documentation gaps discovered while building the Agent Delegation Network
on the Terminal 3 ADK (`@terminal3/t3n-sdk@3.5.2`).

---

## BUG-001: `tenant.contracts.register()` returns no numeric `contractId`

**Component**: `@terminal3/t3n-sdk` — `TenantContractsNamespace.register()`

**Type declaration**:
```ts
declare class TenantContractsNamespace {
  register(input: ContractPublishInput): Promise<unknown>;
}
```

**Impact**: `tenant.maps.create()` requires a numeric `contractId` in its `writers` / `readers` ACL fields:
```ts
tenant.maps.create({
  tail: "auction-bids",
  visibility: "private",
  writers: { only: [contractId] },   // ← numeric ID required
  readers: { only: [contractId] },
})
```

`register()` returns `Promise<unknown>` — no typed `id` or `contractId` field in the response. There is no documented API to retrieve the numeric contract ID after registration (no `tenant.contracts.get()` or `tenant.contracts.list()` returning an id).

**Effect on this submission**: `map_setup.ts` is implemented but cannot be wired into the live bridge. KV-map-backed features (blind auction persistence, reputation ledger, KYC state, etc.) are demonstrated via the TEE contract's in-call computation only — not via persistent map storage.

**Workaround**: None. The map/ACL layer is ready to activate once the SDK returns a contract ID.

**Bounty category**: Bug found during onboarding

---

## BUG-002: Agent Auth grant APIs not exposed at top-level

**Component**: `@terminal3/t3n-sdk` — no exported `AgentAuth`, `grantAgent`, `delegateAuthority`, or `issueGrant` functions

**What exists**: The SDK does export the full `DelegationCredential` system:
- `buildDelegationCredential()` — construct a user-to-agent credential
- `signCredential()` — EIP-191 sign it with an ETH key
- `canonicaliseCredential()` — JCS canonicalization (RFC 8785)
- `validateCredentialBody()` — body-level validation matching Rust contract
- `revokeDelegation()` — calls `tee:delegation/contracts::revoke`
- `DelegationCustodialClient` — TEE-custodial signing for OIDC users

**What is missing**: A higher-level `grantAgentAuthority()` convenience wrapper that issues a scoped grant tied to a specific tenant contract and forwards it to T3N's delegation infrastructure in one call. Developers must assemble the credential manually from primitives.

**Effect on this submission**: `agent_auth.ts` demonstrates the full delegation lifecycle using the available SDK primitives — build, sign, validate, revoke. The missing convenience wrapper means more boilerplate for integrators but the core capability is present.

**Bounty category**: Documentation gap — the ADK landing page and overview docs do not describe the `DelegationCredential` primitives, only the payroll-specific `buildPayrollInvocation` wrapper.

---

## BUG-003: `buildDelegationCredential` rejects `z:{tenant}:{tail}` as `contract` field

**Component**: `@terminal3/t3n-sdk` — `buildDelegationCredential` / `validateCredentialBody`

**Error**: `ContractTooLong` thrown by `validateCredentialBody` when `contract` is set to `z:ad146e6861ac408900af7ece1f6e90976dad3a02:adn-processor` (the `executeAndDecode` `script_name` format).

**Root cause**: The delegation credential's `contract` field is documented with example `"tee:payroll"` — a short service identifier. The `z:{40-hex}:{tail}` format used by `executeAndDecode` is too long for this field.

**Workaround**: Use just the contract tail (`"adn-processor"`) as the contract identifier in `buildDelegationCredential`.

**Bounty category**: Documentation gap — ADK docs do not clarify the distinction between `script_name` format for TEE invocation vs. `contract` format for delegation credentials.

---

## BUG-004: Testnet `fuel_per_minute` quota limits Phase 4 coverage in a single run

**Component**: T3N testnet — `fuel_per_minute` rate limit on TEE contract invocations

**Observed**: ~8-10 TEE calls succeed per 60-second window per tenant. Firing all 18 Phase 4 functions (plus 3 from Phase 3) in a single run exhausts the budget mid-run. One call (`kyc-submit-step`) received a transient `429` at the window boundary even with 7-second inter-call delays.

**Workaround**: 7-second delays between Phase 4 calls spread invocations across 2+ minutes (crossing the replenishment boundary). 17/18 Phase 4 functions succeeded; the single transient failure on `kyc-submit-step` did not affect correctness — `kyc-get-status` (the next call, same module) succeeded immediately after.

**Bounty category**: Testnet limitation found during integration.
