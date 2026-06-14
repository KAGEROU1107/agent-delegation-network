# DOCGAP-004 — Sandbox token claim process and credit limits not documented in ADK

## Summary

The T3N sandbox claim page (`https://www.terminal3.io/claim-page`) provides testnet
API keys, but the ADK documentation does not specify: the credit amount issued per
claim, what each "credit" corresponds to in terms of TEE calls, the per-minute quota,
how to check the current balance, or what to do when credits are exhausted.

## Where Found

During integration of `@terminal3/t3n-sdk@3.5.2` — after credits were exhausted
during session 6 of live development (see BUG-007).

## Missing / Confusing Information

1. **Credit amount per claim** — not documented. How much do you get?
2. **Credit-to-call mapping** — how many credits per `executeAndDecode` call?
3. **`fuel_per_minute` quota** — not documented. What is the per-minute limit?
4. **Balance check API** — is there a way to query remaining credits from the SDK?
5. **Low-balance warning** — no notification when credits are running low
6. **Self-service top-up** — no documented path to get more credits without contacting T3N
7. **Hackathon credit policy** — no documentation on whether hackathon participants
   receive additional credits or a higher quota

## Expected Documentation

An "ADK Sandbox Limits" section covering:

| Topic | Expected information |
|---|---|
| Claim URL | `https://www.terminal3.io/claim-page` |
| Credits per claim | e.g., "500 credits per claim" |
| Credit definition | e.g., "1 credit = 1 TEE function invocation" |
| Per-minute quota | e.g., "10 calls per 60-second window" |
| Balance check | SDK method or REST endpoint to query balance |
| Refill process | How to request more credits / self-service top-up |
| Hackathon policy | Special quota or unlimited credits for active hackathon participants |

## Actual Documentation

The ADK quickstart links to `https://www.terminal3.io/claim-page`. No further
documentation of limits, quotas, or refill process exists.

## Impact on Developer Onboarding

**HIGH** — Without knowing limits, developers will exhaust sandbox credits during
normal development cycles and be blocked from generating live proofs near the
submission deadline. This directly blocked session 7 live proof generation.

## Suggested Fix

Add a "Sandbox Limits & Credits" page to the ADK docs. Include the claim URL,
credit amount per claim, fuel_per_minute quota, balance check method, and refill
process. Consider providing unlimited credits (or a very high quota) to active
hackathon participants to avoid submission delays.

## Evidence

BUG-007 (`docs/bugs/BUG-007-testnet-credits-exhausted.md`)

## Status

**OPEN**
