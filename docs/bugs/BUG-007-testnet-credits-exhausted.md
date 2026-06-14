# BUG-007 — Testnet account credits exhausted mid-development (`available=0`)

## Summary

The T3N testnet account ran out of credits (`available=0`) after session 6 live runs,
halting all further live T3N execution. The credit exhaustion happened during active
development and was not preceded by a warning, notification, or low-balance indicator.
No self-service credit top-up mechanism is documented.

## Date / Time

2026-06-11 (credits confirmed exhausted after session 6 run)

## Environment

| Field | Value |
|---|---|
| OS | Windows 10 Pro 22H2 |
| Node version | 20.x |
| Package manager | npm |
| SDK version | `@terminal3/t3n-sdk@3.5.2` |
| DID | `did:t3n:REDACTED_DID` |
| Branch | main |
| Commit | `8f3831c` |

## Command Run

```bash
T3N_API_KEY=REDACTED_API_KEY node --loader ts-node/esm src/index.ts
# After session 6 run
```

## Expected Result

Sandbox testnet credits are sufficient to run multiple development sessions without
mid-development exhaustion. When credits are low, the platform should warn the developer.

## Actual Result

After ~6 full live runs and development sessions, credits reached `available=0`.
Subsequent runs attempt T3N auth and may succeed for handshake/authenticate, but
TEE contract invocations are blocked. No in-run warning preceded the exhaustion.

## Error Summary

Credit balance: `available=0`. All TEE `executeAndDecode` calls blocked. No notification
or low-balance warning was delivered before exhaustion.

## Evidence

`evidence/bugs/BUG-007/`

Credit status endpoint confirmed `available=0` after session 6.

## Reproduction Steps

1. Obtain testnet API key from `https://www.terminal3.io/claim-page`
2. Run 5–6 full demo sessions (each invokes 20–25 TEE calls)
3. Observe credit balance approaching zero (no warning issued)
4. After exhaustion, `executeAndDecode` calls fail silently or with a non-obvious error

## Impact

Blocks all live proof generation and prevents running session 7 (final submission proof).
Requires manual credit request to T3N team — no self-service path documented.
Submission deadline pressure: credits exhausted with 11 days remaining before June 22.

## Severity

**HIGH** — Blocks live testing and final proof generation during active development.

## Workaround

Contact T3N team at `devrel@terminal3.io` or through DoraHacks to request credit
refill. No self-service top-up mechanism available through the sandbox portal
(`https://www.terminal3.io/claim-page`).

## Status

**OPEN** (pending credit refill from T3N team)

## Notes for Terminal 3

1. Document the credit balance for sandbox accounts (how much per claim).
2. Add a low-balance warning at the testnet level (e.g., warn at 20% remaining).
3. Consider providing a self-service credit top-up mechanism or increased sandbox
   allocation for active hackathon participants.
4. `authenticate()` returns account info — consider exposing `credits.available` in
   the authenticate response so developers can check balance before running long sequences.
