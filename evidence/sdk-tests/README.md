# SDK Test Evidence

## Automated Tests

**33 negative security tests** — `tests/negative_security.py`

Run: `python -m pytest tests/negative_security.py -v`

```
======================== 33 passed in 0.20s ========================
```

Coverage:

| Category | Tests |
|---|---|
| Structural tamper (hash mismatch, field mutation) | 6 |
| Replay attack (duplicate nonce) | 2 |
| Expired proof (past timestamp) | 2 |
| Wrong audience (DID mismatch) | 2 |
| Forged key (key substitution) | 1 |
| Missing required fields | 4 |
| Agent identity distinctness | 2 |
| Delegation policy enforcement | 9 |
| Credential TTL window validation | 5 |

## Live SDK Integration Tests

Live proof files in `proof/`:

| File | Content |
|---|---|
| `proof/live_run_v3.8.0_session6_final.txt` | Phase 0 (Agent Auth) + Phase 1 + Phase 3 (TEE contract) + Phase 4 (20 WIT exports) |
| `proof/live_run_v3.8.0_session5.txt` | Phase 0–4 with 20/20 WIT exports, all Phase 4 maps |
| `proof/live_run_v3.6.0_session5.txt` | v3.6.0 baseline — BUG-005 fix confirmed |
| `proof/live_run_v3.5.0.txt` | v3.5.0 baseline — pre-fix BUG-005 behavior |
| `proof/live_run_v3.6.0.txt` | v3.6.0 intermediate proof |

## Bugs Found During SDK Testing

| Bug | Title | Status |
|---|---|---|
| BUG-001 | `tenant.contracts.register()` returns no numeric contractId | WORKAROUND_FOUND |
| BUG-002 | Agent Auth grant APIs not at top level | UPSTREAM |
| BUG-003 | `buildDelegationCredential` rejects `z:{tenant}:{tail}` as contract field | WORKAROUND_FOUND |
| BUG-004 | Testnet `fuel_per_minute` quota limits Phase 4 coverage | WORKAROUND_FOUND |
| BUG-005 | Delegation envelope not validated at transport layer for generic-input contracts | FIXED (v3.6.0) |
| BUG-006 | CI Post commit status step caused red X | FIXED (0c7b10b) |
| BUG-007 | Testnet credits exhausted during development | OPEN |

## Documentation Gaps Found

| Gap | Title | Status |
|---|---|---|
| DOCGAP-001 | DelegationCredential primitives undocumented in ADK overview | OPEN |
| DOCGAP-002 | script_name vs contract field distinction not documented | OPEN |
| DOCGAP-003 | tee:delegation/contracts::is-live host primitive missing | OPEN |
| DOCGAP-004 | Sandbox token claim and credit limits not documented | OPEN |
