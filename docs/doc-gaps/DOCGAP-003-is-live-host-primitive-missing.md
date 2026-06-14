# DOCGAP-003 — `tee:delegation/contracts::is-live` host primitive not exposed for `generic-input` contracts

## Summary

Real-time revocation registry lookup from inside a `generic-input` WASM contract requires
a host call primitive (`tee:delegation/contracts::is-live` or equivalent). This primitive
is not documented in the ADK for `generic-input` contracts, and it is unclear whether it
is available at all. Without it, WASM contracts cannot perform synchronous revocation
checks against the T3N delegation registry.

## Where Found

During BUG-005 investigation: implementing contract-layer delegation enforcement in
`contract/src/lib.rs` for `adn-processor v3.6.0`.

## Missing / Confusing Information

1. No documentation of available WASI host call primitives for `generic-input` WIT contracts
2. No documentation of whether T3N delegation infrastructure is accessible from inside
   the TEE enclave for `generic-input` contracts
3. `tee:delegation/contracts::revoke` is callable from the SDK (outside the enclave),
   but it is unclear if a contract inside the enclave can call `::is-live` or similar

## Expected Documentation

A "Host Primitives for generic-input Contracts" section in the ADK covering:
- Which WASI host calls are available from inside a `generic-input` WASM contract
- Whether `tee:delegation/contracts::is-live` (or equivalent) is accessible
- How to perform revocation registry lookup from inside the enclave
- Reference implementation or WIT import for host-side delegation calls

## Actual Documentation

None. The WIT format (`world.wit`) is documented. WASI system calls are used freely
(`SystemTime::now()`, `println!`). But no host-side T3N-specific primitives are
documented for `generic-input` contracts.

## Impact on Developer Onboarding

**HIGH** — Any `generic-input` WASM contract implementing delegation enforcement
must use time-bound credentials as a workaround for real-time revocation checking.
This is an architectural gap: revocation is a core Agent Auth capability, but it
cannot be verified synchronously inside the TEE without this primitive.

## Suggested Fix

1. Document available host call primitives for `generic-input` WASM contracts.
2. If `tee:delegation/contracts::is-live` exists, document its WIT import and usage.
3. If it does not exist, document this as a known limitation and the recommended
   workaround (short-lived credentials with TEE-enforced expiry).
4. Add a reference implementation of host-primitive-based revocation checking to
   the ADK example contracts.

## Evidence

`contract/src/lib.rs` — `fn delegate_task()` uses WASI `SystemTime::now()` for
time-bound enforcement as a workaround for missing revocation registry access.

BUG-005 (`docs/bugs/BUG-005-envelope-not-validated-at-transport.md`) — root cause.

## Status

**OPEN**
