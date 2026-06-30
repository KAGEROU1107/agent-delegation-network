# ADN Security Posture — v3.9.2

**Updated:** Phase 8 complete (remediation Phases 0–8)
**Date:** 2026-06-30

## What Is Verified

| Control | Verification Method | Status |
|---|---|---|
| WIT cfg-gating | `export!(Component)` only under `#[cfg(target_arch = "wasm32")]`; native build excludes WASM exports | VERIFIED |
| Worker key isolation | `adn/worker_executor.py` owns keys; bridge receives only public identity via IPC socket | VERIFIED (Phase 4) |
| Gateway key isolation | Bridge calls `connectToExistingExecutor()` only in live mode; raw `ADN_GATEWAY_PRIVATE_KEY_HEX` never read by bridge | VERIFIED (Phase 5) |
| Legacy live-path block | `audit_legacy_imports.mjs` confirms no forbidden legacy symbols in live-path source; live-mode guards enforced at runtime | VERIFIED (Phase 6) |
| Release manifest validity | `validate_manifest.py proof/release` exits 0 against `adn-release-proof-v1` schema; all file digests recomputed and correct | VERIFIED (Phase 7) |
| T3N registration | Contract ID 459 registered on T3N testnet; `registered_at: 2026-06-28T10:10:36Z` | VERIFIED |
| T3N invocation | `credential_enforced: true`; delegation ID `tee-del-2c970ed3f7ff0514a6069aad8ed96b05`; fresh per remediation run | VERIFIED |
| Python test suite | 113 tests pass (`pytest tests/ -q`) covering signing adapter, policy, result verifier, replay guard, bridge hardening, audit guards | VERIFIED |
| TypeScript test suite | All tests pass (`npm test` in `t3n-bridge/`) | VERIFIED |
| Legacy audit | `node scripts/audit_legacy_imports.mjs` exits 0 | VERIFIED |

## What Is NOT Cryptographically Complete

| Item | Gap | Required To Close |
|---|---|---|
| `deployment_manifest.sig` | Operator private key signing ceremony not performed; `operator_public_key` is a placeholder in the manifest | Operator runs `sign_manifest.py` with a real Ed25519 key pair; signs `deployment_manifest.json` digest |
| `ci_release_sha.json` | No GitHub Actions CI run has produced a pinned workflow SHA for this HEAD | GitHub Actions CI run completes on HEAD; `ci_release_sha.json` written with workflow run ID and SHA |
| T3N platform attestation | `T3nAttestedEvidenceVerifier` accepts any non-empty `platformMaterial`; no real signature from a T3N trust anchor is checked | T3N publishes a trust anchor and the verifier is updated to check it; or a T3N-signed platform material blob is provided |

## v3.8.1 Historical Live Proof

The v3.8.1 proof (`proof/live_run_v3.8.1_final_88b7b88.txt`, `proof/live_run_v3.8.1_c01_proof.txt`) is the authoritative live-attested run. Do not modify these files.

## v3.9.2 Proof Bundle Status

The v3.9.2 proof bundle (`proof/release/`) is:
- Structurally complete and self-validating (manifest schema valid, all digests correct)
- Backed by a real T3N testnet registration (contract ID 459) and invocation (`credential_enforced: true`)
- Not yet backed by an operator-signed manifest (`deployment_manifest.sig` missing)
- Not yet backed by a pinned GitHub Actions CI artifact (`ci_release_sha.json` missing)
- Not yet cryptographically verified against a T3N platform trust anchor

## Related Documents

- [claim-matrix.md](claim-matrix.md) — full claim-by-claim verification status
- [worker-key-isolation.md](worker-key-isolation.md) — Phase 4 isolation detail
- [gateway-key-isolation.md](gateway-key-isolation.md) — Phase 5 isolation detail
- [docs/architecture/security-invariants.md](../architecture/security-invariants.md) — runtime invariants
- [docs/release/criteria.md](../release/criteria.md) — release criteria checklist
