# ADN Security Posture — Current State
Baseline audit commit: 84a5d2fbdd44466058e6ffb3349a8e1e687ac33b
Date: 2026-06-28

## v3.8.1 Historical Proof
- Status: historical live T3N testnet proof
- Location: proof/ (live_run_v3.8.1_final_88b7b88.txt, live_run_v3.8.1_c01_proof.txt — do not modify)

## v3.9.2 Current State
- Source hardening: complete (Phases 0-7, commits 40eb618..04f484f)
- Registration: registered on T3N testnet (contract_id=459)
- Gateway authorization: signed gateway receipt (tee-del-2c970ed3…)
- Platform attestation: NOT cryptographically verified — T3nAttestedEvidenceVerifier accepts any non-empty platformMaterial; no signature verification
- Worker key isolation: PARTIAL — keys generated inside Python executor but still written to bridge-accessible temp directory; no OS-level separation
- Contract state: stateless WIT contract (no wasi:keyvalue)
- Release manifest: INVALID against adn-release-proof-v1 schema — deployment_manifest.json is a remediation tracker, not a schema-valid release proof
- Remote verifiers: FAILING — verify_release.py, verify_release_remote.py, verify_release_asset.py all fail; missing deployment_manifest.sig and ci_release_sha.json
- CI status: green on main (20/20 WIT exports, 25/25 Rust, 105/105 Python)

## What "v3.9.2 live proven" would require (not yet achieved)
1. Schema-valid deployment_manifest.json against adn-release-proof-v1
2. Cryptographically verified T3N platform evidence (real signature from T3N signer)
3. OS-enforced worker key isolation
4. Gateway key never entering bridge process
5. All remote verifiers passing: verify_release.py, verify_release_remote.py, verify_release_asset.py, verify_release_asset_remote.py
6. deployment_manifest.sig from operator private key
7. ci_release_sha.json from GitHub Actions CI on final HEAD
