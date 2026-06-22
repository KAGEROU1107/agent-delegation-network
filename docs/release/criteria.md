# Release Criteria

ADN v3.9.2 remains `source-hardened / live-proof pending` until every release
gate below has evidence in the repository.

## Required Gates

- persistent ledger configuration is mandatory for live execution.
- executor key separation is mandatory before production-security claims.
- deployment manifest finalization must record post-registration evidence.
- live proof artifact must include the exact pinned deployment run.
- `python scripts/verify_release.py <proof-dir>` must pass for the proof bundle.
- visible CI success must be attached to the release commit.
- `.github/workflows/release-proof.yml` must first run
  `python scripts/verify_release.py proof/release --input-only`, upload the
  verified proof-input archive, then generate `ci_release_sha.json` from
  GitHub Actions upload outputs before running `python scripts/verify_release.py proof/release`.
- `python scripts/verify_release_remote.py proof/release` must verify that the
  declared GitHub workflow run exists, completed successfully for the manifest
  commit, owns the declared artifact, and that the downloaded artifact contains
  the exact retained proof inputs.

## Claim Labels

- `gateway-linked authorization` means a configured gateway signed a receipt
  over a typed T3N authorization result and the worker verified that receipt.
- `T3N-attested authorization` means the worker independently verified a
  platform-origin T3N receipt, signed result, or TEE attestation artifact.

The current source supports `gateway-linked authorization`. Do not claim
`T3N-attested authorization` or T3N-attested worker dispatch until Phase 5
evidence verification exists.

## Persistence Boundaries

Host-side replay protection can be claimed only when live mode uses durable
ledger configuration and the bridge restart replay proof rejects both the same
signed request and the same signed result after a process restart.
contract-layer persistence cannot be claimed because the
current WIT world imports no storage capability.

## Proof Bundle

The release proof verifier expects:

- `deployment_manifest.json`
- `deployment_manifest.sig`
- `registration_response.json`
- `invocation_receipt.json`
- `t3n_evidence.json`
- `replay_restart_proof.json`
- `ci_release_sha.json`

The verifier checks manifest schema, manifest digest, operator signature,
registration response digest, first invocation digest, T3N evidence digest,
release SHA, GitHub Actions evidence fields, actual upload-artifact ID/URL/digest
metadata, recomputed `proof_input_digest`, build configuration, and snake_case
replay restart proof booleans.

Remote CI provenance is checked by `scripts/verify_release_remote.py`. It uses
GitHub Actions API evidence to fetch the declared workflow run and uploaded
proof-input artifact, compares GitHub's artifact digest with the attestation,
downloads the artifact ZIP, reads `proof-input.tar`, and recomputes the retained
proof-input file digests.

Persistent auction, vault, KYC, DAO, bond, and reputation systems cannot be
claimed until state-capable contract or executor storage semantics are designed,
implemented, and proven.
