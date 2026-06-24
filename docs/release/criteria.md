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
- `.github/workflows/release-proof-input.yml` must run
  `python scripts/verify_release.py proof/release --input-only`, upload the
  verified proof-input archive, and then finish without asserting its own final
  success in `ci_release_sha.json`.
- `.github/workflows/release-proof-attest.yml` must run from the completed
  `Release Proof Input` workflow event, generate `ci_release_sha.json` from the
  completed run and GitHub artifact metadata, then run
  `python scripts/verify_release.py proof/release`.
- `python scripts/verify_release_remote.py proof/release` must verify that the
  declared GitHub workflow run exists, completed successfully for the manifest
  commit, owns the declared artifact, and that the downloaded artifact contains
  the exact retained proof inputs.
- `python scripts/verify_release_asset.py <release-asset-dir>` must verify the
  published GitHub Release proof assets after download, including the signed
  `release_asset_manifest.json`, `release_asset_manifest.sig`, per-file SHA-256
  hashes, proof-input archive contents, CI attestation, remote verifier output,
  and workflow metadata.

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

Remote CI provenance is checked by `scripts/verify_release_remote.py` from the
attestation workflow, after the input workflow has completed. It uses GitHub
Actions API evidence to fetch the declared workflow run and uploaded proof-input
artifact, compares GitHub's artifact digest with the attestation, downloads the
artifact ZIP, reads `proof-input.tar`, rejects unexpected archive paths, and
recomputes the retained proof-input file digests.

Durable release asset provenance is checked by
`scripts/verify_release_asset.py` after downloading the GitHub Release assets.
It verifies the operator-signed release asset manifest, hashes every published
payload file, re-materializes `proof-input.tar`, reruns the local release proof
checks against that archive plus `ci_release_sha.json`, and rejects unexpected
release asset files.

Persistent auction, vault, KYC, DAO, bond, and reputation systems cannot be
claimed until state-capable contract or executor storage semantics are designed,
implemented, and proven.
