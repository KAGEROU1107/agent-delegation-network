# Security Claim Matrix

Current release label: `source-hardened / live-proof pending`.

| Claim | Current Status | Required Evidence |
| --- | --- | --- |
| Issuer-pinned contract authorization | Source-supported | Passing Rust tests and pinned build evidence |
| Worker execution with gateway-linked authorization | Source-supported | Prepared identity, typed T3N result, gateway receipt, durable replay ledger |
| T3N-attested authorization | Not claimed | Worker-verifiable T3N invocation receipt, signed response, or attestation |
| Durable host replay protection | Conditional | `ADN_RUNTIME_MODE=live`, persistent ledger configuration, restart replay proof |
| Contract-layer persistence | Not claimed | State-capable WIT/storage world and nonce consume proof |
| Deployment artifact provenance | Partial | `adn-release-proof-v1` manifest finalization with registration response, invocation receipt, T3N evidence digest, replay proof, and CI artifact evidence |
| Production-security release | Blocked | executor key separation, live proof artifact, visible CI success |

## Release Gate Checklist

- persistent ledger configuration is present and outside transient temp space.
- executor key separation prevents the TypeScript bridge from owning worker and gateway private keys.
- deployment manifest finalization records remote contract identity and registration evidence.
- live proof artifact captures a pinned v3.9.x prepare -> authorize -> execute run.
- `python scripts/verify_release.py <proof-dir>` passes against the retained proof bundle.
- visible CI success exists for the release commit.

## Forbidden Overclaims

- Do not call gateway-linked authorization T3N-attested authorization.
- Do not claim T3N-attested worker dispatch.
- Do not claim contract-layer persistence.
- Do not claim persistent feature systems for stateless WIT exports.
