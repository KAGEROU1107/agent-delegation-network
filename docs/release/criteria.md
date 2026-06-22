# Release Criteria

ADN v3.9.2 remains `source-hardened / live-proof pending` until every release
gate below has evidence in the repository.

## Required Gates

- persistent ledger configuration is mandatory for live execution.
- executor key separation is mandatory before production-security claims.
- deployment manifest finalization must record post-registration evidence.
- live proof artifact must include the exact pinned deployment run.
- visible CI success must be attached to the release commit.

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
ledger configuration. contract-layer persistence cannot be claimed because the
current WIT world imports no storage capability.

Persistent auction, vault, KYC, DAO, bond, and reputation systems cannot be
claimed until state-capable contract or executor storage semantics are designed,
implemented, and proven.
