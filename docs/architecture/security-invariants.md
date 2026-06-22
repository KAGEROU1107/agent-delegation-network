# Security Invariants

This document defines the runtime properties ADN v3.9.2 is allowed to claim.
If implementation, tests, and proof disagree with this file, the narrower claim wins.

## Worker Execution Gate

A worker executes only when all of these checks pass:

- target matches
- action matches
- credential is enforced
- gateway key ID matches
- build configuration matches
- authorization has not expired
- replay reservation succeeds

## Replay Keys

The request replay key is:

```text
SHA-256(delegation_id || request_hash || receipt_fingerprint)
```

The result replay key is:

```text
SHA-256(worker_public_key || coordinator_id || delegation_id || result_nonce || receipt_fingerprint)
```

## Durable Replay Boundary

Durable replay means the replay decision persists across:

- Python subprocess restart
- TypeScript bridge restart
- host process restart
- concurrent worker processes

Live bridge execution must use a persistent `ADN_REPLAY_LEDGER_DIR` outside the
bridge transient workspace plus a configured replay-ledger HMAC key. Demo mode may
use transient storage, but its output must be labeled `non-durable-demo`.

## Authorization Evidence Boundary

The current worker receipt is gateway-linked evidence bound to a typed T3N
authorization decision. It is not independently T3N-attested worker dispatch.

T3N-attested worker dispatch cannot be claimed unless the worker independently
verifies a platform-signed or TEE-attested T3N artifact.

## Contract-State Boundary

The current WIT world exports functions and imports no persistent storage
interface. Do not claim contract-layer nonce replay, persistent auction state,
persistent vault state, persistent KYC state, persistent DAO state, or a persistent
reputation ledger until a state-capable world is deployed and evidenced.
