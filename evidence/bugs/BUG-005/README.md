# BUG-005 Evidence — Delegation envelope not validated at transport layer

## Pre-fix behavior (adn-processor v3.5.0)

Both pre- and post-revocation calls returned `ACCEPTED`. The revocation call succeeded
(T3N delegation registry), but the transport layer did not enforce it for `generic-input`
contracts. No observable difference between valid and revoked credential.

## Post-fix behavior (adn-processor v3.6.0+)

From `proof/live_run_v3.8.0_session6_final.txt`:
```
[+] pre-revocation call:   ACCEPTED: {"delegation_id":...,"status":"ROUTED",...}
[+] revocation:            SUCCESS (tee:delegation/contracts::revoke)
[35s sleep — credential window expires]
[+] post-revocation call:  REJECTED: delegate-task: credential expired (TEE contract layer v3.8.0)
[+] missing agent_sig:     REJECTED: delegate-task: agent_sig missing from envelope
[+] short nonce (4 bytes): REJECTED: delegate-task: nonce too short (< 8 bytes)
```

## Fix location

`contract/src/lib.rs` — `fn delegate_task()` — parses `__delegation_envelope` from
input, validates `credential_jcs` fields against WASI `SystemTime::now()`.

## Related

- `docs/bugs/BUG-005-envelope-not-validated-at-transport.md`
- `contract/src/lib.rs`
- `proof/live_run_v3.5.0.txt` — pre-fix baseline
- `proof/live_run_v3.8.0_session6_final.txt` — post-fix evidence
