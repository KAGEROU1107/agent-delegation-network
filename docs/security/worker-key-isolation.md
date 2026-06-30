# Worker Key Isolation

## Architecture

Worker private keys are owned exclusively by `adn/worker_executor.py`.
The T3N Bridge (TypeScript) never receives or stores worker private key bytes.

## Isolation Boundary

| Platform | Mechanism |
|----------|-----------|
| Windows (current) | Process boundary + 32-byte capability token over TCP loopback (127.0.0.1) |
| Linux/macOS (production target) | Process boundary + token + chmod 0700 key dir + OS UID separation |

## Bridge API (public identity only)

```
createSession()              -> { sessionId, agentId, did, publicKeyHex }
signResult(sessionId, data)  -> { signature, sessionId }
getPublicKey(sessionId)      -> { publicKeyHex, did, agentId }
closeSession(sessionId)      -> void
```

## What the bridge NEVER receives

- Private key bytes (raw, PEM, hex)
- Key serialization of any kind
- Any key material in RPC responses

## Capability token

- Generated: `crypto.randomBytes(32).toString("hex")` in bridge at spawn time
- Passed: `WORKER_CAPABILITY_TOKEN` env var to executor child process only
- Compared: `secrets.compare_digest()` (constant-time) in executor
- Never: logged, persisted, or sent over the wire in any response

## Files

| File | Role |
|------|------|
| `adn/worker_executor.py` | Key enclave process. Owns all worker Ed25519 private keys in memory. |
| `t3n-bridge/src/worker_client.ts` | Bridge-side client. Spawns executor, holds token, exposes public-identity API. |
| `t3n-bridge/test/worker_isolation.test.mjs` | Isolation tests verifying the key boundary holds. |

## What changed from Phase 3

Phase 3 used Python-written temp files for worker keys — TypeScript held the file *path* but never the key bytes. Phase 4 replaces this with a long-lived executor process:

| | Phase 3 | Phase 4 |
|-|---------|---------|
| Worker key lifetime | Written to temp file per execution, deleted after | In-memory in executor process, session-scoped |
| Bridge sees | File path (never content) | Only public identity fields |
| Key boundary | Filesystem + os.chmod | Process boundary + capability token |
| Signing | Python subprocess per execution | RPC to persistent executor process |
