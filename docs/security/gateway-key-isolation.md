# Gateway Key Isolation

## Before Phase 5

The bridge read `ADN_GATEWAY_PRIVATE_KEY_HEX` from its own process environment, stored the
raw private key bytes in a local variable (`privateKeyHex`), and explicitly passed the value
to the gateway executor subprocess via the child's environment.

The raw private key was present in bridge process memory as a JavaScript string.

## After Phase 5

### Live mode (`ADN_RUNTIME_MODE=live`)

- The bridge calls `connectToExistingExecutor()` — reads only a socket address and a
  capability token file path from its env. No key material is read.
- `ADN_GATEWAY_PRIVATE_KEY_HEX` must **NOT** be set in the bridge process environment in
  live mode.
- The gateway executor is started independently by a secrets provider or process supervisor
  that has access to the key. The bridge never holds the raw key.
- `spawnGatewayExecutor()` throws immediately in live mode — before reading any env vars.

### Dev/demo mode (`ADN_RUNTIME_MODE` unset or `demo`)

- The bridge spawns the gateway executor locally.
- The bridge performs a **presence-only** check (`if (!process.env.ADN_GATEWAY_PRIVATE_KEY_HEX)`)
  to give a useful error, but never reads the value into a bridge-owned variable.
- The child executor inherits the parent env snapshot (which includes the key) and reads
  `ADN_GATEWAY_PRIVATE_KEY_HEX` from **its own** `process.env`, then immediately scrubs it.
- The bridge deletes the key from its own `process.env` immediately after creating the
  child's env snapshot.
- This dev-mode path is explicitly blocked in live mode.

## Required live-mode env vars

```
ADN_GATEWAY_EXECUTOR_SOCKET            tcp:<port>  or  unix:<path>
ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE   /path/to/token/file (permissions: 0600)
```

## What the bridge NEVER holds in live mode

- The raw `ADN_GATEWAY_PRIVATE_KEY_HEX` byte value — it is only ever inside the executor process.
- The capability token string in memory beyond the duration of a single RPC call (it is read
  from the file at startup of `connectToExistingExecutor()` and stored inside the closure of
  the returned client object, not in any global bridge state).

## Health endpoint

The executor exposes a `health` method that returns `{ status: "ok", hasKey: boolean }`.
This allows the bridge to verify the executor is alive and the key was loaded, **without**
exposing the key value or any signing capability.

## Security guarantee chain

```
Secrets provider / supervisor
  ↓ starts executor with key in its own env
Gateway Executor (gateway_executor.ts)
  ↓ reads key, scrubs it from env, starts listening
  ↓ writes GATEWAY_EXECUTOR_READY line with socket address
Secrets provider writes capability token to file (mode 0600)
Bridge (gateway_client.ts — connectToExistingExecutor)
  ↓ reads socket address + reads token from file
  ↓ calls health() to verify executor is alive
  ↓ all signing calls include the capability token
```

The bridge process never has `ADN_GATEWAY_PRIVATE_KEY_HEX` in its memory in live mode.
