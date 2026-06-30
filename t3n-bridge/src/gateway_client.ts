/**
 * Gateway Client — bridge-side interface to the Gateway Executor.
 *
 * Security model:
 *   DEV/DEMO MODE (ADN_RUNTIME_MODE ≠ "live"):
 *     - spawnGatewayExecutor() reads ADN_GATEWAY_PRIVATE_KEY_HEX once,
 *       passes it to the child process, and immediately deletes it from the
 *       bridge's own process.env. All signing happens inside the executor.
 *
 *   LIVE MODE (ADN_RUNTIME_MODE === "live"):
 *     - connectToExistingExecutor() is used instead. The bridge reads ONLY:
 *         ADN_GATEWAY_EXECUTOR_SOCKET          — "tcp:<port>" or "unix:<path>"
 *         ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE — path to a file containing the token
 *     - ADN_GATEWAY_PRIVATE_KEY_HEX MUST NOT be set in the bridge env in live mode.
 *     - The gateway executor is started by a secrets provider / process supervisor
 *       that has access to the key. The bridge never holds raw key material.
 *     - spawnGatewayExecutor() throws immediately in live mode.
 *
 * The executor communicates over a Unix-domain socket (non-Windows) or loopback
 * TCP (Windows). Protocol: newline-delimited JSON.
 */

import * as net from "net";
import * as cp from "child_process";
import { randomBytes } from "crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync as fsReadFileSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface GatewayPublicInfo {
  publicKeyHex: string;
  agentId: string;
  did: string;
  gatewayKeyId: string;
}

export interface GatewayHealthResult {
  status: string;
  hasKey: boolean;
}

export interface GatewaySigningClient {
  /** Returns public identity info (never returns private key). */
  getPublicInfo(): Promise<GatewayPublicInfo>;

  /**
   * Signs a TEE authorization receipt inside the executor process.
   * The bridge never sees raw key material; only the signed receipt is returned.
   */
  signReceipt(
    teeResult: Record<string, unknown>,
    action: string,
    parameters?: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;

  /** Checks executor liveness — returns status without exposing key material. */
  health(): Promise<GatewayHealthResult>;

  /** Closes the socket. In dev mode also terminates the spawned executor. */
  close(): void;
}

// ─── Live mode: connect to an already-running executor ───────────────────────

/**
 * Connect to an already-running gateway executor.
 * Used in live mode — the executor was started by a secrets provider/supervisor,
 * not by the bridge. The bridge never handles the raw gateway private key.
 *
 * Reads from env:
 *   ADN_GATEWAY_EXECUTOR_SOCKET          — "tcp:<port>" or "unix:<path>"
 *   ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE — path to file containing capability token
 */
export async function connectToExistingExecutor(): Promise<GatewaySigningClient> {
  const socketEnv = process.env.ADN_GATEWAY_EXECUTOR_SOCKET;
  const tokenFile = process.env.ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE;

  if (!socketEnv) {
    throw new Error(
      "[gateway] ADN_GATEWAY_EXECUTOR_SOCKET not set — cannot connect to executor in live mode",
    );
  }
  if (!tokenFile) {
    throw new Error(
      "[gateway] ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE not set — cannot load capability token",
    );
  }

  let token: string;
  try {
    token = fsReadFileSync(tokenFile, "utf8").trim();
  } catch (err) {
    throw new Error(
      `[gateway] Cannot read capability token file "${tokenFile}": ${(err as Error).message}`,
    );
  }
  if (!token || token.length < 32) {
    throw new Error("[gateway] Capability token file is empty or too short");
  }

  let addrSpec: string;
  if (socketEnv.startsWith("tcp:") || socketEnv.startsWith("unix:")) {
    addrSpec = socketEnv;
  } else {
    throw new Error(`[gateway] Unknown socket format: ${socketEnv} — expected "tcp:<port>" or "unix:<path>"`);
  }

  // Verify the executor is reachable before returning the client
  const client = createClient(null, addrSpec, token);
  const health = await client.health();
  if (health.status !== "ok") {
    client.close();
    throw new Error(`[gateway] Executor health check failed: status=${health.status}`);
  }

  return client;
}

// ─── Dev mode: spawn & connect ───────────────────────────────────────────────

export function spawnGatewayExecutor(): Promise<GatewaySigningClient> {
  if (process.env.ADN_RUNTIME_MODE === "live") {
    return Promise.reject(
      new Error(
        "[gateway] spawnGatewayExecutor() is blocked in live mode. " +
          "Start the executor as a separate process and use connectToExistingExecutor() instead.",
      ),
    );
  }

  return new Promise((resolve, reject) => {
    // Generate a per-session capability token — passed out-of-band via env, not TCP
    const capabilityToken = randomBytes(32).toString("hex");

    // Presence-only check — the bridge never reads the key VALUE.
    // The executor reads ADN_GATEWAY_PRIVATE_KEY_HEX from its own inherited environment.
    if (!process.env.ADN_GATEWAY_PRIVATE_KEY_HEX?.trim()) {
      reject(
        new Error(
          "ADN_GATEWAY_PRIVATE_KEY_HEX must be set for dev-mode executor spawn. " +
            "The key is read by the executor from its own environment, not by the bridge.",
        ),
      );
      return;
    }

    // Snapshot parent env for the child, then immediately scrub key from bridge env.
    // The key is in the snapshot for the executor but is never held in a bridge variable.
    const executorEnv: NodeJS.ProcessEnv = {
      ...process.env,
      GATEWAY_CAPABILITY_TOKEN: capabilityToken,
    };
    delete process.env.ADN_GATEWAY_PRIVATE_KEY_HEX;

    // Resolve the compiled executor path (sits next to this file after `tsc`)
    const executorPath = join(__dirname, "gateway_executor.js");

    const child = cp.spawn(process.execPath, [executorPath], {
      env: executorEnv as Record<string, string>,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdoutBuf = "";
    let settled = false;

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8");
      if (settled) return;
      // Ready line is either:
      //   GATEWAY_EXECUTOR_READY:unix:/tmp/gw-XXXX/gateway.sock
      //   GATEWAY_EXECUTOR_READY:tcp:12345
      const match = stdoutBuf.match(/GATEWAY_EXECUTOR_READY:(unix:[^\n]+|tcp:\d+)/);
      if (match) {
        settled = true;
        const addrSpec = match[1].trim();
        resolve(createClient(child, addrSpec, capabilityToken));
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(`[gateway_executor] ${chunk.toString("utf8")}`);
    });

    child.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(new Error(`Failed to spawn gateway executor: ${err.message}`));
      }
    });

    child.on("exit", (code) => {
      if (!settled) {
        settled = true;
        reject(new Error(`Gateway executor exited before ready (code ${code ?? "unknown"})`));
      }
    });

    // Hard timeout — executor should start in < 10 s
    setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGTERM");
        reject(new Error("Gateway executor startup timeout (10s)"));
      }
    }, 10_000);
  });
}

// ─── Client implementation ────────────────────────────────────────────────────

/**
 * Creates a GatewaySigningClient that communicates over the given socket.
 * Pass child=null when connecting to an externally-managed executor (live mode).
 * Pass child=ChildProcess when the bridge spawned the executor (dev mode).
 */
function createClient(
  child: cp.ChildProcess | null,
  addrSpec: string,
  capabilityToken: string,
): GatewaySigningClient {
  let socket: net.Socket | null = null;
  let idCounter = 0;
  let recvBuf = "";
  const pending = new Map<
    number,
    {
      resolve: (v: Record<string, unknown>) => void;
      reject: (e: Error) => void;
    }
  >();

  function onSocketData(chunk: Buffer): void {
    recvBuf += chunk.toString("utf8");
    let nl: number;
    while ((nl = recvBuf.indexOf("\n")) !== -1) {
      const line = recvBuf.slice(0, nl).trim();
      recvBuf = recvBuf.slice(nl + 1);
      if (!line) continue;
      try {
        const resp = JSON.parse(line) as Record<string, unknown>;
        const id = resp.id as number;
        const cb = pending.get(id);
        if (cb) {
          pending.delete(id);
          if (resp.error) {
            cb.reject(new Error(String(resp.error)));
          } else {
            cb.resolve(resp);
          }
        }
      } catch {
        /* ignore malformed response */
      }
    }
  }

  function ensureConnected(): Promise<net.Socket> {
    if (socket && !socket.destroyed) return Promise.resolve(socket);
    return new Promise((res, rej) => {
      let s: net.Socket;
      if (addrSpec.startsWith("unix:")) {
        const sockPath = addrSpec.slice(5);
        s = net.connect(sockPath, () => {
          socket = s;
          res(s);
        });
      } else {
        // tcp:PORT
        const port = parseInt(addrSpec.slice(4), 10);
        s = net.connect(port, "127.0.0.1", () => {
          socket = s;
          res(s);
        });
      }
      s.on("data", onSocketData);
      s.on("error", rej);
    });
  }

  function rpc(request: Record<string, unknown>): Promise<Record<string, unknown>> {
    return ensureConnected().then(
      (s) =>
        new Promise((res, rej) => {
          const id = ++idCounter;
          pending.set(id, { resolve: res, reject: rej });
          // Include capability token in every request
          s.write(JSON.stringify({ ...request, id, token: capabilityToken }) + "\n");
        }),
    );
  }

  return {
    async getPublicInfo(): Promise<GatewayPublicInfo> {
      const resp = await rpc({ method: "get_public_key" });
      return {
        publicKeyHex: resp.publicKeyHex as string,
        agentId: resp.agentId as string,
        did: resp.did as string,
        gatewayKeyId: resp.gatewayKeyId as string,
      };
    },

    async signReceipt(
      teeResult: Record<string, unknown>,
      action: string,
      parameters?: Record<string, unknown>,
    ): Promise<Record<string, unknown>> {
      const resp = await rpc({
        method: "sign_receipt",
        teeResult,
        action,
        parameters: parameters ?? {},
      });
      return resp.receipt as Record<string, unknown>;
    },

    async health(): Promise<GatewayHealthResult> {
      const resp = await rpc({ method: "health" });
      return { status: resp.status as string, hasKey: resp.hasKey as boolean };
    },

    close(): void {
      socket?.destroy();
      socket = null;
      if (child) {
        try {
          child.kill("SIGTERM");
        } catch {
          /* already gone */
        }
      }
    },
  };
}
