/**
 * Gateway Client — bridge-side interface to the Gateway Executor.
 *
 * Security model:
 *   1. This module reads ADN_GATEWAY_PRIVATE_KEY_HEX once from the bridge's env.
 *   2. It spawns the gateway_executor child process with the key in the child's env.
 *   3. It immediately deletes the key from the bridge's own process.env.
 *   4. All subsequent signing happens inside the executor process.
 *   5. The bridge never touches raw Ed25519 key material again.
 *
 * The executor communicates over a loopback TCP socket (127.0.0.1, random port).
 * Protocol: newline-delimited JSON.
 */

import * as net from "net";
import * as cp from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface GatewayPublicInfo {
  publicKeyHex: string;
  agentId: string;
  did: string;
  gatewayKeyId: string;
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

  /** Terminates the executor and closes the TCP socket. */
  close(): void;
}

// ─── Spawn & connect ──────────────────────────────────────────────────────────

export function spawnGatewayExecutor(): Promise<GatewaySigningClient> {
  return new Promise((resolve, reject) => {
    // Read the private key once — immediately scrub from this process's env
    const privateKeyHex = process.env.ADN_GATEWAY_PRIVATE_KEY_HEX;
    const gatewayKeyId = process.env.ADN_GATEWAY_KEY_ID;

    if (!privateKeyHex?.trim()) {
      reject(
        new Error(
          "ADN_GATEWAY_PRIVATE_KEY_HEX is required to spawn the gateway executor. " +
            "Pass it via the service environment; it will be isolated to the executor process.",
        ),
      );
      return;
    }

    // Scrub from bridge env immediately — executor gets its own isolated copy
    delete process.env.ADN_GATEWAY_PRIVATE_KEY_HEX;

    const executorEnv: Record<string, string> = {
      ADN_GATEWAY_PRIVATE_KEY_HEX: privateKeyHex.trim(),
    };
    if (gatewayKeyId) executorEnv.ADN_GATEWAY_KEY_ID = gatewayKeyId;

    // Resolve the compiled executor path (sits next to this file after `tsc`)
    const executorPath = join(__dirname, "gateway_executor.js");

    const child = cp.spawn(process.execPath, [executorPath], {
      env: executorEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdoutBuf = "";
    let settled = false;

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8");
      if (settled) return;
      const match = stdoutBuf.match(/GATEWAY_EXECUTOR_READY:(\d+)/);
      if (match) {
        settled = true;
        const port = parseInt(match[1], 10);
        resolve(createClient(child, port));
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

    // Hard timeout — executor should start in < 5 s
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

function createClient(
  child: cp.ChildProcess,
  port: number,
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
      const s = net.connect(port, "127.0.0.1", () => {
        socket = s;
        res(s);
      });
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
          s.write(JSON.stringify({ ...request, id }) + "\n");
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

    close(): void {
      socket?.destroy();
      socket = null;
      try {
        child.kill("SIGTERM");
      } catch {
        /* already gone */
      }
    },
  };
}
