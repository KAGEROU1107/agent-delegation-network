/**
 * Worker Executor Client
 *
 * Bridge interface to adn/worker_executor.py.
 * The bridge NEVER sees worker private key bytes.
 * Bridge receives only: sessionId, agentId, did, publicKeyHex.
 *
 * Isolation boundary: process + 32-byte capability token (TCP loopback).
 * On Linux/macOS: supplement with chmod 0700 key directory + OS UID separation.
 * On Windows: process boundary + token is the isolation mechanism.
 */
import { spawn, ChildProcess } from "child_process";
import * as net from "net";
import * as crypto from "crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Resolves to agent-delegation-network/adn/worker_executor.py regardless of cwd
const WORKER_EXECUTOR_PATH = join(__dirname, "../../adn/worker_executor.py");

export interface WorkerPublicIdentity {
  sessionId: string;
  agentId: string;
  did: string;
  publicKeyHex: string;
}

export interface WorkerSignResult {
  signature: string;
  sessionId: string;
}

export class WorkerExecutorClient {
  private proc: ChildProcess | null = null;
  private _port = 0;
  private readonly token: string;

  constructor() {
    this.token = crypto.randomBytes(32).toString("hex");
  }

  /** Exposed for testing only — not part of the public API contract. */
  get port(): number {
    return this._port;
  }

  async spawn(): Promise<void> {
    return new Promise((resolve, reject) => {
      const env = { ...process.env, WORKER_CAPABILITY_TOKEN: this.token };
      this.proc = spawn("python3", [WORKER_EXECUTOR_PATH], {
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let ready = false;
      this.proc.stdout?.on("data", (chunk: Buffer) => {
        const line = chunk.toString().trim();
        if (line.startsWith("WORKER_EXECUTOR_READY:tcp:")) {
          this._port = parseInt(line.split(":")[2], 10);
          ready = true;
          resolve();
        }
      });
      this.proc.stderr?.on("data", (c: Buffer) => {
        if (!ready) reject(new Error(`worker_executor stderr: ${c}`));
      });
      this.proc.on("exit", (code) => {
        if (!ready) reject(new Error(`worker_executor exited: ${code}`));
      });
      setTimeout(() => { if (!ready) reject(new Error("worker_executor startup timeout")); }, 10000);
    });
  }

  private rpc(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const conn = net.createConnection(this._port, "127.0.0.1");
      let buf = "";
      conn.on("connect", () => conn.write(JSON.stringify({ token: this.token, method, ...params })));
      conn.on("data", (c) => {
        buf += c.toString();
        try {
          const parsed = JSON.parse(buf);
          conn.destroy();
          if (parsed.error) reject(new Error(`worker RPC: ${parsed.error}`));
          else resolve(parsed);
        } catch { /* wait for more data */ }
      });
      conn.on("error", reject);
      setTimeout(() => { conn.destroy(); reject(new Error("worker RPC timeout")); }, 5000);
    });
  }

  async createSession(): Promise<WorkerPublicIdentity> {
    const r = await this.rpc("create_session");
    return {
      sessionId: r.session_id as string,
      agentId: r.agentId as string,
      did: r.did as string,
      publicKeyHex: r.publicKeyHex as string,
    };
  }

  async signResult(sessionId: string, payload: unknown): Promise<WorkerSignResult> {
    const r = await this.rpc("sign_result", { session_id: sessionId, payload });
    return { signature: r.signature as string, sessionId: r.session_id as string };
  }

  async getPublicKey(sessionId: string): Promise<Pick<WorkerPublicIdentity, "publicKeyHex" | "did" | "agentId">> {
    const r = await this.rpc("get_public_key", { session_id: sessionId });
    return {
      publicKeyHex: r.publicKeyHex as string,
      did: r.did as string,
      agentId: r.agentId as string,
    };
  }

  async closeSession(sessionId: string): Promise<void> {
    await this.rpc("close_session", { session_id: sessionId });
  }

  terminate(): void { this.proc?.kill(); }
}
