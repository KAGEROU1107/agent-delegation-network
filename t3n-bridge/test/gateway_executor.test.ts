/**
 * Integration tests for gateway_executor.ts — verifies the token-auth boundary
 * and method dispatch over the socket protocol.
 *
 * Each test case spawns a fresh executor so that connection-closing cases
 * (unauthorized, etc.) don't bleed into subsequent assertions.
 */

import assert from "assert/strict";
import * as cp from "child_process";
import * as net from "net";
import * as crypto from "crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXECUTOR_PATH = join(__dirname, "../src/gateway_executor.ts");

// A random valid 32-byte Ed25519 seed for these tests
const TEST_PRIVATE_KEY_HEX = crypto.randomBytes(32).toString("hex");
const VALID_TOKEN = crypto.randomBytes(32).toString("hex");
const WRONG_TOKEN = crypto.randomBytes(32).toString("hex");

const MOCK_TEE_RESULT = {
  delegation_id: "test-delegation-abc123",
  status: "ROUTED",
  routed_to: "test-agent-001",
  credential_fingerprint: "fp-test-001",
  credential_enforced: true,
  build_config_id: "test-build-001",
  authorization_expires_at: "2099-12-31T00:00:00+00:00",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function spawnTestExecutor(
  token: string,
): Promise<{ address: string; child: cp.ChildProcess }> {
  return new Promise((resolve, reject) => {
    const child = cp.spawn(
      process.execPath,
      ["--loader", "ts-node/esm", EXECUTOR_PATH],
      {
        env: {
          ...process.env,
          ADN_GATEWAY_PRIVATE_KEY_HEX: TEST_PRIVATE_KEY_HEX,
          GATEWAY_CAPABILITY_TOKEN: token,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    let buf = "";
    child.stdout!.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      const match = buf.match(/GATEWAY_EXECUTOR_READY:(unix:[^\n]+|tcp:\d+)/);
      if (match) {
        resolve({ address: match[1].trim(), child });
      }
    });
    child.stderr!.on("data", (_chunk: Buffer) => {
      /* suppress executor startup noise */
    });
    child.on("error", reject);
    setTimeout(() => reject(new Error("executor startup timeout (20s)")), 20_000);
  });
}

async function connectToAddress(address: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let s: net.Socket;
    if (address.startsWith("unix:")) {
      s = net.connect(address.slice(5), () => resolve(s));
    } else {
      const port = parseInt(address.slice(4), 10);
      s = net.connect(port, "127.0.0.1", () => resolve(s));
    }
    s.on("error", reject);
  });
}

/**
 * Write a raw line and wait for the first complete newline-delimited response.
 * Works even when the server closes the connection after responding.
 */
async function rawRpc(
  socket: net.Socket,
  line: string,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let buf = "";

    const cleanup = () => {
      socket.removeListener("data", onData);
      socket.removeListener("end", onEnd);
      socket.removeListener("error", onError);
    };

    const onData = (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        cleanup();
        try {
          resolve(JSON.parse(buf.slice(0, nl).trim()));
        } catch (e) {
          reject(e);
        }
      }
    };

    // Server may close connection after responding (e.g. unauthorized)
    const onEnd = () => {
      cleanup();
      const trimmed = buf.trim();
      if (trimmed) {
        try {
          resolve(JSON.parse(trimmed));
        } catch (e) {
          reject(e);
        }
      } else {
        reject(new Error("Socket closed without sending a response"));
      }
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    socket.on("data", onData);
    socket.on("end", onEnd);
    socket.on("error", onError);
    socket.write(line + "\n");
  });
}

/** Convenience wrapper: serialise req as JSON then call rawRpc. */
function sendRpc(
  socket: net.Socket,
  req: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return rawRpc(socket, JSON.stringify(req));
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// Test 1: missing token → rejected
{
  const { address, child } = await spawnTestExecutor(VALID_TOKEN);
  const socket = await connectToAddress(address);
  try {
    const resp = await sendRpc(socket, { id: 1, method: "get_public_key" });
    assert.equal(resp.error, "unauthorized", "missing token should be rejected");
  } finally {
    socket.destroy();
    child.kill("SIGTERM");
  }
  console.log("✓ missing token → rejected");
}

// Test 2: wrong token → rejected
{
  const { address, child } = await spawnTestExecutor(VALID_TOKEN);
  const socket = await connectToAddress(address);
  try {
    const resp = await sendRpc(socket, {
      id: 1,
      method: "get_public_key",
      token: WRONG_TOKEN,
    });
    assert.equal(resp.error, "unauthorized", "wrong token should be rejected");
  } finally {
    socket.destroy();
    child.kill("SIGTERM");
  }
  console.log("✓ wrong token → rejected");
}

// Test 3: valid token + get_public_key → success
{
  const { address, child } = await spawnTestExecutor(VALID_TOKEN);
  const socket = await connectToAddress(address);
  try {
    const resp = await sendRpc(socket, {
      id: 1,
      method: "get_public_key",
      token: VALID_TOKEN,
    });
    assert.ok(!resp.error, `unexpected error: ${resp.error}`);
    assert.ok(
      typeof resp.publicKeyHex === "string" && resp.publicKeyHex.length === 64,
      "publicKeyHex should be a 64-char hex string",
    );
    assert.ok(typeof resp.agentId === "string" && resp.agentId.length > 0, "agentId required");
    assert.ok(typeof resp.did === "string" && (resp.did as string).startsWith("did:"), "did required");
    assert.ok(typeof resp.gatewayKeyId === "string", "gatewayKeyId required");
  } finally {
    socket.destroy();
    child.kill("SIGTERM");
  }
  console.log("✓ valid token + get_public_key → success");
}

// Test 4: valid token + sign_receipt → success (mock minimal receipt)
{
  const { address, child } = await spawnTestExecutor(VALID_TOKEN);
  const socket = await connectToAddress(address);
  try {
    const resp = await sendRpc(socket, {
      id: 2,
      method: "sign_receipt",
      token: VALID_TOKEN,
      teeResult: MOCK_TEE_RESULT,
      action: "PROCESS_DATA",
      parameters: { data_source: "csv" },
    });
    assert.ok(!resp.error, `unexpected error: ${resp.error}`);
    const receipt = resp.receipt as Record<string, unknown>;
    assert.ok(receipt, "receipt should be present");
    assert.equal(receipt.delegation_id, MOCK_TEE_RESULT.delegation_id);
    assert.equal(receipt.to_agent_id, MOCK_TEE_RESULT.routed_to);
    assert.equal(receipt.action, "PROCESS_DATA");
    assert.ok(typeof receipt.gateway_proof === "object", "gateway_proof required");
    const proof = receipt.gateway_proof as Record<string, unknown>;
    assert.ok(
      typeof proof.signature_hex === "string" && (proof.signature_hex as string).length === 128,
      "signature_hex should be 64-byte Ed25519 signature (128 hex chars)",
    );
  } finally {
    socket.destroy();
    child.kill("SIGTERM");
  }
  console.log("✓ valid token + sign_receipt → success");
}

// Test 5: malformed JSON → rejected (connection stays open; send raw bytes)
{
  const { address, child } = await spawnTestExecutor(VALID_TOKEN);
  const socket = await connectToAddress(address);
  try {
    // Send a raw line that is not valid JSON — bypass sendRpc to avoid serialisation
    const resp = await rawRpc(socket, "this is definitely not json {{{");
    assert.ok(typeof resp.error === "string", "malformed JSON should return an error field");
  } finally {
    socket.destroy();
    child.kill("SIGTERM");
  }
  console.log("✓ malformed JSON → rejected");
}

// Test 6: unknown method → rejected with unknown_method
{
  const { address, child } = await spawnTestExecutor(VALID_TOKEN);
  const socket = await connectToAddress(address);
  try {
    const resp = await sendRpc(socket, {
      id: 1,
      method: "fly_to_moon",
      token: VALID_TOKEN,
    });
    assert.equal(resp.error, "unknown_method", "unknown method should return unknown_method");
  } finally {
    socket.destroy();
    child.kill("SIGTERM");
  }
  console.log("✓ unknown method → rejected with unknown_method");
}

console.log("\nAll gateway_executor tests passed.");
