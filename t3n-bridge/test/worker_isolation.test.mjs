/**
 * Worker Executor Isolation Tests
 *
 * Verifies that WorkerExecutorClient exposes ONLY public identity fields —
 * no worker private key bytes ever reach the bridge (TypeScript) side.
 */
import assert from "assert/strict";
import * as net from "net";
import * as crypto from "crypto";

// Import via ts-node/esm loader (same pattern as other tests in this suite)
const { WorkerExecutorClient } = await import("../src/worker_client.ts");

let client;

async function setup() {
  client = new WorkerExecutorClient();
  await client.spawn();
}

async function teardown() {
  client?.terminate();
}

// ─── Test helpers ────────────────────────────────────────────────────────────

async function rpcWithToken(port, token, method, params = {}) {
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(port, "127.0.0.1");
    let buf = "";
    conn.on("connect", () => conn.write(JSON.stringify({ token, method, ...params })));
    conn.on("data", (c) => {
      buf += c.toString();
      try {
        const parsed = JSON.parse(buf);
        conn.destroy();
        resolve(parsed);
      } catch { /* wait */ }
    });
    conn.on("error", reject);
    setTimeout(() => { conn.destroy(); reject(new Error("RPC timeout")); }, 3000);
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

await setup();
let failures = 0;

// Test 1: createSession returns only public identity (no private key bytes)
{
  const id = await client.createSession();
  const keys = Object.keys(id);
  const hasPrivate = "privateKey" in id || "privateKeyHex" in id;
  const hasAll = id.sessionId && id.publicKeyHex && id.did && id.agentId;
  const exactFour = keys.length === 4;

  if (!hasAll || !exactFour || hasPrivate) {
    console.error(`✗ createSession: keys=${JSON.stringify(keys)} hasPrivate=${hasPrivate}`);
    failures++;
  } else {
    console.log("✓ createSession returns exactly 4 public-identity fields (no private key)");
  }
  await client.closeSession(id.sessionId);
}

// Test 2: signResult returns a valid 64-byte hex signature
{
  const id = await client.createSession();
  const result = await client.signResult(id.sessionId, { data: "test-payload" });
  const validSig = /^[0-9a-f]{128}$/.test(result.signature);
  if (!validSig) {
    console.error(`✗ signResult: signature="${result.signature}"`);
    failures++;
  } else {
    console.log("✓ signResult returns a valid 64-byte hex signature");
  }
  await client.closeSession(id.sessionId);
}

// Test 3: unauthorized RPC token is rejected
{
  const wrongToken = crypto.randomBytes(32).toString("hex");
  const port = client.port;
  const r = await rpcWithToken(port, wrongToken, "create_session");
  if (r.error !== "unauthorized") {
    console.error(`✗ unauthorized token: expected error=unauthorized got ${JSON.stringify(r)}`);
    failures++;
  } else {
    console.log("✓ unauthorized RPC token rejected");
  }
}

// Test 4: cross-session access rejected (closed session cannot be signed)
{
  const s1 = await client.createSession();
  const s2 = await client.createSession();
  await client.closeSession(s1.sessionId);
  let threwExpected = false;
  try {
    await client.signResult(s1.sessionId, { data: "test" });
  } catch (e) {
    threwExpected = /unknown_session/.test(e.message);
  }
  if (!threwExpected) {
    console.error("✗ cross-session access: expected unknown_session error");
    failures++;
  } else {
    console.log("✓ cross-session access rejected (unknown_session)");
  }
  await client.closeSession(s2.sessionId);
}

// Test 5: getPublicKey after close throws unknown_session
{
  const id = await client.createSession();
  await client.closeSession(id.sessionId);
  let threwExpected = false;
  try {
    await client.getPublicKey(id.sessionId);
  } catch (e) {
    threwExpected = /unknown_session/.test(e.message);
  }
  if (!threwExpected) {
    console.error("✗ getPublicKey after close: expected unknown_session error");
    failures++;
  } else {
    console.log("✓ getPublicKey after close throws unknown_session");
  }
}

// Test 6: signResult returns distinct signatures for different payloads (sanity)
{
  const id = await client.createSession();
  const r1 = await client.signResult(id.sessionId, { data: "payload-A" });
  const r2 = await client.signResult(id.sessionId, { data: "payload-B" });
  if (r1.signature === r2.signature) {
    console.error("✗ different payloads produced identical signatures");
    failures++;
  } else {
    console.log("✓ distinct payloads produce distinct signatures");
  }
  await client.closeSession(id.sessionId);
}

await teardown();

if (failures > 0) {
  console.error(`\n${failures} worker isolation test(s) FAILED`);
  process.exit(1);
} else {
  console.log(`\nAll worker isolation tests passed.`);
}
