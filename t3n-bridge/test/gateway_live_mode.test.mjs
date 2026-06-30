/**
 * Gateway Live Mode Isolation Tests — Phase 5 remediation.
 *
 * Verifies:
 *   1. spawnGatewayExecutor() is blocked in live mode
 *   2. connectToExistingExecutor() fails without ADN_GATEWAY_EXECUTOR_SOCKET
 *   3. connectToExistingExecutor() fails without ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE
 *   4. health endpoint returns { status: "ok", hasKey: true } without exposing private key
 *   5. Bridge never holds raw gateway private key in live mode (structural check)
 */

import assert from "assert/strict";
import * as crypto from "crypto";
import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import via ts-node/esm loader (same pattern as the rest of this test suite)
const { spawnGatewayExecutor, connectToExistingExecutor } =
  await import("../src/gateway_client.ts");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function saveEnv(...keys) {
  const saved = {};
  for (const k of keys) saved[k] = process.env[k];
  return saved;
}

function restoreEnv(saved) {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
}

/** Spawn a real executor for integration-style health test. */
async function spawnTestExecutorRaw() {
  const privateKeyHex = crypto.randomBytes(32).toString("hex");
  const capabilityToken = crypto.randomBytes(32).toString("hex");

  return new Promise((resolve, reject) => {
    const executorPath = path.join(__dirname, "../src/gateway_executor.ts");
    const child = cp.spawn(process.execPath, ["--loader", "ts-node/esm", executorPath], {
      env: {
        ...process.env,
        ADN_GATEWAY_PRIVATE_KEY_HEX: privateKeyHex,
        GATEWAY_CAPABILITY_TOKEN: capabilityToken,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let buf = "";
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const match = buf.match(/GATEWAY_EXECUTOR_READY:(unix:[^\n]+|tcp:\d+)/);
      if (match) {
        resolve({ child, addrSpec: match[1].trim(), capabilityToken });
      }
    });
    child.stderr.on("data", () => {});
    child.on("error", reject);
    setTimeout(() => reject(new Error("executor startup timeout (20s)")), 20_000);
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

let failures = 0;

// Test 1: spawnGatewayExecutor() blocked in live mode
{
  const saved = saveEnv("ADN_RUNTIME_MODE");
  try {
    process.env.ADN_RUNTIME_MODE = "live";
    await assert.rejects(
      () => spawnGatewayExecutor(),
      /blocked in live mode/,
    );
    console.log("✓ spawnGatewayExecutor() blocked in live mode");
  } catch (err) {
    console.error(`✗ spawnGatewayExecutor() live-mode block: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// Test 2: connectToExistingExecutor() fails without ADN_GATEWAY_EXECUTOR_SOCKET
{
  const saved = saveEnv("ADN_RUNTIME_MODE", "ADN_GATEWAY_EXECUTOR_SOCKET", "ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE");
  try {
    process.env.ADN_RUNTIME_MODE = "live";
    delete process.env.ADN_GATEWAY_EXECUTOR_SOCKET;
    delete process.env.ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE;
    await assert.rejects(
      () => connectToExistingExecutor(),
      /ADN_GATEWAY_EXECUTOR_SOCKET not set/,
    );
    console.log("✓ connectToExistingExecutor() fails without ADN_GATEWAY_EXECUTOR_SOCKET");
  } catch (err) {
    console.error(`✗ connectToExistingExecutor() missing socket check: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// Test 3: connectToExistingExecutor() fails without ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE
{
  const saved = saveEnv("ADN_RUNTIME_MODE", "ADN_GATEWAY_EXECUTOR_SOCKET", "ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE");
  try {
    process.env.ADN_RUNTIME_MODE = "live";
    process.env.ADN_GATEWAY_EXECUTOR_SOCKET = "tcp:9999";
    delete process.env.ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE;
    await assert.rejects(
      () => connectToExistingExecutor(),
      /ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE not set/,
    );
    console.log("✓ connectToExistingExecutor() fails without ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE");
  } catch (err) {
    console.error(`✗ connectToExistingExecutor() missing cap-file check: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// Test 4: health endpoint returns { status: "ok", hasKey: true } without exposing private key
{
  let child;
  try {
    const { child: c, addrSpec, capabilityToken } = await spawnTestExecutorRaw();
    child = c;

    // Write token to a temp file so connectToExistingExecutor can read it
    const tokenFile = path.join(os.tmpdir(), `gw-test-token-${crypto.randomBytes(4).toString("hex")}.bin`);
    fs.writeFileSync(tokenFile, capabilityToken, { mode: 0o600 });

    const saved = saveEnv("ADN_GATEWAY_EXECUTOR_SOCKET", "ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE");
    try {
      process.env.ADN_GATEWAY_EXECUTOR_SOCKET = addrSpec;
      process.env.ADN_GATEWAY_EXECUTOR_CAPABILITY_FILE = tokenFile;

      const client = await connectToExistingExecutor();
      const health = await client.health();

      assert.equal(health.status, "ok", "health.status should be 'ok'");
      assert.equal(health.hasKey, true, "health.hasKey should be true");
      assert.ok(!("privateKey" in health), "privateKey must NOT be in health response");
      assert.ok(!("privateKeyHex" in health), "privateKeyHex must NOT be in health response");

      client.close();
      console.log("✓ health endpoint returns { status: 'ok', hasKey: true } without exposing key");
    } finally {
      restoreEnv(saved);
      try { fs.unlinkSync(tokenFile); } catch {}
    }
  } catch (err) {
    console.error(`✗ health endpoint test: ${err.message}`);
    failures++;
  } finally {
    try { child?.kill("SIGTERM"); } catch {}
  }
}

// Test 5: structural check — connectToExistingExecutor source never reads ADN_GATEWAY_PRIVATE_KEY_HEX
{
  try {
    const src = fs.readFileSync(
      path.join(__dirname, "../src/gateway_client.ts"),
      "utf8",
    );
    // connectToExistingExecutor function body — extract it roughly
    const fnStart = src.indexOf("export async function connectToExistingExecutor");
    const fnEnd = src.indexOf("\nexport function spawnGatewayExecutor", fnStart);
    const fnBody = src.slice(fnStart, fnEnd);

    const hasKeyRead = fnBody.includes("ADN_GATEWAY_PRIVATE_KEY_HEX");
    assert.ok(
      !hasKeyRead,
      "connectToExistingExecutor() must not reference ADN_GATEWAY_PRIVATE_KEY_HEX",
    );
    console.log("✓ connectToExistingExecutor() source contains no reference to ADN_GATEWAY_PRIVATE_KEY_HEX");
  } catch (err) {
    console.error(`✗ structural source check: ${err.message}`);
    failures++;
  }
}

// ─── Summary ─────────────────────────────────────────────────────────────────

if (failures > 0) {
  console.error(`\n${failures} gateway live-mode test(s) FAILED`);
  process.exit(1);
} else {
  console.log("\nAll gateway live-mode tests passed.");
}
