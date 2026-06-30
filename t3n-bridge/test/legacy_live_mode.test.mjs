/**
 * Phase 6 — Legacy Live-Mode Guard Tests
 *
 * Verifies that every forbidden legacy private-key path throws immediately
 * when ADN_RUNTIME_MODE=live:
 *
 *   1. runAdnWithRealDid()                      — throws in live mode
 *   2. requireConfiguredGatewayKeyBundleFromEnv() — throws in live mode
 *   3. prepareGatewayKeyBundle()                 — throws in live mode
 *   4. Python restore_gateway_identity()         — live-mode guard present in RUNNER_SCRIPT
 */

import assert from "assert/strict";
import { EventEmitter } from "events";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

/** Mock spawnImpl: simulates a child process that exits with code 1 immediately. */
function mockSpawnFail() {
  const proc = new EventEmitter();
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  setImmediate(() => proc.emit("close", 1));
  return proc;
}

const __dirname = dirname(fileURLToPath(import.meta.url));

import {
  runAdnWithRealDid,
  requireConfiguredGatewayKeyBundleFromEnv,
  prepareGatewayKeyBundle,
} from "../src/adn_runner.ts";

function saveEnv(...keys) {
  const saved = {};
  for (const k of keys) saved[k] = process.env[k];
  return saved;
}

function restoreEnv(saved) {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

let failures = 0;

// ── Test 1: runAdnWithRealDid throws in live mode ──────────────────────────────
{
  const saved = saveEnv("ADN_RUNTIME_MODE");
  try {
    process.env.ADN_RUNTIME_MODE = "live";
    let threw = false;
    try {
      await runAdnWithRealDid("did:example:tenant", {}, {}, {}, {});
    } catch (e) {
      threw = /blocked in live mode/i.test(e.message);
    }
    assert.ok(threw, "runAdnWithRealDid must throw 'blocked in live mode' when ADN_RUNTIME_MODE=live");
    console.log("✓ runAdnWithRealDid() throws in live mode");
  } catch (err) {
    console.error(`✗ runAdnWithRealDid live-mode guard: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// ── Test 2: requireConfiguredGatewayKeyBundleFromEnv throws in live mode ──────
{
  const saved = saveEnv("ADN_RUNTIME_MODE");
  try {
    process.env.ADN_RUNTIME_MODE = "live";
    let threw = false;
    try {
      requireConfiguredGatewayKeyBundleFromEnv();
    } catch (e) {
      threw = /blocked in live mode/i.test(e.message);
    }
    assert.ok(threw, "requireConfiguredGatewayKeyBundleFromEnv must throw 'blocked in live mode' when ADN_RUNTIME_MODE=live");
    console.log("✓ requireConfiguredGatewayKeyBundleFromEnv() throws in live mode");
  } catch (err) {
    console.error(`✗ requireConfiguredGatewayKeyBundleFromEnv live-mode guard: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// ── Test 3: requireConfiguredGatewayKeyBundleFromEnv does NOT throw in demo mode
{
  const saved = saveEnv("ADN_RUNTIME_MODE", "ADN_GATEWAY_PRIVATE_KEY_HEX", "ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX");
  try {
    process.env.ADN_RUNTIME_MODE = "demo";
    // Provide dummy hex values so it doesn't fail on requireHexEnv
    process.env.ADN_GATEWAY_PRIVATE_KEY_HEX = "a".repeat(64);
    process.env.ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX = "b".repeat(64);
    let threwLiveModeGuard = false;
    try {
      requireConfiguredGatewayKeyBundleFromEnv();
    } catch (e) {
      threwLiveModeGuard = /blocked in live mode/i.test(e.message);
    }
    assert.ok(!threwLiveModeGuard, "requireConfiguredGatewayKeyBundleFromEnv must NOT throw live-mode guard in demo mode");
    console.log("✓ requireConfiguredGatewayKeyBundleFromEnv() does not throw live-mode guard in demo mode");
  } catch (err) {
    console.error(`✗ requireConfiguredGatewayKeyBundleFromEnv demo-mode passthrough: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// ── Test 4: prepareGatewayKeyBundle throws in live mode ───────────────────────
{
  const saved = saveEnv("ADN_RUNTIME_MODE");
  try {
    process.env.ADN_RUNTIME_MODE = "live";
    let threw = false;
    try {
      await prepareGatewayKeyBundle({});
    } catch (e) {
      threw = /blocked in live mode/i.test(e.message);
    }
    assert.ok(threw, "prepareGatewayKeyBundle must throw 'blocked in live mode' when ADN_RUNTIME_MODE=live");
    console.log("✓ prepareGatewayKeyBundle() throws in live mode");
  } catch (err) {
    console.error(`✗ prepareGatewayKeyBundle live-mode guard: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// ── Test 5: prepareGatewayKeyBundle does NOT throw live-mode guard in demo mode
{
  const saved = saveEnv("ADN_RUNTIME_MODE");
  try {
    process.env.ADN_RUNTIME_MODE = "demo";
    let threwLiveModeGuard = false;
    try {
      // Use a mock spawn that exits with code 1 — so we get a process error, NOT a live-mode error.
      await prepareGatewayKeyBundle({ spawnImpl: mockSpawnFail });
    } catch (e) {
      threwLiveModeGuard = /blocked in live mode/i.test(e.message);
    }
    assert.ok(!threwLiveModeGuard, "prepareGatewayKeyBundle must NOT throw live-mode guard in demo mode");
    console.log("✓ prepareGatewayKeyBundle() does not throw live-mode guard in demo mode");
  } catch (err) {
    console.error(`✗ prepareGatewayKeyBundle demo-mode passthrough: ${err.message}`);
    failures++;
  } finally {
    restoreEnv(saved);
  }
}

// ── Test 6: Python restore_gateway_identity guard present in RUNNER_SCRIPT ────
// Structural check — confirms the live-mode guard string is embedded in the Python runner.
{
  try {
    const src = readFileSync(join(__dirname, "../src/adn_runner.ts"), "utf-8");
    const guardPattern = "ADN_RUNTIME_MODE.*live.*restore_gateway_identity|restore_gateway_identity.*ADN_RUNTIME_MODE";
    // Check that both the env check and the error message exist near restore_gateway_identity
    const fnIdx = src.indexOf("def restore_gateway_identity");
    assert.ok(fnIdx !== -1, "restore_gateway_identity must be present in RUNNER_SCRIPT");
    const fnBody = src.slice(fnIdx, fnIdx + 500);
    const hasLiveModeCheck = fnBody.includes("ADN_RUNTIME_MODE") && fnBody.includes("live mode");
    assert.ok(
      hasLiveModeCheck,
      "restore_gateway_identity() must contain a live-mode guard (ADN_RUNTIME_MODE check + 'live mode' error)"
    );
    console.log("✓ restore_gateway_identity() contains live-mode guard in RUNNER_SCRIPT");
  } catch (err) {
    console.error(`✗ restore_gateway_identity structural guard check: ${err.message}`);
    failures++;
  }
}

// ── Summary ───────────────────────────────────────────────────────────────────

if (failures > 0) {
  console.error(`\n${failures} legacy live-mode test(s) FAILED`);
  process.exit(1);
} else {
  console.log("\nAll Phase 6 legacy live-mode guard tests passed.");
}
