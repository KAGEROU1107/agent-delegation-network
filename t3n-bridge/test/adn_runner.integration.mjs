import assert from "assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

import { prepareAdnExecution, prepareGatewayKeyBundle, runAdnWithRealDid } from "../src/adn_runner.ts";

const pythonExecutable = process.platform === "win32" ? "python" : "python3";
const tenantDid = "did:t3n:tenant";
const buildConfigId = "adn-build-test";
const authorizationExpiresAt = "2999-01-01T00:00:00+00:00";

const prepared = await prepareAdnExecution(tenantDid, { pythonExecutable });
const gatewayKeyBundle = await prepareGatewayKeyBundle({ pythonExecutable });
const previousRuntimeMode = process.env.ADN_RUNTIME_MODE;
const replayLedgerDir = mkdtempSync(join(tmpdir(), "adn-persistent-replay-"));
const replayKeyFile = join(replayLedgerDir, "replay-hmac.key");
writeFileSync(replayKeyFile, "33".repeat(32), { encoding: "utf-8", mode: 0o600 });

assert.equal("gateway" in prepared, false);

const teeBundle = {
  buildConfigId,
  processData: {
    delegation_id: "tee-del-process",
    status: "ROUTED",
    routed_to: prepared.worker1.agentId,
    credential_fingerprint: "cred-process",
    credential_enforced: true,
    build_config_id: buildConfigId,
    authorization_expires_at: authorizationExpiresAt,
  },
  validateQuality: {
    delegation_id: "tee-del-validate",
    status: "ROUTED",
    routed_to: prepared.validator.agentId,
    credential_fingerprint: "cred-validate",
    credential_enforced: true,
    build_config_id: buildConfigId,
    authorization_expires_at: authorizationExpiresAt,
  },
};

try {
  // Phase 4: runAdnWithRealDid is blocked in live mode — must throw immediately.
  process.env.ADN_RUNTIME_MODE = "live";
  process.env.ADN_REPLAY_LEDGER_DIR = replayLedgerDir;
  process.env.ADN_REPLAY_LEDGER_KEY_REF = `file:${replayKeyFile}`;
  delete process.env.ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX;

  await assert.rejects(
    () => runAdnWithRealDid(tenantDid, prepared, teeBundle, gatewayKeyBundle, { pythonExecutable }),
    /blocked in live mode/,
    "runAdnWithRealDid must be blocked in live mode"
  );

  // Demo mode: runAdnWithRealDid is still permitted.
  delete process.env.ADN_REPLAY_LEDGER_DIR;
  delete process.env.ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX;
  delete process.env.ADN_REPLAY_LEDGER_KEY_REF;
  process.env.ADN_RUNTIME_MODE = "demo";

  const demoResult = await runAdnWithRealDid(
    tenantDid,
    prepared,
    teeBundle,
    gatewayKeyBundle,
    { pythonExecutable }
  );
  assert.equal(demoResult.success, true);
  assert.equal(demoResult.replayMode, "non-durable-demo");
  assert.equal(demoResult.tenantDid, tenantDid);
  assert.equal(demoResult.uniqueIdentities, 4);
  assert.ok(demoResult.recordsProcessed > 0);
  assert.ok(demoResult.totalRevenue > 0);
  assert.equal(demoResult.qualityPassed, true);
  assert.ok(demoResult.qualityScore >= 0.8);
} finally {
  if (previousRuntimeMode === undefined) {
    delete process.env.ADN_RUNTIME_MODE;
  } else {
    process.env.ADN_RUNTIME_MODE = previousRuntimeMode;
  }
  delete process.env.ADN_REPLAY_LEDGER_DIR;
  delete process.env.ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX;
  delete process.env.ADN_REPLAY_LEDGER_KEY_REF;
  rmSync(replayLedgerDir, { recursive: true, force: true });
}
