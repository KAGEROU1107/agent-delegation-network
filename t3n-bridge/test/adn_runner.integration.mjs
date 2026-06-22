import assert from "assert/strict";

import { prepareAdnExecution, prepareGatewayKeyBundle, runAdnWithRealDid } from "../src/adn_runner.ts";

const pythonExecutable = process.platform === "win32" ? "python" : "python3";
const tenantDid = "did:t3n:tenant";
const buildConfigId = "adn-build-test";
const authorizationExpiresAt = "2999-01-01T00:00:00+00:00";

const prepared = await prepareAdnExecution(tenantDid, { pythonExecutable });
const gatewayKeyBundle = await prepareGatewayKeyBundle({ pythonExecutable });
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

const result = await runAdnWithRealDid(
  tenantDid,
  prepared,
  teeBundle,
  gatewayKeyBundle,
  { pythonExecutable }
);

assert.equal(result.success, true);
assert.equal(result.tenantDid, tenantDid);
assert.equal(result.uniqueIdentities, 4);
assert.ok(result.recordsProcessed > 0);
assert.ok(result.totalRevenue > 0);
assert.equal(result.qualityPassed, true);
assert.ok(result.qualityScore >= 0.8);

await assert.rejects(
  () =>
    runAdnWithRealDid(
      tenantDid,
      prepared,
      { buildConfigId, processData: teeBundle.processData },
      gatewayKeyBundle,
      { pythonExecutable }
    ),
  /validateQuality TEE authorization bundle is required/
);

const mismatchedBundle = JSON.parse(JSON.stringify(teeBundle));
mismatchedBundle.processData.routed_to = prepared.validator.agentId;

await assert.rejects(
  () => runAdnWithRealDid(tenantDid, prepared, mismatchedBundle, gatewayKeyBundle, { pythonExecutable }),
  /processData routed_to mismatch/
);

const wrongGatewayBundle = { ...gatewayKeyBundle, publicKeyHex: "00".repeat(32) };

await assert.rejects(
  () => runAdnWithRealDid(tenantDid, prepared, teeBundle, wrongGatewayBundle, { pythonExecutable }),
  /Trusted gateway public key mismatch/
);
