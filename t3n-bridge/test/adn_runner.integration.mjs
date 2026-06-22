import assert from "assert/strict";

import { prepareAdnExecution, runAdnWithRealDid } from "../src/adn_runner.ts";

const pythonExecutable = process.platform === "win32" ? "python" : "python3";
const tenantDid = "did:t3n:tenant";
const buildConfigId = "adn-build-test";
const apiKey = "0x" + "11".repeat(32);

const prepared = await prepareAdnExecution(tenantDid, { pythonExecutable });
const teeBundle = {
  buildConfigId,
  processData: {
    delegation_id: "tee-del-process",
    status: "ROUTED",
    routed_to: prepared.worker1.agentId,
    credential_fingerprint: "cred-process",
    credential_enforced: true,
    build_config_id: buildConfigId,
  },
  validateQuality: {
    delegation_id: "tee-del-validate",
    status: "ROUTED",
    routed_to: prepared.validator.agentId,
    credential_fingerprint: "cred-validate",
    credential_enforced: true,
    build_config_id: buildConfigId,
  },
};

const result = await runAdnWithRealDid(
  apiKey,
  tenantDid,
  prepared,
  teeBundle,
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
      apiKey,
      tenantDid,
      prepared,
      { buildConfigId, processData: teeBundle.processData },
      { pythonExecutable }
    ),
  /validateQuality TEE authorization bundle is required/
);

const mismatchedBundle = JSON.parse(JSON.stringify(teeBundle));
mismatchedBundle.processData.routed_to = prepared.validator.agentId;

await assert.rejects(
  () => runAdnWithRealDid(apiKey, tenantDid, prepared, mismatchedBundle, { pythonExecutable }),
  /processData routed_to mismatch/
);
