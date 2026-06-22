import assert from "assert/strict";
import { EventEmitter } from "events";
import { PassThrough } from "stream";
import { readFileSync } from "fs";

import { runAdnWithRealDid } from "../src/adn_runner.ts";

const stdout = new PassThrough();
const stderr = new PassThrough();
const fakeProc = new EventEmitter();
fakeProc.stdout = stdout;
fakeProc.stderr = stderr;

let capturedScript = "";
let capturedEnv;
let capturedPython = "";

const spawnImpl = (python, args, options) => {
  capturedPython = python;
  capturedEnv = options.env;
  capturedScript = readFileSync(args[0], "utf-8");
  queueMicrotask(() => {
    stdout.end(JSON.stringify({
      success: true,
      tenantDid: "did:t3n:tenant",
      coordinatorDid: "did:key:coordinator",
      uniqueIdentities: 4,
      recordsProcessed: 2,
      totalRevenue: 123.45,
      avgValue: 61.72,
      qualityScore: 0.91,
      qualityPassed: true,
    }));
    stderr.end("");
    fakeProc.emit("close", 0);
  });
  return fakeProc;
};

const result = await runAdnWithRealDid(
  "0xdeadbeef",
  "did:t3n:tenant",
  {
    buildConfigId: "adn-build-test",
    processData: {
      delegation_id: "tee-del-process",
      status: "ROUTED",
      routed_to: "worker-1",
      credential_fingerprint: "cred-process",
      credential_enforced: true,
      build_config_id: "adn-build-test",
    },
    validateQuality: {
      delegation_id: "tee-del-validate",
      status: "ROUTED",
      routed_to: "validator-1",
      credential_fingerprint: "cred-validate",
      credential_enforced: true,
      build_config_id: "adn-build-test",
    },
  },
  { spawnImpl, pythonExecutable: "python3" }
);

assert.equal(capturedPython, "python3");
assert.equal(
  capturedEnv.TEE_AUTHORIZATION_BUNDLE_JSON,
  JSON.stringify({
    buildConfigId: "adn-build-test",
    processData: {
      delegation_id: "tee-del-process",
      status: "ROUTED",
      routed_to: "worker-1",
      credential_fingerprint: "cred-process",
      credential_enforced: true,
      build_config_id: "adn-build-test",
    },
    validateQuality: {
      delegation_id: "tee-del-validate",
      status: "ROUTED",
      routed_to: "validator-1",
      credential_fingerprint: "cred-validate",
      credential_enforced: true,
      build_config_id: "adn-build-test",
    },
  })
);
assert.ok(capturedScript.includes("expected_gateway_public_key_hex=auth1['gateway_public_key_hex']"));
assert.ok(capturedScript.includes("expected_gateway_public_key_hex=auth2['gateway_public_key_hex']"));
assert.ok(capturedScript.includes("TEE_AUTHORIZATION_BUNDLE_JSON"));
assert.equal(result.success, true);
assert.equal(result.recordsProcessed, 2);
assert.equal(result.qualityPassed, true);
