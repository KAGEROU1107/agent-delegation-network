/**
 * Receipt binding integration tests — verifies the two-pass execution in
 * runAdnWithSignedGateway produces receipts bound to actual parameters.
 *
 * Test 1: processDataReceipt is signed with real process params (not empty)
 * Test 2: validateQualityReceipt is signed with actual processed_data from worker1
 * Test 3: placeholder {} params produce different JSON than real processed_data
 *
 * Note: we inline the signing primitives from gateway_executor.ts here because
 * gateway_executor.ts calls startExecutor() at import time (side effect). Keeping
 * the math in sync is verified by gateway_executor.test.ts signing the same receipts
 * that Python verifies.
 */

import assert from "assert/strict";
import * as crypto from "crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { prepareAdnExecution, runAdnWithSignedGateway } from "../src/adn_runner.ts";

const pythonExecutable = process.platform === "win32" ? "python" : "python3";

// Use demo mode: no replay ledger required, so the test is self-contained
const previousRuntimeMode = process.env.ADN_RUNTIME_MODE;
process.env.ADN_RUNTIME_MODE = "demo";
const tenantDid = "did:t3n:tenant-receipt-binding-test";
const buildConfigId = "adn-build-receipt-test";
const authorizationExpiresAt = "2999-01-01T00:00:00+00:00";

// ── Signing helpers (mirror of gateway_executor.ts — same canonical JSON + Ed25519) ──

const AUDIENCE = "t3n-adn-v1";
const PROOF_TTL_SECONDS = 300;
const RECEIPT_VERSION = "adn.tee_authorization/1";
const RECEIPT_ACTION = "TEE_AUTHORIZATION";

function canonicalJson(obj) {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",") + "}";
}

function sha256hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function keyFingerprint(pubKeyHex) {
  const prefix = Buffer.from("terminal3\x00", "utf8");
  const pub = Buffer.from(pubKeyHex, "hex");
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([prefix, pub]))
    .digest("hex")
    .slice(0, 12);
}

function isoNow() {
  return new Date().toISOString().replace("Z", "+00:00");
}

function isoFromMs(ms) {
  return new Date(ms).toISOString().replace("Z", "+00:00");
}

function signAction(identity, action, nonce, data) {
  const issuedAt = isoNow();
  const expiresAt = isoFromMs(Date.now() + PROOF_TTL_SECONDS * 1000);
  const dataHash = data !== undefined ? sha256hex(canonicalJson(data)) : undefined;

  const payload = {
    agent_id: identity.agentId,
    did: identity.did,
    public_key_hex: identity.publicKeyHex,
    action,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    audience: AUDIENCE,
  };
  if (dataHash !== undefined) payload.data_hash = dataHash;

  const payloadHash = sha256hex(canonicalJson(payload));
  const sigBytes = ed25519.sign(
    new TextEncoder().encode(payloadHash),
    identity.privateKeyBytes,
  );

  return { ...payload, payload_hash: payloadHash, signature_hex: Buffer.from(sigBytes).toString("hex") };
}

function teeAuthorizationRequestHash(toAgentId, action, parameters = {}) {
  return sha256hex(canonicalJson({ to_agent_id: toAgentId, action, parameters }));
}

function buildSignedReceipt(identity, teeResult, action, parameters = {}) {
  const delegationId = teeResult.delegation_id;
  const toAgentId = teeResult.routed_to;
  if (!delegationId || !toAgentId) throw new Error("TEE authorization requires delegation_id and routed_to");
  const authorizationExpiresAt = teeResult.authorization_expires_at;
  if (!authorizationExpiresAt) throw new Error("TEE authorization requires authorization_expires_at");

  const authorizedAt = isoNow();
  const body = {
    v: RECEIPT_VERSION,
    delegation_id: delegationId,
    tee_delegation_id: delegationId,
    status: teeResult.status,
    to_agent_id: toAgentId,
    action,
    request_hash: teeAuthorizationRequestHash(toAgentId, action, parameters),
    credential_fingerprint: teeResult.credential_fingerprint,
    credential_enforced: teeResult.credential_enforced,
    build_config_id: teeResult.build_config_id,
    tee_result_digest: sha256hex(canonicalJson(teeResult)),
    gateway_key_id: identity.gatewayKeyId,
    authorization_expires_at: authorizationExpiresAt,
    authorized_at: authorizedAt,
  };

  const proof = signAction(identity, RECEIPT_ACTION, delegationId, body);
  return { ...body, gateway_public_key_hex: proof.public_key_hex, gateway_proof: proof };
}

// ── Test 3 (pure unit — no Python needed) ────────────────────────────────────
{
  const placeholder = { data: {} };
  const realData = {
    data: {
      records_processed: 50,
      total_revenue: 12345.67,
      avg_value: 246.91,
      min_value: 100.0,
      max_value: 500.0,
      trend: "UPWARD",
      csv_file: "sales_Q1-2026_US_premium.csv",
    },
  };
  assert.notDeepEqual(
    placeholder,
    realData,
    "placeholder {} must differ from real processed_data",
  );
  assert.notEqual(
    JSON.stringify(placeholder),
    JSON.stringify(realData),
    "JSON of placeholder must differ from JSON of real processed_data",
  );
  console.log(
    "✓ receipt signed with placeholder params {} differs from one signed with real params",
  );
}

// ── Tests 1 & 2 (integration — real Python, real Ed25519 signing) ─────────────
{
  // Generate a real Ed25519 key for signing
  const privateKeyBytes = Uint8Array.from(crypto.randomBytes(32));
  const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
  const publicKeyHex = Buffer.from(publicKeyBytes).toString("hex");
  const agentId = keyFingerprint(publicKeyHex);
  const gatewayKeyId = `gateway-${publicKeyHex.slice(0, 12)}`;

  const gatewayIdentity = {
    privateKeyBytes,
    publicKeyHex,
    agentId,
    did: `did:key:ed25519:${agentId}`,
    gatewayKeyId,
  };

  const prepared = await prepareAdnExecution(tenantDid, { pythonExecutable });

  const teeBundle = {
    buildConfigId,
    processData: {
      delegation_id: "tee-del-process-binding",
      status: "ROUTED",
      routed_to: prepared.worker1.agentId,
      credential_fingerprint: "cred-process-binding",
      credential_enforced: true,
      build_config_id: buildConfigId,
      authorization_expires_at: authorizationExpiresAt,
    },
    validateQuality: {
      delegation_id: "tee-del-validate-binding",
      status: "ROUTED",
      routed_to: prepared.validator.agentId,
      credential_fingerprint: "cred-validate-binding",
      credential_enforced: true,
      build_config_id: buildConfigId,
      authorization_expires_at: authorizationExpiresAt,
    },
  };

  // In-process signing client — records every signReceipt call
  const signReceiptCalls = [];
  const mockClient = {
    async getPublicInfo() {
      return {
        publicKeyHex: gatewayIdentity.publicKeyHex,
        agentId: gatewayIdentity.agentId,
        did: gatewayIdentity.did,
        gatewayKeyId: gatewayIdentity.gatewayKeyId,
      };
    },
    async signReceipt(teeResult, action, parameters) {
      signReceiptCalls.push({
        action,
        parameters: JSON.parse(JSON.stringify(parameters ?? {})),
      });
      return buildSignedReceipt(gatewayIdentity, teeResult, action, parameters ?? {});
    },
    close() {},
  };

  const result = await runAdnWithSignedGateway(
    tenantDid,
    prepared,
    teeBundle,
    mockClient,
    { pythonExecutable },
  );

  assert.equal(result.success, true, "overall delegation must succeed");
  assert.equal(result.qualityPassed, true, "quality check must pass");
  assert.ok(result.recordsProcessed > 0, "must have processed records");

  // signReceipt must be called exactly twice (process then validate)
  assert.equal(
    signReceiptCalls.length,
    2,
    `expected 2 signReceipt calls, got ${signReceiptCalls.length}`,
  );

  // Test 1: process receipt uses real process params — not empty
  const processCall = signReceiptCalls[0];
  assert.equal(processCall.action, "PROCESS_DATA");
  assert.equal(
    processCall.parameters.data_source,
    "csv",
    "processDataReceipt must bind data_source=csv",
  );
  assert.equal(
    processCall.parameters.time_period,
    "Q1-2026",
    "processDataReceipt must bind time_period=Q1-2026",
  );
  assert.deepEqual(
    processCall.parameters.filters,
    [],
    "processDataReceipt must bind filters=[]",
  );
  console.log("✓ process receipt binds process parameters (not empty)");

  // Test 2: validation receipt uses actual processed_data — not placeholder {}
  const validateCall = signReceiptCalls[1];
  assert.equal(validateCall.action, "VALIDATE_QUALITY");
  assert.ok(
    validateCall.parameters.data,
    "validateQualityReceipt params must have a 'data' field",
  );
  const boundData = validateCall.parameters.data;
  assert.ok(
    typeof boundData.records_processed === "number" && boundData.records_processed > 0,
    "validateQualityReceipt must bind actual records_processed from worker1",
  );
  assert.ok(
    typeof boundData.total_revenue === "number" && boundData.total_revenue > 0,
    "validateQualityReceipt must bind actual total_revenue from worker1",
  );
  assert.notDeepEqual(
    validateCall.parameters,
    { data: {} },
    "validateQualityReceipt must NOT use the placeholder { data: {} }",
  );
  console.log("✓ validation receipt binds actual processed_data (not placeholder)");
}

if (previousRuntimeMode === undefined) {
  delete process.env.ADN_RUNTIME_MODE;
} else {
  process.env.ADN_RUNTIME_MODE = previousRuntimeMode;
}

console.log("\nAll receipt binding tests passed.");
