/**
 * Phase 3 evidence verifier tests — full acceptance matrix
 *
 * Covers all live-mode rejection scenarios, demo mode behaviour,
 * and buildEvidenceFromReceipt() factory function.
 */
import { strict as assert } from "assert";

const { T3nAttestedEvidenceVerifier, buildEvidenceFromReceipt } =
  await import("../src/t3n_evidence.js");

const TENANT_DID = "did:t3n:ad146e6861ac408900af7ece1f6e90976dad3a02";
const CONTRACT_TAIL = "adn-processor";
const CONTRACT_VERSION = "3.9.2";

const BINDING = {
  tenantDid: TENANT_DID,
  contractTail: CONTRACT_TAIL,
  contractVersion: CONTRACT_VERSION,
};

const SAMPLE_RECEIPT = {
  delegation_id: "tee-del-2c970ed3f7ff0514a6069aad8ed96b05",
  status: "ROUTED",
  routed_to: "c096c6f873f6",
  credential_enforced: true,
  credential_fingerprint: "8998bbfe255c0a91cecfee1ad5c056d5f784037e0f62c8474f2a74bca1fcf4aa",
  authorization_expires_at: "2026-06-28T10:16:02Z",
  user_signer: "0xb5a5808b97bdef6b053bb110be63af0deec60ed9",
};

const VALID_EVIDENCE = {
  schema_version: "t3n-invocation-evidence-v1",
  tenant_did: TENANT_DID,
  contract_tail: CONTRACT_TAIL,
  contract_version: CONTRACT_VERSION,
  invocation_id: SAMPLE_RECEIPT.delegation_id,
  worker_did: "c096c6f873f6",
  action: "PROCESS_DATA",
  request_digest: "a".repeat(64),
  result_digest: "b".repeat(64),
  issued_at: SAMPLE_RECEIPT.authorization_expires_at,
  raw_platform_receipt: SAMPLE_RECEIPT,
  platform_credential_fingerprint: SAMPLE_RECEIPT.credential_fingerprint,
  platform_credential_enforced: true,
  evidence_mode: "t3n_attested",
};

let passed = 0;

// ── Test 1: valid t3n_attested evidence accepted ─────────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify(VALID_EVIDENCE);
  assert.equal(r.valid, true, "Test 1: valid t3n_attested evidence should be accepted");
  assert.equal(r.errors.length, 0, "Test 1: should have no errors");
  assert.equal(r.mode, "t3n_attested", "Test 1: mode should be t3n_attested");
  passed++;
}

// ── Test 2: unsigned evidence (no platform_signature) accepted with warning ──
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const evidenceWithoutSig = { ...VALID_EVIDENCE };
  delete evidenceWithoutSig.platform_signature;
  const r = v.verify(evidenceWithoutSig);
  assert.equal(r.valid, true, "Test 2: unsigned evidence should be accepted (T3N key not yet published)");
  assert.ok(
    r.warnings.some(w => w.includes("platform_signature") || w.includes("T3N")),
    "Test 2: should warn about missing signature"
  );
  assert.ok(
    r.pending_checks.some(p => p.includes("cryptographic signature") || p.includes("trust anchor")),
    "Test 2: pending_checks should document crypto signature as pending"
  );
  passed++;
}

// ── Test 3: wrong tenant_did rejected ────────────────────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...VALID_EVIDENCE, tenant_did: "did:t3n:wrong-tenant" });
  assert.equal(r.valid, false, "Test 3: wrong tenant_did should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("tenant_did")),
    "Test 3: error should mention tenant_did"
  );
  passed++;
}

// ── Test 4: wrong contract_tail rejected ─────────────────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...VALID_EVIDENCE, contract_tail: "wrong-contract" });
  assert.equal(r.valid, false, "Test 4: wrong contract_tail should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("contract_tail")),
    "Test 4: error should mention contract_tail"
  );
  passed++;
}

// ── Test 5: wrong contract_version rejected ──────────────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...VALID_EVIDENCE, contract_version: "9.9.9" });
  assert.equal(r.valid, false, "Test 5: wrong contract_version should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("contract_version")),
    "Test 5: error should mention contract_version"
  );
  passed++;
}

// ── Test 6: missing invocation_id rejected ───────────────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const { invocation_id: _, ...noInvId } = VALID_EVIDENCE;
  const r = v.verify(noInvId);
  assert.equal(r.valid, false, "Test 6: missing invocation_id should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("invocation_id")),
    "Test 6: error should mention invocation_id"
  );
  passed++;
}

// ── Test 7: missing raw_platform_receipt rejected ────────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const { raw_platform_receipt: _, ...noReceipt } = VALID_EVIDENCE;
  const r = v.verify(noReceipt);
  assert.equal(r.valid, false, "Test 7: missing raw_platform_receipt should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("raw_platform_receipt")),
    "Test 7: error should mention raw_platform_receipt"
  );
  passed++;
}

// ── Test 8: missing platform_credential_fingerprint rejected ─────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const { platform_credential_fingerprint: _, ...noFingerprint } = VALID_EVIDENCE;
  const r = v.verify(noFingerprint);
  assert.equal(r.valid, false, "Test 8: missing platform_credential_fingerprint should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("platform_credential_fingerprint")),
    "Test 8: error should mention platform_credential_fingerprint"
  );
  passed++;
}

// ── Test 9: platform_credential_enforced=false rejected ──────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...VALID_EVIDENCE, platform_credential_enforced: false });
  assert.equal(r.valid, false, "Test 9: platform_credential_enforced=false should be rejected");
  assert.ok(
    r.errors.some(e => e.includes("platform_credential_enforced")),
    "Test 9: error should mention platform_credential_enforced"
  );
  passed++;
}

// ── Test 10: gateway_only mode rejected in live mode ─────────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...VALID_EVIDENCE, evidence_mode: "gateway_only" });
  assert.equal(r.valid, false, "Test 10: gateway_only evidence should be rejected");
  assert.equal(r.mode, "gateway_only", "Test 10: mode should be gateway_only");
  assert.ok(
    r.errors.some(e => e.includes("gateway_only")),
    "Test 10: error should mention gateway_only"
  );
  passed++;
}

// ── Test 11: demo mode accepted with NON-ATTESTED warning ────────────────────
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ evidence_mode: "demo" });
  assert.equal(r.valid, true, "Test 11: demo mode should be accepted");
  assert.equal(r.mode, "demo", "Test 11: mode should be demo");
  assert.ok(
    r.warnings.some(w => w.includes("NON-ATTESTED") || w.includes("demo")),
    "Test 11: should warn with NON-ATTESTED label"
  );
  assert.equal(r.errors.length, 0, "Test 11: demo mode should have no errors");
  passed++;
}

// ── Test 12: buildEvidenceFromReceipt() produces correct structure ────────────
{
  const evidence = buildEvidenceFromReceipt(SAMPLE_RECEIPT, {
    tenantDid: TENANT_DID,
    contractTail: CONTRACT_TAIL,
    contractVersion: CONTRACT_VERSION,
    workerDid: "c096c6f873f6",
    action: "PROCESS_DATA",
    requestDigest: "a".repeat(64),
    resultDigest: "b".repeat(64),
  });

  assert.equal(evidence.schema_version, "t3n-invocation-evidence-v1", "Test 12: schema_version");
  assert.equal(evidence.tenant_did, TENANT_DID, "Test 12: tenant_did");
  assert.equal(evidence.contract_tail, CONTRACT_TAIL, "Test 12: contract_tail");
  assert.equal(evidence.contract_version, CONTRACT_VERSION, "Test 12: contract_version");
  assert.equal(evidence.invocation_id, SAMPLE_RECEIPT.delegation_id, "Test 12: invocation_id = delegation_id");
  assert.equal(evidence.platform_credential_fingerprint, SAMPLE_RECEIPT.credential_fingerprint, "Test 12: fingerprint");
  assert.equal(evidence.platform_credential_enforced, true, "Test 12: credential_enforced");
  assert.equal(evidence.evidence_mode, "t3n_attested", "Test 12: evidence_mode");
  assert.deepEqual(evidence.raw_platform_receipt, SAMPLE_RECEIPT, "Test 12: raw receipt preserved unchanged");

  // Verify it passes the verifier
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify(evidence);
  assert.equal(r.valid, true, "Test 12: built evidence should pass verification");
  passed++;
}

console.log(`t3n_evidence_v2: all ${passed} tests passed`);
