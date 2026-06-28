import { strict as assert } from "assert";

// We test the compiled JS via ts-node loader
const { T3nAttestedEvidenceVerifier } = await import("../src/t3n_evidence.js");

const BINDING = {
  tenantDid: "did:t3n:tenant123",
  contractTail: "adn-processor",
  contractVersion: "3.9.2",
};

const RECEIPT = {
  delegation_id: "tee-del-abc123",
  status: "ROUTED",
  routed_to: "worker-node",
  credential_enforced: true,
  credential_fingerprint: "8998bbfe255c0a91cecfee1ad5c056d5f784037e0f62c8474f2a74bca1fcf4aa",
  authorization_expires_at: "2026-06-28T10:16:02Z",
  user_signer: "0xb5a5808b97bdef6b053bb110be63af0deec60ed9",
};

const FULL_EVIDENCE = {
  schema_version: "t3n-invocation-evidence-v1",
  tenant_did: "did:t3n:tenant123",
  contract_tail: "adn-processor",
  contract_version: "3.9.2",
  invocation_id: "tee-del-abc123",
  worker_did: "did:t3n:worker456",
  action: "PROCESS_DATA",
  request_digest: "a".repeat(64),
  result_digest: "b".repeat(64),
  issued_at: "2026-06-28T10:16:02Z",
  raw_platform_receipt: RECEIPT,
  platform_credential_fingerprint: "8998bbfe255c0a91cecfee1ad5c056d5f784037e0f62c8474f2a74bca1fcf4aa",
  platform_credential_enforced: true,
  evidence_mode: "t3n_attested",
};

// Test 1: demo mode accepts evidence with NON-ATTESTED warning
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...FULL_EVIDENCE, evidence_mode: "demo" });
  assert.equal(r.valid, true, "demo mode should accept evidence");
  assert.ok(r.warnings.length > 0, "demo mode should warn about NON-ATTESTED evidence");
}

// Test 2: demo mode returns mode="demo"
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify({ ...FULL_EVIDENCE, evidence_mode: "demo" });
  assert.equal(r.mode, "demo");
}

// Test 3: t3n_attested mode rejects missing raw_platform_receipt
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const { raw_platform_receipt: _, ...noReceipt } = FULL_EVIDENCE;
  const r = v.verify(noReceipt);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => e.includes("raw_platform_receipt")));
}

// Test 4: t3n_attested mode rejects missing invocation_id
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const { invocation_id: _, ...noId } = FULL_EVIDENCE;
  const r = v.verify(noId);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => e.includes("invocation_id")));
}

// Test 5: t3n_attested mode accepts complete evidence
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  const r = v.verify(FULL_EVIDENCE);
  assert.equal(r.valid, true, "t3n_attested mode should accept complete evidence");
  assert.equal(r.errors.length, 0);
}

// Test 6: requireValid throws in t3n_attested mode with missing fields
{
  const v = new T3nAttestedEvidenceVerifier(BINDING);
  assert.throws(
    () => v.requireValid({ tenant_did: "did:t3n:x", evidence_mode: "t3n_attested" }),
    /Verification failed/
  );
}

console.log("t3n_evidence: all 6 tests passed");
