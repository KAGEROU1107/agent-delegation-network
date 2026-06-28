import { strict as assert } from "assert";

// We test the compiled JS via ts-node loader
const { T3nAttestedEvidenceVerifier } = await import("../src/t3n_evidence.js");

const FULL_EVIDENCE = {
  tenantDid: "did:t3n:tenant123",
  contractVersion: "adn-processor@v3.9.2",
  invocationId: "inv-abc123",
  workerDid: "did:t3n:worker456",
  action: "PROCESS_DATA",
  requestDigest: "a".repeat(64),
  resultDigest: "b".repeat(64),
  timestamp: new Date().toISOString(),
  platformMaterial: { signed: "receipt-data" },
};

// Test 1: demo mode accepts full evidence
{
  const v = new T3nAttestedEvidenceVerifier("demo");
  const r = v.verify(FULL_EVIDENCE);
  assert.equal(r.valid, true, "demo mode should accept full evidence");
  assert.ok(r.warnings.length > 0, "demo mode should warn about unverified evidence");
}

// Test 2: demo mode accepts with warning (gateway_only-style — missing platformMaterial)
{
  const v = new T3nAttestedEvidenceVerifier("demo");
  const r = v.verify({ ...FULL_EVIDENCE, platformMaterial: {} });
  assert.equal(r.mode, "demo");
}

// Test 3: live mode rejects empty platformMaterial
{
  const v = new T3nAttestedEvidenceVerifier("live");
  const r = v.verify({ ...FULL_EVIDENCE, platformMaterial: {} });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => e.includes("platformMaterial")));
}

// Test 4: live mode rejects missing invocationId
{
  const v = new T3nAttestedEvidenceVerifier("live");
  const { invocationId: _, ...noId } = FULL_EVIDENCE;
  const r = v.verify(noId);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some(e => e.includes("invocationId")));
}

// Test 5: live mode accepts complete evidence
{
  const v = new T3nAttestedEvidenceVerifier("live");
  const r = v.verify(FULL_EVIDENCE);
  assert.equal(r.valid, true, "live mode should accept complete evidence");
  assert.equal(r.errors.length, 0);
}

// Test 6: requireValid throws in live mode with missing fields
{
  const v = new T3nAttestedEvidenceVerifier("live");
  assert.throws(
    () => v.requireValid({ tenantDid: "did:t3n:x" }),
    /T3N evidence verification failed/
  );
}

console.log("t3n_evidence: all 6 tests passed");
