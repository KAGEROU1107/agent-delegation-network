import assert from "assert/strict";

import {
  canonicalJson,
  digestCanonicalJson,
  validateReleaseManifestAgainstSchema,
} from "../src/release_proof.ts";

const validManifest = {
  schema_version: "adn-release-proof-v1",
  contract_tail: "adn-processor",
  contract_version: "3.9.2",
  build_commit: "abc1234",
  rustc_version: "rustc 1.0.0",
  trusted_issuer: "58da990a8f4a3a6ca7cb6315d68a140105917352",
  tenant_did: "did:t3n:fixture",
  build_config_id: "adn-build-fixture",
  local_wasm_sha256: "a".repeat(64),
  registration_status: "registered",
  registered_at: "2026-06-23T00:00:00.000Z",
  remote_contract_id: 991,
  raw_registration_response_digest: "b".repeat(64),
  raw_registration_response_path: "registration_response.json",
  first_invocation_digest: "c".repeat(64),
  first_invocation_path: "invocation_receipt.json",
  t3n_evidence_digest: "d".repeat(64),
  t3n_evidence_path: "t3n_evidence.json",
  operator_public_key: "e".repeat(64),
};

const manifest = {
  ...validManifest,
  manifest_digest: digestCanonicalJson(validManifest),
};

validateReleaseManifestAgainstSchema(manifest);

assert.throws(
  () => validateReleaseManifestAgainstSchema({ ...manifest, unexpected_local_claim: "nope" }),
  /schema additional property/
);

assert.equal(
  canonicalJson({ z: ["Ω", { b: 2, a: 1 }], a: "line\u2028separator" }),
  '{"a":"line separator","z":["Ω",{"a":1,"b":2}]}',
);
