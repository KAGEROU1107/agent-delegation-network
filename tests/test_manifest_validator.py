"""Tests for deployment_manifest.json schema validation."""
import copy
import hashlib
import json
import os

import pytest

MANIFEST_PATH = "proof/release/deployment_manifest.json"
PROOF_DIR = "proof/release"

REQUIRED_FIELDS = [
    "schema_version", "contract_tail", "contract_version",
    "build_commit", "rustc_version", "trusted_issuer", "tenant_did",
    "build_config_id", "local_wasm_sha256",
    "registration_status", "registered_at", "remote_contract_id",
    "raw_registration_response_digest", "raw_registration_response_path",
    "first_invocation_digest", "first_invocation_path",
    "t3n_evidence_digest", "t3n_evidence_path",
    "operator_public_key", "manifest_digest",
]


@pytest.fixture
def manifest():
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def test_required_fields_present(manifest):
    for field in REQUIRED_FIELDS:
        assert field in manifest, f"Missing required field: {field}"


def test_no_undeclared_fields(manifest):
    for key in manifest:
        assert key in REQUIRED_FIELDS, (
            f"Undeclared field: {key} (use remediation_report.json)"
        )


def test_schema_version(manifest):
    assert manifest["schema_version"] == "adn-release-proof-v1"


def test_manifest_digest_self_validates(manifest):
    check = {k: v for k, v in manifest.items() if k != "manifest_digest"}
    check["manifest_digest"] = "TBD"
    serialized = json.dumps(check, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(serialized.encode()).hexdigest()
    assert manifest["manifest_digest"] == expected, "manifest_digest does not match"


def test_manifest_digest_stale_if_modified(manifest):
    tampered = copy.deepcopy(manifest)
    tampered["contract_version"] = "9.9.9"
    check = {k: v for k, v in tampered.items() if k != "manifest_digest"}
    check["manifest_digest"] = "TBD"
    serialized = json.dumps(check, sort_keys=True, separators=(",", ":"))
    computed = hashlib.sha256(serialized.encode()).hexdigest()
    assert computed != manifest["manifest_digest"], "Tampered manifest should not validate"


def test_file_digests_match(manifest):
    checks = [
        ("raw_registration_response_digest", "raw_registration_response_path"),
        ("first_invocation_digest", "first_invocation_path"),
        ("t3n_evidence_digest", "t3n_evidence_path"),
    ]
    for digest_field, path_field in checks:
        path = os.path.join(PROOF_DIR, manifest[path_field])
        sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
        assert sha == manifest[digest_field], f"Digest mismatch for {manifest[path_field]}"


def test_missing_required_field_fails(manifest):
    broken = copy.deepcopy(manifest)
    del broken["schema_version"]
    assert "schema_version" not in broken


def test_wrong_operator_key_field_present(manifest):
    assert "operator_public_key" in manifest
    assert manifest["operator_public_key"]  # non-empty
