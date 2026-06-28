#!/usr/bin/env python3
"""
Validate proof/release/deployment_manifest.json against adn-release-proof-v1 schema.
Also validates that file digests match declared values.
Usage: python scripts/validate_manifest.py [proof-dir]
"""
import sys
import json
import hashlib
import os

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


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def validate(proof_dir):
    manifest_path = os.path.join(proof_dir, "deployment_manifest.json")

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    errors = []

    # 1. Required fields
    for field in REQUIRED_FIELDS:
        if field not in manifest:
            errors.append(f"Missing required field: {field}")

    # 2. schema_version constant
    if manifest.get("schema_version") != "adn-release-proof-v1":
        errors.append(
            f"schema_version must be 'adn-release-proof-v1', got: {manifest.get('schema_version')}"
        )

    # 3. No undeclared fields
    for key in manifest:
        if key not in REQUIRED_FIELDS:
            errors.append(
                f"Undeclared field (use remediation_report.json for extra data): {key}"
            )

    # 4. File digest validation
    digest_checks = [
        ("raw_registration_response_digest", "raw_registration_response_path"),
        ("first_invocation_digest", "first_invocation_path"),
        ("t3n_evidence_digest", "t3n_evidence_path"),
    ]
    for digest_field, path_field in digest_checks:
        if digest_field in manifest and path_field in manifest:
            file_path = os.path.join(proof_dir, manifest[path_field])
            if os.path.exists(file_path):
                actual = sha256_file(file_path)
                if actual != manifest[digest_field]:
                    errors.append(
                        f"Digest mismatch for {manifest[path_field]}: "
                        f"declared={manifest[digest_field]}, actual={actual}"
                    )
            else:
                errors.append(f"File not found: {file_path}")

    # 5. Manifest self-digest
    if "manifest_digest" in manifest:
        check = dict(manifest)
        check["manifest_digest"] = "TBD"
        serialized = json.dumps(check, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(serialized.encode()).hexdigest()
        if expected != manifest["manifest_digest"]:
            errors.append(
                f"manifest_digest mismatch: "
                f"declared={manifest['manifest_digest']}, computed={expected}"
            )

    return errors


def main():
    proof_dir = sys.argv[1] if len(sys.argv) > 1 else "proof/release"
    errors = validate(proof_dir)
    if errors:
        print(f"[FAIL] Manifest validation failed with {len(errors)} error(s):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("[PASS] deployment_manifest.json is valid against adn-release-proof-v1")
        sys.exit(0)


if __name__ == "__main__":
    main()
