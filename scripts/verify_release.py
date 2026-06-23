"""Verify a pinned ADN release proof bundle.

This script is intentionally stricter than scripts/release_gate.py. The release
gate lints claims; this verifier checks that retained proof artifacts bind to
one another before a production-security release can be claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "adn-release-proof-v1.schema.json"

PROOF_INPUT_FILES = [
    "deployment_manifest.json",
    "deployment_manifest.sig",
    "registration_response.json",
    "invocation_receipt.json",
    "t3n_evidence.json",
    "replay_restart_proof.json",
]

REQUIRED_PROOF_FILES = [
    *PROOF_INPUT_FILES,
    "ci_release_sha.json",
]

EXPECTED_CI_GENERATOR = ".github/workflows/release-proof-attest.yml"
EXPECTED_ATTESTED_WORKFLOW = ".github/workflows/release-proof-input.yml"
EXPECTED_ATTESTATION_PHASE = "post_verify_completed_run"


def quote_json_string(value: str) -> str:
    replacements = {
        "\\": "\\\\",
        '"': '\\"',
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
    }
    chars = ['"']
    for char in value:
        if char in replacements:
            chars.append(replacements[char])
        elif ord(char) < 0x20:
            chars.append(f"\\u{ord(char):04x}")
        else:
            chars.append(char)
    chars.append('"')
    return "".join(chars)


def canonical_json(value: Any) -> str:
    if value is None or isinstance(value, bool) or isinstance(value, str):
        if isinstance(value, str):
            return quote_json_string(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int) and not isinstance(value, bool):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RuntimeError("canonical JSON cannot encode non-finite numbers")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(entry) for entry in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys(), key=lambda item: tuple(ord(char) for char in item)):
            if not isinstance(key, str):
                raise RuntimeError("canonical JSON object keys must be strings")
            parts.append(quote_json_string(key) + ":" + canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    raise RuntimeError(f"canonical JSON cannot encode {type(value).__name__}")


def digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require_files(proof_path: Path, names: list[str]) -> None:
    missing = [name for name in names if not (proof_path / name).exists()]
    if missing:
        raise RuntimeError("missing release proof files: " + ", ".join(missing))


def proof_input_file_digests(proof_dir: Path | str) -> list[dict[str, str]]:
    proof_path = Path(proof_dir)
    require_files(proof_path, PROOF_INPUT_FILES)
    return [
        {
            "path": name,
            "sha256": digest_hex((proof_path / name).read_bytes()),
        }
        for name in PROOF_INPUT_FILES
    ]


def compute_proof_input_digest(proof_dir: Path | str) -> str:
    payload = {
        "schema_version": "adn-release-proof-input-v1",
        "files": proof_input_file_digests(proof_dir),
    }
    return digest_hex(canonical_json(payload).encode("utf-8"))


def manifest_body(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "manifest_digest"}


def read_release_schema() -> dict[str, Any]:
    return read_json(SCHEMA_PATH)


def validate_manifest_schema(manifest: dict[str, Any]) -> None:
    schema = read_release_schema()
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    allowed = set(properties.keys())

    for field in required:
        if manifest.get(field) in (None, ""):
            raise RuntimeError(f"deployment manifest schema missing required field: {field}")

    for field in manifest:
        if field not in allowed:
            raise RuntimeError(f"deployment manifest schema additional property not allowed: {field}")

    for field, value in manifest.items():
        rule = properties.get(field, {})
        if "const" in rule and value != rule["const"]:
            raise RuntimeError(f"deployment manifest schema {field} must equal {rule['const']}")
        if "enum" in rule and value not in rule["enum"]:
            raise RuntimeError(f"deployment manifest schema {field} must be one of {', '.join(rule['enum'])}")
        if rule.get("type") == "string":
            if not isinstance(value, str) or value == "":
                raise RuntimeError(f"deployment manifest schema {field} must be a non-empty string")
            if len(value) < int(rule.get("minLength", 0)):
                raise RuntimeError(f"deployment manifest schema {field} is shorter than {rule['minLength']}")
            pattern = rule.get("pattern")
            if pattern and re.fullmatch(pattern, value) is None:
                raise RuntimeError(f"deployment manifest schema {field} does not match {pattern}")
        if rule.get("type") == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise RuntimeError(f"deployment manifest schema {field} must be an integer")
            minimum = rule.get("minimum")
            if minimum is not None and value < minimum:
                raise RuntimeError(f"deployment manifest schema {field} must be >= {minimum}")


def require_fields(label: str, payload: dict[str, Any], fields: list[str]) -> None:
    missing = [field for field in fields if payload.get(field) in (None, "")]
    if missing:
        raise RuntimeError(f"{label} missing required fields: " + ", ".join(missing))


def require_digest(label: str, expected: str, payload: Any) -> None:
    actual = digest_hex(canonical_json(payload).encode("utf-8"))
    if actual != expected:
        raise RuntimeError(f"{label} digest mismatch: expected {expected}, got {actual}")


def verify_manifest_signature(manifest: dict[str, Any], signature_doc: dict[str, Any]) -> None:
    if signature_doc.get("algorithm") != "ed25519":
        raise RuntimeError("deployment_manifest.sig algorithm must be ed25519")

    pinned_public_key = os.environ.get("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX", "").strip().lower()
    if not pinned_public_key:
        raise RuntimeError("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX is required")

    manifest_public_key = str(manifest.get("operator_public_key", "")).strip().lower()
    signature_public_key = str(signature_doc.get("public_key_hex", "")).strip().lower()
    if manifest_public_key != pinned_public_key:
        raise RuntimeError("manifest operator_public_key does not match pinned release key")
    if signature_public_key != pinned_public_key:
        raise RuntimeError("deployment_manifest.sig public_key_hex does not match pinned release key")

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_public_key))
    public_key.verify(
        bytes.fromhex(str(signature_doc.get("signature_hex", ""))),
        canonical_json(manifest_body(manifest)).encode("utf-8"),
    )


def verify_release_inputs(proof_dir: Path | str) -> dict[str, Any]:
    proof_path = Path(proof_dir)
    require_files(proof_path, PROOF_INPUT_FILES)

    manifest = read_json(proof_path / "deployment_manifest.json")
    signature_doc = read_json(proof_path / "deployment_manifest.sig")
    registration_response = read_json(proof_path / "registration_response.json")
    invocation_receipt = read_json(proof_path / "invocation_receipt.json")
    t3n_evidence = read_json(proof_path / "t3n_evidence.json")
    replay_restart_proof = read_json(proof_path / "replay_restart_proof.json")

    validate_manifest_schema(manifest)
    require_fields(
        "deployment manifest",
        manifest,
        [
            "schema_version",
            "build_commit",
            "build_config_id",
            "local_wasm_sha256",
            "remote_contract_id",
            "raw_registration_response_digest",
            "first_invocation_digest",
            "t3n_evidence_digest",
            "operator_public_key",
            "manifest_digest",
        ],
    )
    if manifest.get("schema_version") != "adn-release-proof-v1":
        raise RuntimeError("deployment manifest schema_version must be adn-release-proof-v1")

    require_digest("manifest", str(manifest.get("manifest_digest", "")), manifest_body(manifest))
    require_digest(
        "registration response",
        str(manifest.get("raw_registration_response_digest", "")),
        registration_response,
    )
    require_digest(
        "first invocation",
        str(manifest.get("first_invocation_digest", "")),
        invocation_receipt,
    )
    require_digest(
        "T3N evidence",
        str(manifest.get("t3n_evidence_digest", "")),
        t3n_evidence,
    )
    verify_manifest_signature(manifest, signature_doc)
    if invocation_receipt.get("build_config_id") != manifest.get("build_config_id"):
        raise RuntimeError("invocation receipt build_config_id does not match manifest")
    if replay_restart_proof.get("build_config_id") != manifest.get("build_config_id"):
        raise RuntimeError("replay proof build_config_id does not match manifest")
    if replay_restart_proof.get("request_replay_rejected") is not True:
        raise RuntimeError("replay proof does not show request replay rejection")
    if replay_restart_proof.get("result_replay_rejected") is not True:
        raise RuntimeError("replay proof does not show result replay rejection")
    if replay_restart_proof.get("ledger_persisted_across_restart") is not True:
        raise RuntimeError("replay proof does not show restart persistence")

    return {
        "status": "INPUT_OK",
        "build_commit": manifest.get("build_commit"),
        "build_config_id": manifest.get("build_config_id"),
        "proof_input_digest": compute_proof_input_digest(proof_path),
        "proof_input_files": PROOF_INPUT_FILES,
    }


def verify_release_dir(proof_dir: Path | str) -> dict[str, Any]:
    proof_path = Path(proof_dir)
    require_files(proof_path, REQUIRED_PROOF_FILES)
    input_result = verify_release_inputs(proof_path)
    manifest = read_json(proof_path / "deployment_manifest.json")
    ci_release = read_json(proof_path / "ci_release_sha.json")

    expected_repository = os.environ.get("ADN_RELEASE_REPOSITORY", "KAGEROU1107/agent-delegation-network").strip()
    expected_run_url_prefix = f"https://github.com/{expected_repository}/actions/runs/"
    require_fields(
        "CI release evidence",
        ci_release,
        [
            "evidence_source",
            "generated_by",
            "attested_workflow",
            "attestation_phase",
            "repository",
            "sha",
            "workflow_run_id",
            "workflow_run_url",
            "workflow_conclusion",
            "tests_workflow_run_id",
            "tests_workflow_run_url",
            "tests_workflow_conclusion",
            "tests_workflow_head_sha",
            "tests_workflow_event",
            "tests_workflow_head_branch",
            "artifact_id",
            "artifact_name",
            "artifact_url",
            "artifact_digest",
            "proof_input_digest",
            "proof_input_files",
            "retrieved_at",
        ],
    )
    if ci_release.get("evidence_source") != "github_actions":
        raise RuntimeError("CI release evidence must be generated by GitHub Actions")
    if ci_release.get("generated_by") != EXPECTED_CI_GENERATOR:
        raise RuntimeError(f"CI release evidence generated_by must be {EXPECTED_CI_GENERATOR}")
    if ci_release.get("attested_workflow") != EXPECTED_ATTESTED_WORKFLOW:
        raise RuntimeError(f"CI release evidence attested_workflow must be {EXPECTED_ATTESTED_WORKFLOW}")
    if ci_release.get("attestation_phase") != EXPECTED_ATTESTATION_PHASE:
        raise RuntimeError(f"CI release evidence attestation_phase must be {EXPECTED_ATTESTATION_PHASE}")
    if ci_release.get("repository") != expected_repository:
        raise RuntimeError("CI release evidence repository does not match expected repository")
    if not str(ci_release.get("workflow_run_url", "")).startswith(expected_run_url_prefix):
        raise RuntimeError("CI release evidence workflow_run_url does not match expected repository")
    if not str(ci_release.get("artifact_id", "")).isdigit():
        raise RuntimeError("CI release evidence artifact_id must be the uploaded GitHub artifact ID")
    expected_artifact_url = (
        f"https://github.com/{expected_repository}/actions/runs/"
        f"{ci_release.get('workflow_run_id')}/artifacts/{ci_release.get('artifact_id')}"
    )
    if ci_release.get("artifact_url") != expected_artifact_url:
        raise RuntimeError("CI release evidence artifact_url does not match expected GitHub artifact URL")
    if re.fullmatch(r"[0-9a-f]{64}", str(ci_release.get("artifact_digest", ""))) is None:
        raise RuntimeError("CI release evidence artifact_digest must be the uploaded artifact SHA-256 digest")
    if ci_release.get("proof_input_files") != PROOF_INPUT_FILES:
        raise RuntimeError("CI release evidence proof_input_files do not match verifier input set")
    if ci_release.get("proof_input_digest") != input_result["proof_input_digest"]:
        raise RuntimeError("CI release evidence proof input digest does not match retained proof inputs")
    if ci_release.get("workflow_conclusion") != "success":
        raise RuntimeError("CI status is not successful for release SHA")
    if ci_release.get("sha") != manifest.get("build_commit"):
        raise RuntimeError("release SHA does not match manifest build_commit")
    if not str(ci_release.get("tests_workflow_run_url", "")).startswith(expected_run_url_prefix):
        raise RuntimeError("Tests workflow URL does not match expected repository")
    if not str(ci_release.get("tests_workflow_run_id", "")).isdigit():
        raise RuntimeError("Tests workflow run ID must be the uploaded GitHub workflow run ID")
    if ci_release.get("tests_workflow_conclusion") != "success":
        raise RuntimeError("Tests workflow conclusion is not successful for release SHA")
    if ci_release.get("tests_workflow_head_sha") != manifest.get("build_commit"):
        raise RuntimeError("Tests workflow SHA does not match manifest build_commit")
    if ci_release.get("tests_workflow_head_sha") != ci_release.get("sha"):
        raise RuntimeError("Tests workflow SHA does not match release SHA")
    if ci_release.get("tests_workflow_event") != "push":
        raise RuntimeError("Tests workflow event must be push")
    if ci_release.get("tests_workflow_head_branch") != "main":
        raise RuntimeError("Tests workflow head_branch must be main")

    return {
        "status": "OK",
        "build_commit": input_result.get("build_commit"),
        "build_config_id": input_result.get("build_config_id"),
        "proof_input_digest": input_result.get("proof_input_digest"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an ADN release proof bundle")
    parser.add_argument("proof_dir", nargs="?", default="proof/release")
    parser.add_argument("--input-only", action="store_true", help="verify retained proof inputs without CI attestation")
    args = parser.parse_args()
    result = verify_release_inputs(Path(args.proof_dir)) if args.input_only else verify_release_dir(Path(args.proof_dir))
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
