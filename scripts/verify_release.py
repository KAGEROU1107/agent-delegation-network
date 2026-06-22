"""Verify a pinned ADN release proof bundle.

This script is intentionally stricter than scripts/release_gate.py. The release
gate lints claims; this verifier checks that retained proof artifacts bind to
one another before a production-security release can be claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REQUIRED_PROOF_FILES = [
    "deployment_manifest.json",
    "deployment_manifest.sig",
    "registration_response.json",
    "invocation_receipt.json",
    "replay_restart_proof.json",
    "ci_release_sha.json",
]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_body(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "manifestDigest"}


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


def verify_release_dir(proof_dir: Path | str) -> dict[str, Any]:
    proof_path = Path(proof_dir)
    missing = [name for name in REQUIRED_PROOF_FILES if not (proof_path / name).exists()]
    if missing:
        raise RuntimeError("missing release proof files: " + ", ".join(missing))

    manifest = read_json(proof_path / "deployment_manifest.json")
    signature_doc = read_json(proof_path / "deployment_manifest.sig")
    registration_response = read_json(proof_path / "registration_response.json")
    invocation_receipt = read_json(proof_path / "invocation_receipt.json")
    replay_restart_proof = read_json(proof_path / "replay_restart_proof.json")
    ci_release = read_json(proof_path / "ci_release_sha.json")

    require_digest("manifest", str(manifest.get("manifestDigest", "")), manifest_body(manifest))
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
    verify_manifest_signature(manifest, signature_doc)

    if ci_release.get("status") != "success":
        raise RuntimeError("CI status is not successful for release SHA")
    if ci_release.get("sha") != manifest.get("build_commit"):
        raise RuntimeError("release SHA does not match manifest build_commit")
    if invocation_receipt.get("build_config_id") != manifest.get("build_config_id"):
        raise RuntimeError("invocation receipt build_config_id does not match manifest")
    if replay_restart_proof.get("build_config_id") != manifest.get("build_config_id"):
        raise RuntimeError("replay proof build_config_id does not match manifest")
    if replay_restart_proof.get("requestReplayRejected") is not True:
        raise RuntimeError("replay proof does not show request replay rejection")
    if replay_restart_proof.get("resultReplayRejected") is not True:
        raise RuntimeError("replay proof does not show result replay rejection")
    if replay_restart_proof.get("ledgerPersistedAcrossRestart") is not True:
        raise RuntimeError("replay proof does not show restart persistence")

    return {
        "status": "OK",
        "build_commit": manifest.get("build_commit"),
        "build_config_id": manifest.get("build_config_id"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an ADN release proof bundle")
    parser.add_argument("proof_dir", nargs="?", default="proof/release")
    args = parser.parse_args()
    result = verify_release_dir(Path(args.proof_dir))
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
