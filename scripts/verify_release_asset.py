"""Verify durable GitHub Release proof assets.

scripts.verify_release_remote proves the short-lived GitHub Actions artifact.
This verifier checks the durable release asset directory that remains after the
Actions artifact retention window expires.
"""

from __future__ import annotations

import argparse
import io
import os
import posixpath
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_release


RELEASE_ASSET_PAYLOAD_FILES = [
    "proof-input.tar",
    "ci_release_sha.json",
    "remote_verification_result.json",
    "workflow_metadata.json",
]
RELEASE_ASSET_MANIFEST = "release_asset_manifest.json"
RELEASE_ASSET_SIGNATURE = "release_asset_manifest.sig"
REQUIRED_RELEASE_ASSET_FILES = [
    *RELEASE_ASSET_PAYLOAD_FILES,
    RELEASE_ASSET_MANIFEST,
    RELEASE_ASSET_SIGNATURE,
]
EXPECTED_RELEASE_ASSET_SCHEMA = "adn-release-asset-manifest-v1"


def read_json(path: Path) -> Any:
    return verify_release.read_json(path)


def release_asset_manifest_body(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "manifest_digest"}


def require_release_asset_files(asset_path: Path) -> None:
    missing = [name for name in REQUIRED_RELEASE_ASSET_FILES if not (asset_path / name).is_file()]
    if missing:
        raise RuntimeError("missing release asset files: " + ", ".join(missing))

    expected = set(REQUIRED_RELEASE_ASSET_FILES)
    for entry in asset_path.iterdir():
        if entry.name.startswith("."):
            continue
        if entry.is_symlink() or not entry.is_file():
            raise RuntimeError(f"unexpected release asset file: {entry.name}")
        if entry.name not in expected:
            raise RuntimeError(f"unexpected release asset file: {entry.name}")


def require_fields(label: str, payload: dict[str, Any], fields: list[str]) -> None:
    missing = [field for field in fields if payload.get(field) in (None, "")]
    if missing:
        raise RuntimeError(f"{label} missing required fields: " + ", ".join(missing))


def verify_manifest_signature(manifest: dict[str, Any], signature_doc: dict[str, Any]) -> None:
    if signature_doc.get("algorithm") != "ed25519":
        raise RuntimeError("release_asset_manifest.sig algorithm must be ed25519")

    pinned_public_key = os.environ.get("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX", "").strip().lower()
    if not pinned_public_key:
        raise RuntimeError("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX is required")

    manifest_public_key = str(manifest.get("operator_public_key", "")).strip().lower()
    signature_public_key = str(signature_doc.get("public_key_hex", "")).strip().lower()
    if manifest_public_key != pinned_public_key:
        raise RuntimeError("release asset manifest operator_public_key does not match pinned release key")
    if signature_public_key != pinned_public_key:
        raise RuntimeError("release_asset_manifest.sig public_key_hex does not match pinned release key")

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_public_key))
    try:
        public_key.verify(
            bytes.fromhex(str(signature_doc.get("signature_hex", ""))),
            verify_release.canonical_json(release_asset_manifest_body(manifest)).encode("utf-8"),
        )
    except InvalidSignature as exc:
        raise RuntimeError("release_asset_manifest.sig signature verification failed") from exc


def validate_release_asset_manifest(manifest: dict[str, Any]) -> None:
    require_fields(
        "release asset manifest",
        manifest,
        [
            "schema_version",
            "repository",
            "sha",
            "release_tag",
            "operator_public_key",
            "proof_input_digest",
            "remote_verification_status",
            "files",
            "created_at",
            "manifest_digest",
        ],
    )
    if manifest.get("schema_version") != EXPECTED_RELEASE_ASSET_SCHEMA:
        raise RuntimeError(f"release asset manifest schema_version must be {EXPECTED_RELEASE_ASSET_SCHEMA}")
    if manifest.get("remote_verification_status") != "REMOTE_OK":
        raise RuntimeError("release asset manifest remote_verification_status must be REMOTE_OK")
    if re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("proof_input_digest", ""))) is None:
        raise RuntimeError("release asset manifest proof_input_digest must be a 64-hex SHA-256 digest")

    files = manifest.get("files")
    if not isinstance(files, list):
        raise RuntimeError("release asset manifest files must be a list")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise RuntimeError("release asset manifest files entries must be objects")
        path = entry.get("path")
        digest = entry.get("sha256")
        if path in seen:
            raise RuntimeError(f"release asset manifest contains duplicate file: {path}")
        seen.add(str(path))
        if path not in RELEASE_ASSET_PAYLOAD_FILES:
            raise RuntimeError(f"release asset manifest contains unexpected file: {path}")
        if re.fullmatch(r"[0-9a-f]{64}", str(digest or "")) is None:
            raise RuntimeError(f"release asset manifest digest for {path} must be 64-hex SHA-256")
    if seen != set(RELEASE_ASSET_PAYLOAD_FILES):
        missing = sorted(set(RELEASE_ASSET_PAYLOAD_FILES) - seen)
        raise RuntimeError("release asset manifest missing file digests: " + ", ".join(missing))

    expected_digest = verify_release.digest_hex(
        verify_release.canonical_json(release_asset_manifest_body(manifest)).encode("utf-8")
    )
    if manifest.get("manifest_digest") != expected_digest:
        raise RuntimeError("release asset manifest digest mismatch")


def verify_release_asset_hashes(asset_path: Path, manifest: dict[str, Any]) -> None:
    for entry in manifest["files"]:
        path = str(entry["path"])
        actual = verify_release.digest_hex((asset_path / path).read_bytes())
        expected = str(entry["sha256"])
        if actual != expected:
            raise RuntimeError(f"release asset digest mismatch for {path}: expected {expected}, got {actual}")


def extract_proof_input_tar(tar_path: Path, output_dir: Path) -> None:
    expected_names = set(verify_release.PROOF_INPUT_FILES)
    extracted: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_path.read_bytes()), mode="r:*") as tar:
            for member in tar.getmembers():
                normalized_name = member.name.replace("\\", "/")
                normalized_path = posixpath.normpath(normalized_name)
                if normalized_name.startswith("/") or normalized_path != normalized_name or not member.isfile():
                    raise RuntimeError(f"unexpected proof input archive path: {member.name}")

                output_name = ""
                if normalized_name in expected_names:
                    output_name = normalized_name
                elif normalized_name.startswith("proof/release/"):
                    candidate = normalized_name.removeprefix("proof/release/")
                    if candidate in expected_names:
                        output_name = candidate
                if not output_name:
                    raise RuntimeError(f"unexpected proof input archive path: {member.name}")
                if output_name in extracted:
                    raise RuntimeError(f"duplicate proof input archive path: {member.name}")

                stream = tar.extractfile(member)
                if stream is None:
                    raise RuntimeError(f"cannot read proof input archive path: {member.name}")
                target = output_dir / output_name
                if target.exists() or target.is_symlink():
                    raise RuntimeError(f"refusing to overwrite materialized release proof input: {output_name}")
                target.write_bytes(stream.read())
                extracted.add(output_name)
    except tarfile.TarError as exc:
        raise RuntimeError("proof-input.tar is not a valid tar archive") from exc

    missing = sorted(expected_names - extracted)
    if missing:
        raise RuntimeError("proof-input.tar missing release proof inputs: " + ", ".join(missing))


def verify_release_asset_metadata(
    asset_path: Path,
    manifest: dict[str, Any],
    release_result: dict[str, Any],
) -> None:
    ci_release = read_json(asset_path / "ci_release_sha.json")
    remote_result = read_json(asset_path / "remote_verification_result.json")
    workflow_metadata = read_json(asset_path / "workflow_metadata.json")

    if ci_release.get("proof_input_digest") != release_result.get("proof_input_digest"):
        raise RuntimeError("CI attestation proof_input_digest does not match release asset proof inputs")
    if remote_result.get("status") != "REMOTE_OK":
        raise RuntimeError("remote_verification_result status must be REMOTE_OK")
    if remote_result.get("proof_input_digest") != release_result.get("proof_input_digest"):
        raise RuntimeError("remote_verification_result proof_input_digest does not match release asset proof inputs")
    if workflow_metadata.get("remote_verification_status") != "REMOTE_OK":
        raise RuntimeError("workflow_metadata remote_verification_status must be REMOTE_OK")
    if workflow_metadata.get("proof_input_digest") != release_result.get("proof_input_digest"):
        raise RuntimeError("workflow_metadata proof_input_digest does not match release asset proof inputs")
    if manifest.get("proof_input_digest") != release_result.get("proof_input_digest"):
        raise RuntimeError("release asset manifest proof_input_digest does not match release asset proof inputs")
    if workflow_metadata.get("proof_input_archive_sha256") != verify_release.digest_hex(
        (asset_path / "proof-input.tar").read_bytes()
    ):
        raise RuntimeError("workflow_metadata proof_input_archive_sha256 mismatch")
    if workflow_metadata.get("ci_attestation_sha256") != verify_release.digest_hex(
        (asset_path / "ci_release_sha.json").read_bytes()
    ):
        raise RuntimeError("workflow_metadata ci_attestation_sha256 mismatch")
    if workflow_metadata.get("remote_verification_result_sha256") != verify_release.digest_hex(
        (asset_path / "remote_verification_result.json").read_bytes()
    ):
        raise RuntimeError("workflow_metadata remote_verification_result_sha256 mismatch")


def verify_release_asset_dir(asset_dir: Path | str) -> dict[str, Any]:
    asset_path = Path(asset_dir)
    require_release_asset_files(asset_path)
    manifest = read_json(asset_path / RELEASE_ASSET_MANIFEST)
    signature_doc = read_json(asset_path / RELEASE_ASSET_SIGNATURE)
    validate_release_asset_manifest(manifest)
    verify_manifest_signature(manifest, signature_doc)
    verify_release_asset_hashes(asset_path, manifest)

    with tempfile.TemporaryDirectory(prefix="adn-release-asset-proof-") as temp_dir:
        proof_path = Path(temp_dir)
        extract_proof_input_tar(asset_path / "proof-input.tar", proof_path)
        (proof_path / "ci_release_sha.json").write_bytes((asset_path / "ci_release_sha.json").read_bytes())
        release_result = verify_release.verify_release_dir(proof_path)

    verify_release_asset_metadata(asset_path, manifest, release_result)
    return {
        "status": "RELEASE_ASSET_OK",
        "build_commit": release_result.get("build_commit"),
        "build_config_id": release_result.get("build_config_id"),
        "proof_input_digest": release_result.get("proof_input_digest"),
        "release_tag": manifest.get("release_tag"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify durable ADN GitHub Release proof assets")
    parser.add_argument("asset_dir", nargs="?", default="proof/release-assets")
    args = parser.parse_args()
    result = verify_release_asset_dir(Path(args.asset_dir))
    print(verify_release.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
