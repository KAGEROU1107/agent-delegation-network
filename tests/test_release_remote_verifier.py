import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_release, verify_release_remote


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def sign_manifest(proof_dir: Path, manifest_body: dict, private_key, public_key_hex: str) -> None:
    manifest = {
        **manifest_body,
        "manifest_digest": verify_release.digest_hex(
            verify_release.canonical_json(manifest_body).encode("utf-8")
        ),
    }
    write_json(proof_dir / "deployment_manifest.json", manifest)

    signature = private_key.sign(verify_release.canonical_json(manifest_body).encode("utf-8"))
    write_json(proof_dir / "deployment_manifest.sig", {
        "algorithm": "ed25519",
        "public_key_hex": public_key_hex,
        "signature_hex": signature.hex(),
    })


def build_valid_release_fixture(proof_dir: Path, monkeypatch):
    proof_dir.mkdir()
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    monkeypatch.setenv("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX", public_key_hex)

    registration_response = {
        "contractId": 991,
        "tail": "adn-processor",
        "version": "3.9.2",
    }
    invocation_receipt = {
        "delegation_id": "tee-del-fixture",
        "build_config_id": "adn-build-fixture",
        "status": "ROUTED",
    }
    replay_restart_proof = {
        "build_config_id": "adn-build-fixture",
        "request_replay_rejected": True,
        "result_replay_rejected": True,
        "ledger_persisted_across_restart": True,
    }
    write_json(proof_dir / "registration_response.json", registration_response)
    write_json(proof_dir / "invocation_receipt.json", invocation_receipt)
    write_json(proof_dir / "t3n_evidence.json", invocation_receipt)
    write_json(proof_dir / "replay_restart_proof.json", replay_restart_proof)
    manifest_body = {
        "schema_version": "adn-release-proof-v1",
        "contract_tail": "adn-processor",
        "contract_version": "3.9.2",
        "build_commit": "abc1234",
        "rustc_version": "rustc 1.0.0",
        "tenant_did": "did:t3n:fixture",
        "trusted_issuer": "58da990a8f4a3a6ca7cb6315d68a140105917352",
        "build_config_id": "adn-build-fixture",
        "local_wasm_sha256": "a" * 64,
        "registration_status": "registered",
        "remote_contract_id": 991,
        "raw_registration_response_digest": verify_release.digest_hex(
            verify_release.canonical_json(registration_response).encode("utf-8")
        ),
        "raw_registration_response_path": "registration_response.json",
        "first_invocation_digest": verify_release.digest_hex(
            verify_release.canonical_json(invocation_receipt).encode("utf-8")
        ),
        "first_invocation_path": "invocation_receipt.json",
        "t3n_evidence_digest": verify_release.digest_hex(
            verify_release.canonical_json(invocation_receipt).encode("utf-8")
        ),
        "t3n_evidence_path": "t3n_evidence.json",
        "operator_public_key": public_key_hex,
    }
    sign_manifest(proof_dir, manifest_body, private_key, public_key_hex)
    write_json(proof_dir / "ci_release_sha.json", {
        "evidence_source": "github_actions",
        "generated_by": ".github/workflows/release-proof.yml",
        "attestation_phase": "post_verify",
        "repository": "KAGEROU1107/agent-delegation-network",
        "sha": "abc1234",
        "workflow_run_id": "12345",
        "workflow_run_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345",
        "workflow_conclusion": "success",
        "artifact_id": "67890",
        "artifact_name": "adn-release-proof-input-abc1234",
        "artifact_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345/artifacts/67890",
        "artifact_digest": "0" * 64,
        "proof_input_digest": verify_release.compute_proof_input_digest(proof_dir),
        "proof_input_files": verify_release.PROOF_INPUT_FILES,
        "retrieved_at": "2026-06-23T00:00:00Z",
    })


def build_artifact_zip(proof_dir: Path, *, omit: str | None = None) -> bytes:
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as tar:
        for name in verify_release.PROOF_INPUT_FILES:
            if name == omit:
                continue
            data = (proof_dir / name).read_bytes()
            info = tarfile.TarInfo(name=f"proof/release/{name}")
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))

    zip_bytes = io.BytesIO()
    with zipfile.ZipFile(zip_bytes, mode="w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("proof-input.tar", tar_bytes.getvalue())
    return zip_bytes.getvalue()


class FakeGitHubClient:
    def __init__(self, run: dict, artifact: dict, artifact_zip: bytes):
        self.run = run
        self.artifact = artifact
        self.artifact_zip = artifact_zip

    def get_workflow_run(self, repository: str, run_id: str) -> dict:
        assert repository == "KAGEROU1107/agent-delegation-network"
        assert run_id == "12345"
        return self.run

    def get_workflow_run_artifact(self, repository: str, run_id: str, artifact_id: str) -> dict:
        assert repository == "KAGEROU1107/agent-delegation-network"
        assert run_id == "12345"
        assert artifact_id == "67890"
        return self.artifact

    def download_artifact_zip(self, artifact: dict) -> bytes:
        assert artifact["archive_download_url"] == "https://api.github.local/artifacts/67890/zip"
        return self.artifact_zip


def make_client(proof_dir: Path, *, run_overrides: dict | None = None, artifact_zip: bytes | None = None):
    artifact_zip = artifact_zip if artifact_zip is not None else build_artifact_zip(proof_dir)
    artifact_digest = verify_release.digest_hex(artifact_zip)
    ci_evidence = json.loads((proof_dir / "ci_release_sha.json").read_text(encoding="utf-8"))
    ci_evidence["artifact_digest"] = artifact_digest
    write_json(proof_dir / "ci_release_sha.json", ci_evidence)
    run = {
        "id": 12345,
        "head_sha": "abc1234",
        "conclusion": "success",
        "html_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345",
        "repository": {"full_name": "KAGEROU1107/agent-delegation-network"},
        **(run_overrides or {}),
    }
    artifact = {
        "id": 67890,
        "name": "adn-release-proof-input-abc1234",
        "expired": False,
        "digest": f"sha256:{artifact_digest}",
        "archive_download_url": "https://api.github.local/artifacts/67890/zip",
    }
    return FakeGitHubClient(run, artifact, artifact_zip)


def test_remote_verifier_accepts_matching_github_run_and_artifact(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    client = make_client(proof_dir)

    result = verify_release_remote.verify_release_remote(proof_dir, client=client)

    assert result["status"] == "REMOTE_OK"
    assert result["artifact_id"] == "67890"
    assert result["workflow_run_id"] == "12345"


def test_remote_verifier_rejects_workflow_sha_mismatch(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    client = make_client(proof_dir, run_overrides={"head_sha": "different-sha"})

    with pytest.raises(RuntimeError, match="workflow run head_sha"):
        verify_release_remote.verify_release_remote(proof_dir, client=client)


def test_remote_verifier_rejects_downloaded_artifact_digest_mismatch(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    client = make_client(proof_dir)
    client.artifact_zip = b"not the uploaded archive"

    with pytest.raises(RuntimeError, match="downloaded artifact digest"):
        verify_release_remote.verify_release_remote(proof_dir, client=client)


def test_remote_verifier_rejects_archive_missing_proof_input(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    artifact_zip = build_artifact_zip(proof_dir, omit="t3n_evidence.json")
    client = make_client(proof_dir, artifact_zip=artifact_zip)

    with pytest.raises(RuntimeError, match="missing proof input"):
        verify_release_remote.verify_release_remote(proof_dir, client=client)
