import io
import json
import tarfile
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_release, verify_release_asset


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def sign_doc(body: dict, private_key, public_key_hex: str) -> dict:
    return {
        "algorithm": "ed25519",
        "public_key_hex": public_key_hex,
        "signature_hex": private_key.sign(verify_release.canonical_json(body).encode("utf-8")).hex(),
    }


def sign_deployment_manifest(proof_dir: Path, manifest_body: dict, private_key, public_key_hex: str) -> None:
    manifest = {
        **manifest_body,
        "manifest_digest": verify_release.digest_hex(
            verify_release.canonical_json(manifest_body).encode("utf-8")
        ),
    }
    write_json(proof_dir / "deployment_manifest.json", manifest)
    write_json(proof_dir / "deployment_manifest.sig", sign_doc(manifest_body, private_key, public_key_hex))


def write_proof_input_tar(asset_dir: Path, proof_dir: Path, *, unsafe_member: str | None = None) -> None:
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as tar:
        for name in verify_release.PROOF_INPUT_FILES:
            data = (proof_dir / name).read_bytes()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
        if unsafe_member is not None:
            data = b"escape"
            info = tarfile.TarInfo(name=unsafe_member)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    (asset_dir / "proof-input.tar").write_bytes(tar_bytes.getvalue())


def build_valid_release_asset_fixture(asset_dir: Path, monkeypatch):
    asset_dir.mkdir()
    proof_dir = asset_dir.parent / "_proof_inputs"
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
        "build_commit": "abc1234000000000000000000000000000000000",
        "rustc_version": "rustc 1.0.0",
        "tenant_did": "did:t3n:fixture",
        "trusted_issuer": "58da990a8f4a3a6ca7cb6315d68a140105917352",
        "build_config_id": "adn-build-fixture",
        "local_wasm_sha256": "a" * 64,
        "registration_status": "registered",
        "registered_at": "2026-06-28T10:10:36.104Z",
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
    sign_deployment_manifest(proof_dir, manifest_body, private_key, public_key_hex)
    write_proof_input_tar(asset_dir, proof_dir)

    proof_input_digest = verify_release.compute_proof_input_digest(proof_dir)
    ci_release = {
        "evidence_source": "github_actions",
        "generated_by": ".github/workflows/release-proof-attest.yml",
        "attested_workflow": ".github/workflows/release-proof-input.yml",
        "attestation_phase": "post_verify_completed_run",
        "repository": "KAGEROU1107/agent-delegation-network",
        "sha": "abc1234000000000000000000000000000000000",
        "workflow_run_id": "12345",
        "workflow_run_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345",
        "workflow_conclusion": "success",
        "tests_workflow_run_id": "54321",
        "tests_workflow_run_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/54321",
        "tests_workflow_conclusion": "success",
        "tests_workflow_head_sha": "abc1234000000000000000000000000000000000",
        "tests_workflow_event": "push",
        "tests_workflow_head_branch": "main",
        "artifact_id": "67890",
        "artifact_name": "adn-release-proof-input-abc1234",
        "artifact_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345/artifacts/67890",
        "artifact_digest": "d" * 64,
        "proof_input_digest": proof_input_digest,
        "proof_input_files": verify_release.PROOF_INPUT_FILES,
        "retrieved_at": "2026-06-23T00:00:00Z",
    }
    remote_result = {
        "status": "REMOTE_OK",
        "build_commit": "abc1234",
        "build_config_id": "adn-build-fixture",
        "workflow_run_id": "12345",
        "tests_workflow_run_id": "54321",
        "artifact_id": "67890",
        "artifact_digest": "d" * 64,
        "proof_input_digest": proof_input_digest,
    }
    write_json(asset_dir / "ci_release_sha.json", ci_release)
    write_json(asset_dir / "remote_verification_result.json", remote_result)
    workflow_metadata = {
        "evidence_source": "github_actions_release_asset",
        "repository": "KAGEROU1107/agent-delegation-network",
        "sha": "abc1234",
        "attest_workflow_run_id": "12345",
        "attest_workflow_run_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345",
        "attest_workflow_run_attempt": "1",
        "input_workflow_run_id": "12345",
        "input_workflow_run_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/12345",
        "tests_workflow_run_id": "54321",
        "tests_workflow_run_url": "https://github.com/KAGEROU1107/agent-delegation-network/actions/runs/54321",
        "proof_input_digest": proof_input_digest,
        "remote_verification_status": "REMOTE_OK",
        "durable_asset_files": verify_release_asset.RELEASE_ASSET_PAYLOAD_FILES,
        "proof_input_archive_sha256": verify_release.digest_hex((asset_dir / "proof-input.tar").read_bytes()),
        "ci_attestation_sha256": verify_release.digest_hex((asset_dir / "ci_release_sha.json").read_bytes()),
        "remote_verification_result_sha256": verify_release.digest_hex(
            (asset_dir / "remote_verification_result.json").read_bytes()
        ),
        "created_at": "2026-06-23T00:00:00Z",
    }
    write_json(asset_dir / "workflow_metadata.json", workflow_metadata)

    file_digests = [
        {
            "path": name,
            "sha256": verify_release.digest_hex((asset_dir / name).read_bytes()),
        }
        for name in verify_release_asset.RELEASE_ASSET_PAYLOAD_FILES
    ]
    release_manifest_body = {
        "schema_version": "adn-release-asset-manifest-v1",
        "repository": "KAGEROU1107/agent-delegation-network",
        "sha": "abc1234",
        "release_tag": "adn-release-proof-abc1234",
        "operator_public_key": public_key_hex,
        "proof_input_digest": proof_input_digest,
        "remote_verification_status": "REMOTE_OK",
        "files": file_digests,
        "created_at": "2026-06-23T00:00:00Z",
    }
    release_manifest = {
        **release_manifest_body,
        "manifest_digest": verify_release.digest_hex(
            verify_release.canonical_json(release_manifest_body).encode("utf-8")
        ),
    }
    write_json(asset_dir / "release_asset_manifest.json", release_manifest)
    write_json(asset_dir / "release_asset_manifest.sig", sign_doc(release_manifest_body, private_key, public_key_hex))
    return {
        "proof_dir": proof_dir,
        "private_key": private_key,
        "public_key_hex": public_key_hex,
        "release_manifest_body": release_manifest_body,
    }


def rewrite_release_asset_manifest(asset_dir: Path, context: dict) -> None:
    manifest_body = {
        **context["release_manifest_body"],
        "files": [
            {
                "path": name,
                "sha256": verify_release.digest_hex((asset_dir / name).read_bytes()),
            }
            for name in verify_release_asset.RELEASE_ASSET_PAYLOAD_FILES
        ],
    }
    manifest = {
        **manifest_body,
        "manifest_digest": verify_release.digest_hex(
            verify_release.canonical_json(manifest_body).encode("utf-8")
        ),
    }
    write_json(asset_dir / "release_asset_manifest.json", manifest)
    write_json(
        asset_dir / "release_asset_manifest.sig",
        sign_doc(manifest_body, context["private_key"], context["public_key_hex"]),
    )


def test_verify_release_asset_accepts_signed_release_asset_bundle(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)

    result = verify_release_asset.verify_release_asset_dir(asset_dir)

    assert result["status"] == "RELEASE_ASSET_OK"
    assert result["build_commit"] == "abc1234000000000000000000000000000000000"
    assert result["proof_input_digest"]


def test_verify_release_asset_rejects_tampered_asset_file(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    write_json(asset_dir / "remote_verification_result.json", {"status": "REMOTE_OK", "tampered": True})

    with pytest.raises(RuntimeError, match="release asset digest mismatch"):
        verify_release_asset.verify_release_asset_dir(asset_dir)


def test_verify_release_asset_rejects_manifest_signature_mismatch(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    context = build_valid_release_asset_fixture(asset_dir, monkeypatch)
    other_key = Ed25519PrivateKey.generate()
    other_public = other_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    write_json(
        asset_dir / "release_asset_manifest.sig",
        sign_doc(context["release_manifest_body"], other_key, other_public),
    )

    with pytest.raises(RuntimeError, match="release_asset_manifest.sig public_key_hex"):
        verify_release_asset.verify_release_asset_dir(asset_dir)


def test_verify_release_asset_rejects_unmanifested_release_file(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    (asset_dir / "unexpected-extra.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unexpected release asset file"):
        verify_release_asset.verify_release_asset_dir(asset_dir)


def test_verify_release_asset_rejects_unsafe_proof_input_archive_path(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    context = build_valid_release_asset_fixture(asset_dir, monkeypatch)
    write_proof_input_tar(asset_dir, context["proof_dir"], unsafe_member="../escape.json")
    rewrite_release_asset_manifest(asset_dir, context)

    with pytest.raises(RuntimeError, match="unexpected proof input archive path"):
        verify_release_asset.verify_release_asset_dir(asset_dir)
