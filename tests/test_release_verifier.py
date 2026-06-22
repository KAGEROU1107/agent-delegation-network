import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_release


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def build_valid_release_fixture(proof_dir: Path, monkeypatch):
    proof_dir.mkdir()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
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
        "requestReplayRejected": True,
        "resultReplayRejected": True,
        "ledgerPersistedAcrossRestart": True,
    }
    write_json(proof_dir / "registration_response.json", registration_response)
    write_json(proof_dir / "invocation_receipt.json", invocation_receipt)
    write_json(proof_dir / "replay_restart_proof.json", replay_restart_proof)
    write_json(proof_dir / "ci_release_sha.json", {
        "sha": "abc123",
        "status": "success",
    })

    manifest_body = {
        "build_commit": "abc123",
        "rustc_version": "rustc 1.0.0",
        "tenant_did": "did:t3n:fixture",
        "trusted_issuer": "58da990a8f4a3a6ca7cb6315d68a140105917352",
        "build_config_id": "adn-build-fixture",
        "local_wasm_sha256": "a" * 64,
        "remote_contract_id": 991,
        "raw_registration_response_digest": verify_release.digest_hex(
            verify_release.canonical_json(registration_response).encode("utf-8")
        ),
        "raw_registration_response_path": "registration_response.json",
        "first_invocation_digest": verify_release.digest_hex(
            verify_release.canonical_json(invocation_receipt).encode("utf-8")
        ),
        "t3n_evidence_digest": verify_release.digest_hex(
            verify_release.canonical_json(invocation_receipt).encode("utf-8")
        ),
        "operator_public_key": public_key_hex,
    }
    manifest = {
        **manifest_body,
        "manifestDigest": verify_release.digest_hex(
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


def test_verify_release_accepts_complete_signed_fixture(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)

    verify_release.verify_release_dir(proof_dir)


def test_verify_release_rejects_tampered_registration_response(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    write_json(proof_dir / "registration_response.json", {
        "contractId": 992,
        "tail": "adn-processor",
        "version": "3.9.2",
    })

    with pytest.raises(RuntimeError, match="registration response digest"):
        verify_release.verify_release_dir(proof_dir)
