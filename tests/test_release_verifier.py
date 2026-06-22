import json
import os
import subprocess
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
        "artifact_digest": "d" * 64,
        "proof_input_digest": verify_release.compute_proof_input_digest(proof_dir),
        "proof_input_files": verify_release.PROOF_INPUT_FILES,
        "retrieved_at": "2026-06-23T00:00:00Z",
    })
    return {
        "private_key": private_key,
        "public_key_hex": public_key_hex,
        "manifest_body": manifest_body,
    }


def test_verify_release_accepts_complete_signed_fixture(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)

    verify_release.verify_release_dir(proof_dir)


def test_verify_release_inputs_accepts_bundle_without_ci_attestation(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    (proof_dir / "ci_release_sha.json").unlink()

    result = verify_release.verify_release_inputs(proof_dir)

    assert result["status"] == "INPUT_OK"
    assert result["proof_input_digest"] == verify_release.compute_proof_input_digest(proof_dir)


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


def test_verify_release_rejects_schema_invalid_manifest(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    context = build_valid_release_fixture(proof_dir, monkeypatch)
    invalid_body = {
        **context["manifest_body"],
        "unexpected_local_claim": "not allowed by adn-release-proof-v1",
    }
    sign_manifest(proof_dir, invalid_body, context["private_key"], context["public_key_hex"])

    with pytest.raises(RuntimeError, match="schema"):
        verify_release.verify_release_dir(proof_dir)


def test_verify_release_rejects_self_authored_ci_without_github_evidence(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    write_json(proof_dir / "ci_release_sha.json", {
        "repository": "KAGEROU1107/agent-delegation-network",
        "sha": "abc1234",
        "workflow_conclusion": "success",
    })

    with pytest.raises(RuntimeError, match="CI release evidence"):
        verify_release.verify_release_dir(proof_dir)


def test_verify_release_rejects_ci_attestation_with_wrong_proof_input_digest(tmp_path, monkeypatch):
    proof_dir = tmp_path / "proof"
    build_valid_release_fixture(proof_dir, monkeypatch)
    ci_evidence = json.loads((proof_dir / "ci_release_sha.json").read_text(encoding="utf-8"))
    ci_evidence["proof_input_digest"] = "0" * 64
    write_json(proof_dir / "ci_release_sha.json", ci_evidence)

    with pytest.raises(RuntimeError, match="proof input digest"):
        verify_release.verify_release_dir(proof_dir)


def test_python_and_typescript_canonical_release_vectors_match():
    vector = {
        "z": ["Ω", {"b": 2, "a": 1}],
        "a": "line\u2028separator",
        "nested": {"é": "accent", "e": "plain"},
    }
    expected_canonical = verify_release.canonical_json(vector)
    expected_digest = verify_release.digest_hex(expected_canonical.encode("utf-8"))

    node_script = """
import { canonicalJson, digestCanonicalJson, signReleaseManifestWithSeed } from './src/release_proof.ts';
const vector = JSON.parse(process.env.ADN_VECTOR_JSON);
const body = {
  build_commit: 'abc1234',
  build_config_id: 'adn-build-fixture',
  operator_public_key: '2f3b8f4f8f6d5d1a5a15b441b59ac7dcf7e2b7d44a36b0da45e9d8ea50a3c8f5',
};
const seed = '11'.repeat(32);
const signatureDoc = signReleaseManifestWithSeed(body, seed);
console.log(JSON.stringify({
  canonical: canonicalJson(vector),
  digest: digestCanonicalJson(vector),
  signatureDoc,
  signedBody: canonicalJson(body),
}));
"""
    env = {**os.environ, "ADN_VECTOR_JSON": json.dumps(vector, ensure_ascii=False)}
    result = subprocess.run(
        ["node", "--loader", "ts-node/esm", "--input-type=module", "-e", node_script],
        cwd=ROOT / "t3n-bridge",
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    output = json.loads(result.stdout.strip())

    assert output["canonical"] == expected_canonical
    assert output["digest"] == expected_digest
    public_key = verify_release.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(output["signatureDoc"]["public_key_hex"])
    )
    public_key.verify(
        bytes.fromhex(output["signatureDoc"]["signature_hex"]),
        output["signedBody"].encode("utf-8"),
    )
