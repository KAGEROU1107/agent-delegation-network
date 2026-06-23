import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_bridge_does_not_substitute_historical_contract_id():
    index = read("t3n-bridge/src/index.ts")

    assert "contractId: 49" not in index
    assert "using known ID from initial registration" not in index
    assert "confirmed on first v3.8.0 deploy" not in index


def test_bridge_requires_pinned_issuer_before_contract_registration():
    index = read("t3n-bridge/src/index.ts")

    assert "ADN_TRUSTED_ISSUER" in index
    assert "does not match authenticated T3N issuer" in index
    assert "ADN_TENANT_DID" in index
    assert "does not match authenticated T3N tenant DID" in index
    assert "requirePinnedRuntimeConfig(session.address, session.tenantDid)" in index


def test_contract_and_bridge_expose_non_self_referential_build_identity():
    contract = read("contract/src/lib.rs")
    bridge = read("t3n-bridge/src/contract_bridge.ts")

    assert "ADN_WASM_SHA256" not in contract
    assert "wasm_sha256" not in contract
    assert "build_config_id" in contract
    assert "local_wasm_sha256" in bridge
    assert "deploymentManifest" in bridge
    assert "manifest_digest" in bridge
    assert "canonicalJson" in bridge
    assert "deployment_manifest.json" in bridge
    assert "registration_response.json" in bridge
    assert "invocation_receipt.json" in bridge
    assert "t3n_evidence.json" in bridge
    assert "ADN_BUILD_COMMIT" in bridge
    assert "ADN_RUSTC_VERSION" in bridge
    assert "already exists remotely" in bridge
    assert "refusing to continue without remote artifact identity verification" in bridge
    assert "Bump CONTRACT_VERSION for a fresh immutable deployment" in bridge
    assert "finalizeDeploymentManifest" in bridge
    assert "raw_registration_response_digest" in bridge
    assert "registered_at" in bridge
    assert "registration_status" in bridge
    assert "first_invocation_digest" in bridge


def test_map_setup_and_docs_do_not_claim_broad_acl_fallback():
    paths = [
        "t3n-bridge/src/map_setup.ts",
        "README.md",
        "SUBMISSION_REPORT.md",
        "docs/bugs/BUG-001-contractid-not-returned.md",
    ]

    for path in paths:
        content = read(path)
        assert 'writers/readers: "all"' not in content
        assert "writers/readers=all" not in content
        assert "broad ACL" not in content
        assert "Each feature phase uses a dedicated map" not in content


def test_docs_do_not_reintroduce_identity_or_test_count_drift():
    combined_docs = "\n".join([
        read("README.md"),
        read("SUBMISSION_REPORT.md"),
        read("PROVENANCE_v3.9.2.md"),
    ])

    assert "Coordinator: T3N DID" not in combined_docs
    assert "The **coordinator** is authenticated through the T3N ADK" not in combined_docs
    assert "Coordinator DID from T3N session" not in combined_docs
    assert "not_after_secs: now + 3600n" not in combined_docs
    assert "22 Rust tests" not in combined_docs
    assert "22/22" not in combined_docs
    assert "65 Python security tests" not in combined_docs
    assert "70/70" not in combined_docs
    assert "72/72" not in combined_docs
    assert "issuer-authenticated delegated execution" not in combined_docs
    assert "TEE authorization decision for delegated calls" in combined_docs


def test_ci_runs_pinned_contract_configuration():
    workflow = read(".github/workflows/ci.yml")

    assert "tests/test_audit_guards.py" in workflow
    assert "tests/test_release_verifier.py" in workflow
    assert "npm test" in workflow
    assert "ADN_BUILD_COMMIT" in workflow
    assert "ADN_RUSTC_VERSION" in workflow
    assert "ADN_TRUSTED_ISSUER: 58da990a8f4a3a6ca7cb6315d68a140105917352" in workflow
    assert "ADN_TENANT_DID: did:t3n:fixture" in workflow
    assert "Run Rust contract tests with pinned issuer" in workflow
    assert "Build pinned Rust/WASM contract" in workflow


def test_python_adn_runner_requires_real_t3n_bundle_and_pinned_gateway():
    runner = read("t3n-bridge/src/adn_runner.ts")
    protocol = read("src/delegation_protocol.py")
    receipt = read("src/tee_authorization.py")
    index = read("t3n-bridge/src/index.ts")

    assert "prepareAdnExecution" in runner
    assert "prepareGatewayKeyBundle" in runner
    assert "requireConfiguredGatewayKeyBundleFromEnv" in runner
    assert "TEE authorization bundle is required" in runner
    assert "require_authorization_result('processData'" in runner
    assert "require_authorization_result('validateQuality'" in runner
    assert "ADN_IDENTITY_BUNDLE_PATH" in runner
    assert "TEE_AUTHORIZATION_BUNDLE_PATH" in runner
    assert "ADN_GATEWAY_KEY_BUNDLE_PATH" in runner
    assert "ADN_IDENTITY_BUNDLE_JSON" not in runner
    assert "TEE_AUTHORIZATION_BUNDLE_JSON" not in runner
    assert "T3N_API_KEY: apiKey" not in runner
    assert "expected_gateway_public_key_hex=trusted_gateway_public_key_hex" in runner
    assert "expected_gateway_key_id=trusted_gateway_key_id" in runner
    assert "expected_gateway_pubkey_hex=signed_request.get(\"public_key_hex\", \"\")" not in protocol
    assert "expected_gateway_key_id: str" in protocol
    assert "ADN_GATEWAY_PRIVATE_KEY_HEX" in index
    assert "ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX" in index
    assert "credential_enforced" in receipt
    assert "build_config_id" in receipt
    assert "gateway_key_id" in receipt
    assert "authorization_expires_at" in receipt


def test_contract_emits_authorization_expiry_and_bridge_uses_contract_value():
    contract = read("contract/src/lib.rs")
    index = read("t3n-bridge/src/index.ts")

    assert "authorization_expires_at" in contract
    assert "authorization_expires_at: result.authorization_expires_at" in index
    assert "authorization_expires_at: delegationEnvelope.authorization_expires_at" not in index


def test_runner_uses_private_temp_dir_for_sensitive_files():
    runner = read("t3n-bridge/src/adn_runner.ts")
    runtime_config = read("t3n-bridge/src/runtime_config.ts")
    doctor = read("t3n-bridge/src/doctor.ts")
    index = read("t3n-bridge/src/index.ts")
    package_json = read("t3n-bridge/package.json")
    replay_ledger = read("src/replay_ledger.py")

    assert "mkdtempSync" in runner
    assert "chmodSync" in runner
    assert "mode: 0o600" in runner
    assert "0o700" in runner
    assert "ADN_REPLAY_LEDGER_DIR" in runner
    assert "ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX" in runner
    assert "ADN_RUNTIME_MODE" in runner
    assert "non-durable-demo" in runner
    assert "resolveReplayKeyProvider" in runtime_config
    assert "ADN_REPLAY_LEDGER_KEY_REF" in runtime_config
    assert "ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX is not accepted in live mode" in runtime_config
    assert "lstatSync" in runtime_config
    assert "isSymbolicLink" in runtime_config
    assert "isFile" in runtime_config
    assert "isAbsolute" in runtime_config
    assert "0o600" in runtime_config
    assert "0o700" in runtime_config
    assert "ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE" in runner
    assert "delete childEnv.ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX" in runner
    assert "runtime doctor" in doctor
    assert "requireReplayLedgerDir" in doctor
    assert "resolveReplayKeyProvider" in doctor
    assert "loadDotEnvIfAllowed" in index
    assert "getRuntimeMode" in index
    assert "Skipping .env load in live mode" in index
    assert '"doctor"' in package_json
    assert "replay_restart.integration.mjs" in package_json
    assert "ADN_REPLAY_LEDGER_DIR is required for durable live replay protection" in runtime_config
    assert "ADN_REPLAY_LEDGER_DIR: replayLedgerDir" in runner
    assert "sqlite3" in replay_ledger
    assert "BEGIN IMMEDIATE" in replay_ledger
    assert "execution_token" in replay_ledger
    assert "ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE" in replay_ledger
    assert "_validate_live_integrity_key_file" in replay_ledger
    assert "must not be a symlink in live mode" in replay_ledger
    assert "0600 permissions" in replay_ledger
    assert "0700 permissions" in replay_ledger


def test_security_invariants_document_runtime_boundaries():
    invariants = read("docs/architecture/security-invariants.md")

    assert "worker executes only when" in invariants
    assert "target matches" in invariants
    assert "action matches" in invariants
    assert "credential is enforced" in invariants
    assert "gateway key ID matches" in invariants
    assert "build configuration matches" in invariants
    assert "authorization has not expired" in invariants
    assert "replay reservation succeeds" in invariants
    assert "delegation_id || request_hash || receipt_fingerprint" in invariants
    assert "worker_public_key || coordinator_id || delegation_id || result_nonce || receipt_fingerprint" in invariants
    assert "TypeScript bridge restart" in invariants
    assert "host process restart" in invariants
    assert "concurrent worker processes" in invariants
    assert "gateway-linked" in invariants
    assert "T3N-attested worker dispatch cannot be claimed" in invariants


def test_live_demo_docs_require_pinned_deployment_sequence():
    readme = read("README.md")
    report = read("SUBMISSION_REPORT.md")
    provenance = read("PROVENANCE_v3.9.2.md")

    combined_docs = "\n".join([readme, report, provenance])

    assert "# Run full live demo" not in combined_docs
    assert "# Full live demo" not in combined_docs
    assert "node scripts/derive_issuer.mjs" in readme
    assert "ADN_TRUSTED_ISSUER=<issuer-address-without-0x>" in readme
    assert "ADN_TENANT_DID=did:t3n:<tenant-hex>" in readme
    assert "ADN_BUILD_COMMIT=$BUILD_COMMIT" in readme
    assert "ADN_RUSTC_VERSION=\"$RUSTC_VERSION\"" in readme
    assert "T3N_API_KEY=0x<your_key> ADN_RUNTIME_MODE=live" in readme
    assert "ADN_REPLAY_LEDGER_KEY_REF=file:/var/lib/adn/replay-hmac.key" in readme
    assert "cargo test --locked" in readme
    assert "cargo build --locked --target wasm32-wasip2 --release" in readme
    assert "proof/release/deployment_manifest.json" in readme
    assert "proof/live_run_v3.9.2.txt" in readme


def test_release_guardrails_and_claim_matrix_are_source_controlled():
    criteria = read("docs/release/criteria.md")
    claim_matrix = read("docs/security/claim-matrix.md")
    release_gate = read("scripts/release_gate.py")
    release_verifier = read("scripts/verify_release.py")
    remote_verifier = read("scripts/verify_release_remote.py")
    schema = read("schemas/adn-release-proof-v1.schema.json")
    workflow = read(".github/workflows/ci.yml")
    release_input_workflow = read(".github/workflows/release-proof-input.yml")
    release_attest_workflow = read(".github/workflows/release-proof-attest.yml")
    actions_lock = read(".github/actions-lock.json")
    requirements_ci_lock = read("requirements-ci.lock")
    requirements_release_lock = read("requirements-release.lock")

    for content in (criteria, claim_matrix):
        assert "source-hardened / live-proof pending" in content
        assert "gateway-linked authorization" in content
        assert "T3N-attested authorization" in content
        assert "persistent ledger configuration" in content
        assert "executor key separation" in content
        assert "deployment manifest finalization" in content
        assert "live proof artifact" in content
        assert "visible CI success" in content
        assert "contract-layer persistence" in content

    assert "FORBIDDEN_CLAIMS" in release_gate
    assert "docs/security/claim-matrix.md" in release_gate
    assert "docs/release/criteria.md" in release_gate
    assert "verify_release.py" in release_gate
    assert "schemas/adn-release-proof-v1.schema.json" in release_gate
    assert ".github/workflows/release-proof-input.yml" in release_gate
    assert ".github/workflows/release-proof-attest.yml" in release_gate
    assert ".github/actions-lock.json" in release_gate
    assert "MUTABLE_WORKFLOW_REF_PATTERNS" in release_gate
    assert "assert_workflow_actions_are_pinned" in release_gate
    assert "PYTHON_REQUIREMENT_LOCKS" in release_gate
    assert "assert_python_dependencies_are_hash_locked" in release_gate
    assert "REQUIRED_PROOF_FILES" in release_verifier
    assert "deployment_manifest.sig" in release_verifier
    assert "registration_response.json" in release_verifier
    assert "t3n_evidence.json" in release_verifier
    assert "replay_restart_proof.json" in release_verifier
    assert "canonical_json" in release_verifier
    assert "Ed25519PublicKey" in release_verifier
    assert "manifest_digest" in release_verifier
    assert "validate_manifest_schema" in release_verifier
    assert "github_actions" in release_verifier
    assert "workflow_run_url" in release_verifier
    assert "artifact_digest" in release_verifier
    assert "tests_workflow_run_id" in release_verifier
    assert "tests_workflow_conclusion" in release_verifier
    assert "tests_workflow_head_sha" in release_verifier
    assert "compute_proof_input_digest" in release_verifier
    assert "PROOF_INPUT_FILES" in release_verifier
    assert "attestation_phase" in release_verifier
    assert "post_verify_completed_run" in release_verifier
    assert "attested_workflow" in release_verifier
    assert "proof_input_digest" in release_verifier
    assert "GitHubActionsClient" in remote_verifier
    assert "get_workflow_run" in remote_verifier
    assert "get_workflow_run_artifact" in remote_verifier
    assert "list_workflow_runs_for_head" in remote_verifier
    assert "find_successful_tests_workflow_run" in remote_verifier
    assert "verify_tests_run" in remote_verifier
    assert "download_artifact_zip" in remote_verifier
    assert "proof-input.tar" in remote_verifier
    assert "unexpected proof input archive path" in remote_verifier
    assert "expected_artifact_url" in remote_verifier
    assert "artifact_digest" in remote_verifier
    assert "proof_input_digest" in remote_verifier
    assert "REMOTE_OK" in remote_verifier
    assert "adn-release-proof-v1" in schema
    assert "name: Release Proof Input" in release_input_workflow
    assert "workflow_dispatch" in release_input_workflow
    assert "ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX" in release_input_workflow
    assert "verify-input:" in release_input_workflow
    assert "--input-only" in release_input_workflow
    assert "actions/upload-artifact" in release_input_workflow
    assert "name: Release Proof Attest" in release_attest_workflow
    assert "workflow_run:" in release_attest_workflow
    assert "Release Proof Input" in release_attest_workflow
    assert "types: [completed]" in release_attest_workflow
    assert "github.event.workflow_run.conclusion == 'success'" in release_attest_workflow
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in release_attest_workflow
    assert "github.event.workflow_run.head_branch == 'main'" in release_attest_workflow
    assert "github.event.workflow_run.head_sha" in release_attest_workflow
    assert "ref: ${{ github.event.workflow_run.head_sha }}" not in release_attest_workflow
    assert "materialize_proof_inputs_from_artifact_zip" in release_attest_workflow
    assert "list_workflow_runs_for_head" in release_attest_workflow
    assert "find_successful_tests_workflow_run" in release_attest_workflow
    assert "tests_workflow_run_id" in release_attest_workflow
    assert "tests_workflow_conclusion" in release_attest_workflow
    assert "tests_workflow_head_sha" in release_attest_workflow
    assert "${{ runner.temp }}/release-proof" in release_attest_workflow
    assert "post_verify_completed_run" in release_attest_workflow
    assert "attested_workflow" in release_attest_workflow
    assert "python scripts/verify_release.py \"${{ steps.attest.outputs.proof_dir }}\"" in release_attest_workflow
    assert "python scripts/verify_release_remote.py \"${{ steps.attest.outputs.proof_dir }}\"" in release_attest_workflow
    assert "adn-release-ci-attestation" in release_attest_workflow
    assert 'workflow_conclusion": "success"' not in release_attest_workflow
    assert 'workflow_conclusion": os.environ["INPUT_RUN_CONCLUSION"]' in release_attest_workflow
    assert "actions/upload-artifact" in release_attest_workflow
    assert "test_release_remote_verifier.py" in workflow
    assert "python scripts/release_gate.py" in workflow
    assert "python -m pip install --require-hashes -r requirements-ci.lock" in workflow
    assert "python -m pip install --require-hashes -r requirements-release.lock" in release_input_workflow
    assert "python -m pip install --require-hashes -r requirements-release.lock" in release_attest_workflow
    assert re.search(r"pip install (pytest|cryptography)\b", "\n".join([
        workflow,
        release_input_workflow,
        release_attest_workflow,
    ])) is None
    assert "pytest==" in requirements_ci_lock
    assert "cryptography==" in requirements_ci_lock
    assert "cryptography==" in requirements_release_lock
    assert "--hash=sha256:" in requirements_ci_lock
    assert "--hash=sha256:" in requirements_release_lock
    assert "actions/checkout" in actions_lock
    assert "actions/setup-python" in actions_lock
    assert "actions/setup-node" in actions_lock
    assert "actions/upload-artifact" in actions_lock
    assert "dtolnay/rust-toolchain" in actions_lock


def test_workflow_actions_are_pinned_to_reviewed_commits():
    lock = json.loads(read(".github/actions-lock.json"))
    locked_actions = {entry["action"]: entry for entry in lock["actions"]}
    workflow_paths = [
        ".github/workflows/ci.yml",
        ".github/workflows/release-proof-input.yml",
        ".github/workflows/release-proof-attest.yml",
    ]
    mutable_ref_pattern = re.compile(r"uses:\s+[^@\s]+@(v\d+|stable)\b")

    assert lock["schema_version"] == "adn-actions-lock-v1"
    assert set(locked_actions) == {
        "actions/checkout",
        "actions/setup-python",
        "actions/setup-node",
        "actions/upload-artifact",
        "dtolnay/rust-toolchain",
    }
    for entry in locked_actions.values():
        assert re.fullmatch(r"[0-9a-f]{40}", entry["commit_sha"])
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["review_date"])
        assert entry["approved_version"]
        assert entry["update_owner"]

    for path in workflow_paths:
        content = read(path)
        assert mutable_ref_pattern.search(content) is None, path
        for action, entry in locked_actions.items():
            if action in content:
                assert f"{action}@{entry['commit_sha']}" in content


def test_python_requirement_locks_pin_every_package_with_hashes():
    lock_paths = ["requirements-ci.lock", "requirements-release.lock"]
    requirement_line = re.compile(r"^[a-zA-Z0-9_.-]+==[^\s\\]+")

    for path in lock_paths:
        content = read(path)
        assert "--require-hashes" not in content
        assert "-r " not in content
        blocks = [block for block in content.split("\n\n") if requirement_line.search(block)]
        assert blocks, path
        for block in blocks:
            lines = [line.rstrip() for line in block.splitlines() if line.strip() and not line.startswith("#")]
            assert requirement_line.match(lines[0]), f"{path}: {lines[0]}"
            assert any("--hash=sha256:" in line for line in lines), f"{path}: {lines[0]}"
            assert not lines[0].startswith(("-e", "git+", "http://", "https://"))
