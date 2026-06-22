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
    assert "localWasmSha256" in bridge
    assert "deploymentManifest" in bridge
    assert "manifestDigest" in bridge
    assert "ADN_BUILD_COMMIT" in bridge
    assert "ADN_RUSTC_VERSION" in bridge
    assert "already exists remotely" in bridge
    assert "refusing to continue without remote artifact identity verification" in bridge
    assert "Bump CONTRACT_VERSION for a fresh immutable deployment" in bridge


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
    replay_ledger = read("src/replay_ledger.py")

    assert "mkdtempSync" in runner
    assert "chmodSync" in runner
    assert "mode: 0o600" in runner
    assert "0o700" in runner
    assert "ADN_REPLAY_LEDGER_DIR" in runner
    assert "ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX" in runner
    assert "ADN_RUNTIME_MODE" in runner
    assert "non-durable-demo" in runner
    assert "ADN_REPLAY_LEDGER_DIR is required for durable live replay protection" in runner
    assert "ADN_REPLAY_LEDGER_DIR: replayLedgerDir" in runner
    assert "sqlite3" in replay_ledger
    assert "BEGIN IMMEDIATE" in replay_ledger
    assert "execution_token" in replay_ledger


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
    assert "ADN_REPLAY_LEDGER_KEY_REF=<secret-manager-reference>" in readme
    assert "cargo test --locked" in readme
    assert "cargo build --locked --target wasm32-wasip2 --release" in readme
    assert "deployment_manifest_v3.9.2.local.json" in readme
    assert "proof/live_run_v3.9.2.txt" in readme
