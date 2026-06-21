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
    assert "issuer-authenticated delegated execution" not in combined_docs
    assert "TEE authorization decision for delegated calls" in combined_docs


def test_ci_runs_pinned_contract_configuration():
    workflow = read(".github/workflows/ci.yml")

    assert "tests/test_audit_guards.py" in workflow
    assert "ADN_BUILD_COMMIT" in workflow
    assert "ADN_RUSTC_VERSION" in workflow
    assert "ADN_TRUSTED_ISSUER: 58da990a8f4a3a6ca7cb6315d68a140105917352" in workflow
    assert "ADN_TENANT_DID: did:t3n:fixture" in workflow
    assert "Run Rust contract tests with pinned issuer" in workflow
    assert "Build pinned Rust/WASM contract" in workflow


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
    assert "T3N_API_KEY=0x<your_key> ADN_BUILD_COMMIT=$BUILD_COMMIT" in readme
    assert "cargo test --locked" in readme
    assert "cargo build --locked --target wasm32-wasip2 --release" in readme
    assert "deployment_manifest_v3.9.2.local.json" in readme
    assert "proof/live_run_v3.9.2.txt" in readme
