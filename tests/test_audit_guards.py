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
    assert "requirePinnedIssuerRuntimeConfig(session.address)" in index


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


def test_ci_runs_pinned_contract_configuration():
    workflow = read(".github/workflows/ci.yml")

    assert "tests/test_audit_guards.py" in workflow
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
    assert "cargo test --locked" in readme
    assert "cargo build --locked --target wasm32-wasip2 --release" in readme
    assert "proof/live_run_v3.9.2.txt" in readme
