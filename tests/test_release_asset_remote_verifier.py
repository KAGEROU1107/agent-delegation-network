import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_release, verify_release_asset, verify_release_asset_remote
from tests.test_release_asset_verifier import build_valid_release_asset_fixture


EXPECTED_REPOSITORY = "KAGEROU1107/agent-delegation-network"
EXPECTED_TAG = "adn-release-proof-abc1234"
EXPECTED_SHA = "abc1234"


class FakeReleaseAssetClient:
    def __init__(self, asset_dir: Path, *, release_overrides: dict | None = None):
        self.asset_dir = asset_dir
        self.requested: list[tuple[str, str]] = []
        self.release = {
            "tag_name": EXPECTED_TAG,
            "target_commitish": EXPECTED_SHA,
            "html_url": f"https://github.com/{EXPECTED_REPOSITORY}/releases/tag/{EXPECTED_TAG}",
            "assets": [
                {
                    "name": name,
                    "url": f"https://api.github.local/assets/{name}",
                    "browser_download_url": f"https://github.com/{EXPECTED_REPOSITORY}/releases/download/{EXPECTED_TAG}/{name}",
                    "size": (asset_dir / name).stat().st_size,
                }
                for name in verify_release_asset.REQUIRED_RELEASE_ASSET_FILES
            ],
            **(release_overrides or {}),
        }

    def get_release_by_tag(self, repository: str, tag: str) -> dict:
        self.requested.append((repository, tag))
        return self.release

    def download_release_asset(self, asset: dict) -> bytes:
        name = asset["name"]
        return (self.asset_dir / name).read_bytes()


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def rewrite_manifest_sha(asset_dir: Path, context: dict, sha: str) -> None:
    body = {
        **context["release_manifest_body"],
        "sha": sha,
    }
    manifest = {
        **body,
        "manifest_digest": verify_release.digest_hex(verify_release.canonical_json(body).encode("utf-8")),
    }
    signature = {
        "algorithm": "ed25519",
        "public_key_hex": context["public_key_hex"],
        "signature_hex": context["private_key"].sign(
            verify_release.canonical_json(body).encode("utf-8")
        ).hex(),
    }
    write_json(asset_dir / "release_asset_manifest.json", manifest)
    write_json(asset_dir / "release_asset_manifest.sig", signature)


def test_remote_release_asset_verifier_accepts_github_release_assets(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    client = FakeReleaseAssetClient(asset_dir)

    result = verify_release_asset_remote.verify_release_asset_remote(
        repository=EXPECTED_REPOSITORY,
        tag=EXPECTED_TAG,
        expected_sha=EXPECTED_SHA,
        client=client,
    )

    assert result["status"] == "REMOTE_RELEASE_ASSET_OK"
    assert result["release_tag"] == EXPECTED_TAG
    assert result["sha"] == EXPECTED_SHA
    assert client.requested == [(EXPECTED_REPOSITORY, EXPECTED_TAG)]


def test_remote_release_asset_verifier_rejects_wrong_tag(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    client = FakeReleaseAssetClient(asset_dir, release_overrides={"tag_name": "wrong-tag"})

    with pytest.raises(RuntimeError, match="release tag mismatch"):
        verify_release_asset_remote.verify_release_asset_remote(
            repository=EXPECTED_REPOSITORY,
            tag=EXPECTED_TAG,
            expected_sha=EXPECTED_SHA,
            client=client,
        )


def test_remote_release_asset_verifier_rejects_wrong_repository(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    client = FakeReleaseAssetClient(asset_dir)

    with pytest.raises(RuntimeError, match="release asset manifest repository"):
        verify_release_asset_remote.verify_release_asset_remote(
            repository="evil/repo",
            tag=EXPECTED_TAG,
            expected_sha=EXPECTED_SHA,
            client=client,
        )


def test_remote_release_asset_verifier_rejects_missing_asset(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    client = FakeReleaseAssetClient(asset_dir)
    client.release["assets"] = [
        asset
        for asset in client.release["assets"]
        if asset["name"] != "remote_verification_result.json"
    ]

    with pytest.raises(RuntimeError, match="missing GitHub Release assets"):
        verify_release_asset_remote.verify_release_asset_remote(
            repository=EXPECTED_REPOSITORY,
            tag=EXPECTED_TAG,
            expected_sha=EXPECTED_SHA,
            client=client,
        )


def test_remote_release_asset_verifier_rejects_replaced_asset(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    client = FakeReleaseAssetClient(asset_dir)

    original_download = client.download_release_asset

    def replaced_download(asset: dict) -> bytes:
        if asset["name"] == "remote_verification_result.json":
            return b'{"status":"REMOTE_OK","tampered":true}\n'
        return original_download(asset)

    client.download_release_asset = replaced_download

    with pytest.raises(RuntimeError, match="release asset digest mismatch"):
        verify_release_asset_remote.verify_release_asset_remote(
            repository=EXPECTED_REPOSITORY,
            tag=EXPECTED_TAG,
            expected_sha=EXPECTED_SHA,
            client=client,
        )


def test_remote_release_asset_verifier_rejects_release_target_mismatch(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    build_valid_release_asset_fixture(asset_dir, monkeypatch)
    client = FakeReleaseAssetClient(asset_dir, release_overrides={"target_commitish": "different-sha"})

    with pytest.raises(RuntimeError, match="release target_commitish"):
        verify_release_asset_remote.verify_release_asset_remote(
            repository=EXPECTED_REPOSITORY,
            tag=EXPECTED_TAG,
            expected_sha=EXPECTED_SHA,
            client=client,
        )


def test_remote_release_asset_verifier_rejects_manifest_sha_mismatch(tmp_path, monkeypatch):
    asset_dir = tmp_path / "release-assets"
    context = build_valid_release_asset_fixture(asset_dir, monkeypatch)
    rewrite_manifest_sha(asset_dir, context, "different-sha")
    client = FakeReleaseAssetClient(asset_dir)

    with pytest.raises(RuntimeError, match="release asset manifest sha"):
        verify_release_asset_remote.verify_release_asset_remote(
            repository=EXPECTED_REPOSITORY,
            tag=EXPECTED_TAG,
            expected_sha=EXPECTED_SHA,
            client=client,
        )
