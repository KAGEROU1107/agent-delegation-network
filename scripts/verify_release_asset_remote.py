"""Remote-verify durable GitHub Release proof assets.

scripts.verify_release_asset validates a local release-asset directory. This
module closes the archival gap by retrieving the assets from a GitHub Release
tag first, then delegating signature, inventory, hash, and proof checks to the
local verifier.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from scripts import verify_release, verify_release_asset
from scripts.verify_release_remote import DEFAULT_API_URL, DEFAULT_API_VERSION, DEFAULT_REPOSITORY, parse_repository


class GitHubReleaseAssetClient:
    def __init__(
        self,
        *,
        token: str | None = None,
        api_url: str = DEFAULT_API_URL,
        api_version: str = DEFAULT_API_VERSION,
        timeout: float = 30.0,
    ) -> None:
        self.token = token or ""
        self.api_url = api_url.rstrip("/")
        self.api_version = api_version
        self.timeout = timeout

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "adn-release-asset-remote-verifier",
            "X-GitHub-Api-Version": self.api_version,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, url: str, *, accept: str) -> bytes:
        request = urllib.request.Request(url, headers=self._headers(accept), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub release asset request failed with HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub release asset request failed: {exc.reason}") from exc

    def _json(self, path: str) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        payload = self._request(url, accept="application/vnd.github+json")
        return json.loads(payload.decode("utf-8"))

    def get_release_by_tag(self, repository: str, tag: str) -> dict[str, Any]:
        owner, repo = parse_repository(repository)
        encoded_tag = urllib.parse.quote(tag, safe="")
        return self._json(f"/repos/{owner}/{repo}/releases/tags/{encoded_tag}")

    def download_release_asset(self, asset: dict[str, Any]) -> bytes:
        url = str(asset.get("url") or asset.get("browser_download_url") or "").strip()
        if not url:
            raise RuntimeError(f"GitHub Release asset {asset.get('name', '')} is missing a download URL")
        return self._request(url, accept="application/octet-stream")


def require_equal(label: str, actual: Any, expected: Any) -> None:
    if str(actual) != str(expected):
        raise RuntimeError(f"{label} mismatch: expected {expected}, got {actual}")


def validate_release_metadata(release: dict[str, Any], *, tag: str, expected_sha: str | None) -> None:
    require_equal("release tag", release.get("tag_name"), tag)
    if expected_sha:
        require_equal("release target_commitish", release.get("target_commitish"), expected_sha)
    if not isinstance(release.get("assets"), list):
        raise RuntimeError("GitHub Release assets response is malformed")


def release_asset_map(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets_by_name: dict[str, dict[str, Any]] = {}
    unexpected: list[str] = []
    duplicate: list[str] = []
    expected_names = set(verify_release_asset.REQUIRED_RELEASE_ASSET_FILES)
    for asset in release.get("assets", []):
        if not isinstance(asset, dict):
            raise RuntimeError("GitHub Release asset entry is malformed")
        name = str(asset.get("name", ""))
        if name in assets_by_name:
            duplicate.append(name)
            continue
        if name not in expected_names:
            unexpected.append(name)
            continue
        assets_by_name[name] = asset

    if duplicate:
        raise RuntimeError("duplicate GitHub Release assets: " + ", ".join(sorted(duplicate)))
    if unexpected:
        raise RuntimeError("unexpected GitHub Release assets: " + ", ".join(sorted(unexpected)))

    missing = sorted(expected_names - set(assets_by_name))
    if missing:
        raise RuntimeError("missing GitHub Release assets: " + ", ".join(missing))
    return assets_by_name


def download_release_assets(
    output_dir: Path,
    *,
    client: GitHubReleaseAssetClient,
    release: dict[str, Any],
) -> None:
    assets_by_name = release_asset_map(release)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in verify_release_asset.REQUIRED_RELEASE_ASSET_FILES:
        asset = assets_by_name[name]
        payload = client.download_release_asset(asset)
        target = output_dir / name
        if target.exists() or target.is_symlink():
            raise RuntimeError(f"refusing to overwrite downloaded GitHub Release asset: {name}")
        target.write_bytes(payload)


def verify_release_manifest_binding(
    asset_dir: Path,
    *,
    repository: str,
    tag: str,
    expected_sha: str | None,
    release_target: str,
) -> dict[str, Any]:
    manifest = verify_release_asset.read_json(asset_dir / verify_release_asset.RELEASE_ASSET_MANIFEST)
    require_equal("release asset manifest repository", manifest.get("repository"), repository)
    require_equal("release asset manifest release_tag", manifest.get("release_tag"), tag)
    require_equal("release asset manifest sha", manifest.get("sha"), expected_sha or release_target)
    require_equal("release asset manifest sha", manifest.get("sha"), release_target)
    return manifest


def verify_release_asset_remote(
    *,
    repository: str | None = None,
    tag: str | None = None,
    expected_sha: str | None = None,
    client: GitHubReleaseAssetClient | None = None,
) -> dict[str, Any]:
    expected_repository = repository or os.environ.get("ADN_RELEASE_REPOSITORY", DEFAULT_REPOSITORY).strip()
    expected_tag = tag or os.environ.get("ADN_RELEASE_ASSET_TAG", "").strip()
    if not expected_tag:
        raise RuntimeError("release asset tag is required")
    parse_repository(expected_repository)

    api_client = client or GitHubReleaseAssetClient(
        token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "",
        api_url=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL),
        api_version=os.environ.get("GITHUB_API_VERSION", DEFAULT_API_VERSION),
    )
    release = api_client.get_release_by_tag(expected_repository, expected_tag)
    validate_release_metadata(release, tag=expected_tag, expected_sha=expected_sha)
    release_target = str(release.get("target_commitish", "")).strip()
    if not release_target:
        raise RuntimeError("GitHub Release target_commitish is required")

    with TemporaryDirectory(prefix="adn-release-asset-remote-") as temp_dir:
        asset_dir = Path(temp_dir)
        download_release_assets(asset_dir, client=api_client, release=release)
        manifest = verify_release_manifest_binding(
            asset_dir,
            repository=expected_repository,
            tag=expected_tag,
            expected_sha=expected_sha,
            release_target=release_target,
        )
        local_result = verify_release_asset.verify_release_asset_dir(asset_dir)

    return {
        "status": "REMOTE_RELEASE_ASSET_OK",
        "repository": expected_repository,
        "release_tag": expected_tag,
        "sha": manifest.get("sha"),
        "build_commit": local_result.get("build_commit"),
        "build_config_id": local_result.get("build_config_id"),
        "proof_input_digest": local_result.get("proof_input_digest"),
        "release_url": release.get("html_url"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote-verify durable ADN GitHub Release proof assets")
    parser.add_argument("--repository", default=os.environ.get("ADN_RELEASE_REPOSITORY", DEFAULT_REPOSITORY))
    parser.add_argument("--tag", default=os.environ.get("ADN_RELEASE_ASSET_TAG", ""))
    parser.add_argument("--sha", default=os.environ.get("ADN_RELEASE_ASSET_SHA", ""))
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL))
    args = parser.parse_args()
    client = GitHubReleaseAssetClient(token=args.github_token, api_url=args.api_url)
    result = verify_release_asset_remote(
        repository=args.repository,
        tag=args.tag,
        expected_sha=args.sha or None,
        client=client,
    )
    print(verify_release.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
