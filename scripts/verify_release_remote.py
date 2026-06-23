"""Verify GitHub-hosted release proof artifact provenance.

scripts.verify_release checks that retained files are internally consistent.
This remote verifier adds the external GitHub Actions checks: the declared run
must exist, belong to the expected repository and commit, expose the declared
artifact, and the downloaded artifact archive must contain the exact proof-input
files hashed by the local release verifier.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import posixpath
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from scripts import verify_release


DEFAULT_REPOSITORY = "KAGEROU1107/agent-delegation-network"
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2022-11-28"
PROOF_INPUT_TAR = "proof-input.tar"


class GitHubActionsClient:
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
            "User-Agent": "adn-release-remote-verifier",
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
            raise RuntimeError(f"GitHub API request failed with HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API request failed: {exc.reason}") from exc

    def _json(self, path: str) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        payload = self._request(url, accept="application/vnd.github+json")
        return json.loads(payload.decode("utf-8"))

    def get_workflow_run(self, repository: str, run_id: str) -> dict[str, Any]:
        owner, repo = parse_repository(repository)
        return self._json(f"/repos/{owner}/{repo}/actions/runs/{run_id}")

    def get_workflow_run_artifact(self, repository: str, run_id: str, artifact_id: str) -> dict[str, Any]:
        owner, repo = parse_repository(repository)
        artifact = self._json(f"/repos/{owner}/{repo}/actions/artifacts/{artifact_id}")
        workflow_run = artifact.get("workflow_run") or {}
        if str(workflow_run.get("id", "")) != str(run_id):
            raise RuntimeError("GitHub artifact does not belong to the declared workflow run")
        return artifact

    def list_workflow_run_artifacts(self, repository: str, run_id: str) -> list[dict[str, Any]]:
        owner, repo = parse_repository(repository)
        artifacts: list[dict[str, Any]] = []
        page = 1
        total_count: int | None = None
        while total_count is None or len(artifacts) < total_count:
            payload = self._json(
                f"/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
            )
            total_count = int(payload.get("total_count", 0))
            page_artifacts = payload.get("artifacts", [])
            if not isinstance(page_artifacts, list):
                raise RuntimeError("GitHub artifacts response is malformed")
            artifacts.extend(page_artifacts)
            if not page_artifacts:
                break
            page += 1
        return artifacts

    def list_workflow_runs_for_head(self, repository: str, head_sha: str) -> list[dict[str, Any]]:
        owner, repo = parse_repository(repository)
        runs: list[dict[str, Any]] = []
        page = 1
        total_count: int | None = None
        encoded_sha = urllib.parse.quote(head_sha, safe="")
        while total_count is None or len(runs) < total_count:
            payload = self._json(
                f"/repos/{owner}/{repo}/actions/runs?per_page=100&page={page}&head_sha={encoded_sha}&status=completed"
            )
            total_count = int(payload.get("total_count", 0))
            page_runs = payload.get("workflow_runs", [])
            if not isinstance(page_runs, list):
                raise RuntimeError("GitHub workflow runs response is malformed")
            runs.extend(page_runs)
            if not page_runs:
                break
            page += 1
        return runs

    def download_artifact_zip(self, artifact: dict[str, Any]) -> bytes:
        download_url = str(artifact.get("archive_download_url", "")).strip()
        if not download_url:
            raise RuntimeError("GitHub artifact is missing archive_download_url")
        return self._request(download_url, accept="application/vnd.github+json")


def parse_repository(repository: str) -> tuple[str, str]:
    parts = repository.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise RuntimeError("repository must use owner/repo format")
    return parts[0], parts[1]


def normalize_digest(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:") :]
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise RuntimeError("GitHub artifact digest must be sha256:<64-hex> or 64-hex")
    return text


def require_equal(label: str, actual: Any, expected: Any) -> None:
    if str(actual) != str(expected):
        raise RuntimeError(f"{label} mismatch: expected {expected}, got {actual}")


def proof_input_digest_from_bytes(file_bytes: dict[str, bytes]) -> str:
    files = [
        {
            "path": name,
            "sha256": verify_release.digest_hex(file_bytes[name]),
        }
        for name in verify_release.PROOF_INPUT_FILES
    ]
    payload = {
        "schema_version": "adn-release-proof-input-v1",
        "files": files,
    }
    return verify_release.digest_hex(verify_release.canonical_json(payload).encode("utf-8"))


def extract_proof_input_tar(artifact_zip_bytes: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(artifact_zip_bytes)) as artifact_zip:
            if PROOF_INPUT_TAR not in artifact_zip.namelist():
                raise RuntimeError(f"downloaded GitHub artifact is missing {PROOF_INPUT_TAR}")
            tar_payload = artifact_zip.read(PROOF_INPUT_TAR)
    except zipfile.BadZipFile as exc:
        raise RuntimeError("downloaded GitHub artifact is not a valid ZIP archive") from exc

    extracted: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:*") as tar:
            expected_paths = {f"proof/release/{name}" for name in verify_release.PROOF_INPUT_FILES}
            members: dict[str, tarfile.TarInfo] = {}
            for member in tar.getmembers():
                normalized_name = member.name.replace("\\", "/")
                normalized_path = posixpath.normpath(normalized_name)
                if (
                    normalized_name.startswith("/")
                    or normalized_path != normalized_name
                    or normalized_name not in expected_paths
                ):
                    raise RuntimeError(f"unexpected proof input archive path: {member.name}")
                if not member.isfile():
                    raise RuntimeError(f"unexpected proof input archive path: {member.name}")
                members[normalized_name] = member
            for name in verify_release.PROOF_INPUT_FILES:
                member_path = f"proof/release/{name}"
                member = members.get(member_path)
                if member is None:
                    raise RuntimeError(f"downloaded GitHub artifact is missing proof input {member_path}")
                stream = tar.extractfile(member)
                if stream is None:
                    raise RuntimeError(f"downloaded GitHub artifact cannot read proof input {member_path}")
                extracted[name] = stream.read()
    except tarfile.TarError as exc:
        raise RuntimeError(f"{PROOF_INPUT_TAR} is not a valid tar archive") from exc
    return extracted


def materialize_proof_inputs_from_artifact_zip(output_dir: Path | str, artifact_zip_bytes: bytes) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    extracted = extract_proof_input_tar(artifact_zip_bytes)
    for name, payload in extracted.items():
        target = output_path / name
        if target.exists() or target.is_symlink():
            raise RuntimeError(f"refusing to overwrite materialized proof input: {name}")
        target.write_bytes(payload)
    return {
        "proof_input_digest": proof_input_digest_from_bytes(extracted),
        "proof_input_files": verify_release.PROOF_INPUT_FILES,
    }


def verify_archive_contents(proof_dir: Path, artifact_zip_bytes: bytes, expected_proof_input_digest: str) -> None:
    extracted = extract_proof_input_tar(artifact_zip_bytes)
    for name in verify_release.PROOF_INPUT_FILES:
        local_digest = verify_release.digest_hex((proof_dir / name).read_bytes())
        remote_digest = verify_release.digest_hex(extracted[name])
        if remote_digest != local_digest:
            raise RuntimeError(f"downloaded GitHub artifact proof input {name} digest mismatch")

    archive_proof_input_digest = proof_input_digest_from_bytes(extracted)
    if archive_proof_input_digest != expected_proof_input_digest:
        raise RuntimeError("downloaded GitHub artifact proof_input_digest does not match CI attestation")


def verify_run(ci_release: dict[str, Any], run: dict[str, Any], expected_repository: str) -> None:
    require_equal("workflow run id", run.get("id"), ci_release.get("workflow_run_id"))
    require_equal("workflow run head_sha", run.get("head_sha"), ci_release.get("sha"))
    require_equal("workflow run conclusion", run.get("conclusion"), "success")
    if run.get("html_url") != ci_release.get("workflow_run_url"):
        raise RuntimeError("workflow run URL does not match CI attestation")
    repository = run.get("repository") or {}
    if repository.get("full_name") != expected_repository:
        raise RuntimeError("workflow run repository does not match expected repository")


def find_successful_tests_workflow_run(
    runs: list[dict[str, Any]],
    *,
    repository: str,
    head_sha: str,
) -> dict[str, Any]:
    matches = [
        run
        for run in runs
        if run.get("name") == "Tests"
        and run.get("conclusion") == "success"
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and str(run.get("head_sha", "")) == head_sha
        and (run.get("repository") or {}).get("full_name") == repository
    ]
    if not matches:
        raise RuntimeError("no successful Tests workflow run found for release SHA")
    return sorted(matches, key=lambda run: str(run.get("run_started_at") or run.get("created_at") or ""), reverse=True)[0]


def verify_tests_run(ci_release: dict[str, Any], run: dict[str, Any], expected_repository: str) -> None:
    require_equal("Tests workflow run id", run.get("id"), ci_release.get("tests_workflow_run_id"))
    require_equal("Tests workflow head_sha", run.get("head_sha"), ci_release.get("tests_workflow_head_sha"))
    require_equal("Tests workflow conclusion", run.get("conclusion"), "success")
    require_equal("Tests workflow event", run.get("event"), ci_release.get("tests_workflow_event"))
    require_equal("Tests workflow head_branch", run.get("head_branch"), ci_release.get("tests_workflow_head_branch"))
    if run.get("html_url") != ci_release.get("tests_workflow_run_url"):
        raise RuntimeError("Tests workflow URL does not match CI attestation")
    if run.get("name") != "Tests":
        raise RuntimeError("Tests workflow run name does not match required workflow")
    if run.get("event") != "push":
        raise RuntimeError("Tests workflow event must be push")
    if run.get("head_branch") != "main":
        raise RuntimeError("Tests workflow head_branch must be main")
    repository = run.get("repository") or {}
    if repository.get("full_name") != expected_repository:
        raise RuntimeError("Tests workflow repository does not match expected repository")


def expected_artifact_url(repository: str, run_id: str, artifact_id: str) -> str:
    return f"https://github.com/{repository}/actions/runs/{run_id}/artifacts/{artifact_id}"


def verify_artifact(ci_release: dict[str, Any], artifact: dict[str, Any], repository: str, run_id: str) -> str:
    require_equal("artifact id", artifact.get("id"), ci_release.get("artifact_id"))
    require_equal("artifact name", artifact.get("name"), ci_release.get("artifact_name"))
    workflow_run = artifact.get("workflow_run") or {}
    if workflow_run and str(workflow_run.get("id", "")) != str(run_id):
        raise RuntimeError("GitHub artifact does not belong to the declared workflow run")
    if ci_release.get("artifact_url") != expected_artifact_url(repository, run_id, str(ci_release.get("artifact_id"))):
        raise RuntimeError("CI release evidence artifact_url does not match expected GitHub artifact URL")
    if artifact.get("expired") is True:
        raise RuntimeError("GitHub artifact has expired")

    remote_digest = normalize_digest(artifact.get("digest"))
    attested_digest = normalize_digest(ci_release.get("artifact_digest"))
    if remote_digest != attested_digest:
        raise RuntimeError("GitHub artifact metadata digest does not match CI attestation")
    return attested_digest


def verify_release_remote(
    proof_dir: Path | str,
    *,
    client: GitHubActionsClient | None = None,
    expected_repository: str | None = None,
) -> dict[str, Any]:
    proof_path = Path(proof_dir)
    local_result = verify_release.verify_release_dir(proof_path)
    ci_release = verify_release.read_json(proof_path / "ci_release_sha.json")
    repository = expected_repository or os.environ.get("ADN_RELEASE_REPOSITORY", DEFAULT_REPOSITORY).strip()
    if ci_release.get("repository") != repository:
        raise RuntimeError("CI release evidence repository does not match expected repository")

    api_client = client or GitHubActionsClient(
        token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "",
        api_url=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL),
        api_version=os.environ.get("GITHUB_API_VERSION", DEFAULT_API_VERSION),
    )
    run_id = str(ci_release.get("workflow_run_id", ""))
    artifact_id = str(ci_release.get("artifact_id", ""))
    run = api_client.get_workflow_run(repository, run_id)
    verify_run(ci_release, run, repository)

    tests_run_id = str(ci_release.get("tests_workflow_run_id", ""))
    tests_run = api_client.get_workflow_run(repository, tests_run_id)
    verify_tests_run(ci_release, tests_run, repository)

    artifact = api_client.get_workflow_run_artifact(repository, run_id, artifact_id)
    attested_artifact_digest = verify_artifact(ci_release, artifact, repository, run_id)
    artifact_zip = api_client.download_artifact_zip(artifact)
    downloaded_digest = verify_release.digest_hex(artifact_zip)
    if downloaded_digest != attested_artifact_digest:
        raise RuntimeError("downloaded artifact digest does not match GitHub artifact metadata")

    verify_archive_contents(proof_path, artifact_zip, str(ci_release.get("proof_input_digest")))
    return {
        "status": "REMOTE_OK",
        "build_commit": local_result.get("build_commit"),
        "build_config_id": local_result.get("build_config_id"),
        "workflow_run_id": run_id,
        "tests_workflow_run_id": tests_run_id,
        "artifact_id": artifact_id,
        "artifact_digest": downloaded_digest,
        "proof_input_digest": local_result.get("proof_input_digest"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote-verify an ADN GitHub Actions release proof artifact")
    parser.add_argument("proof_dir", nargs="?", default="proof/release")
    parser.add_argument("--repository", default=os.environ.get("ADN_RELEASE_REPOSITORY", DEFAULT_REPOSITORY))
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL))
    args = parser.parse_args()
    client = GitHubActionsClient(token=args.github_token, api_url=args.api_url)
    result = verify_release_remote(Path(args.proof_dir), client=client, expected_repository=args.repository)
    print(verify_release.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
