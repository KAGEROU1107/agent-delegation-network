"""Release-claim guard for ADN source and documentation."""

from __future__ import annotations

import json
import re
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "docs/release/criteria.md",
    "docs/security/claim-matrix.md",
    "docs/architecture/security-invariants.md",
    "scripts/verify_release.py",
    "schemas/adn-release-proof-v1.schema.json",
    ".github/workflows/release-proof-input.yml",
    ".github/workflows/release-proof-attest.yml",
    ".github/actions-lock.json",
    "requirements-ci.lock",
    "requirements-release.lock",
]

WORKFLOW_FILES = [
    ".github/workflows/ci.yml",
    ".github/workflows/release-proof-input.yml",
    ".github/workflows/release-proof-attest.yml",
]

MUTABLE_WORKFLOW_REF_PATTERNS = [
    re.compile(r"uses:\s+[^@\s]+@v\d+\b"),
    re.compile(r"uses:\s+[^@\s]+@stable\b"),
]

PYTHON_REQUIREMENT_LOCKS = [
    "requirements-ci.lock",
    "requirements-release.lock",
]

BARE_PIP_INSTALL_PATTERN = re.compile(r"\bpip install\b")
REQUIREMENT_LINE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+==[^\s\\]+")

REQUIRED_TERMS = [
    "source-hardened / live-proof pending",
    "gateway-linked authorization",
    "T3N-attested authorization",
    "persistent ledger configuration",
    "executor key separation",
    "deployment manifest finalization",
    "live proof artifact",
    "visible CI success",
    "contract-layer persistence",
]

FORBIDDEN_CLAIMS = [
    "T3N-attested worker dispatch: supported",
    "T3N-attested worker dispatch: complete",
    "contract-layer persistence: supported",
    "contract-layer persistence: complete",
    "persistent feature systems: supported",
    "persistent feature systems: complete",
]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def read_json(path: str) -> dict:
    return json.loads(read(path))


def assert_workflow_actions_are_pinned() -> list[str]:
    errors: list[str] = []
    try:
        lock = read_json(".github/actions-lock.json")
    except (OSError, json.JSONDecodeError) as exc:
        return [f"release gate cannot read .github/actions-lock.json: {exc}"]

    locked_actions = {}
    for entry in lock.get("actions", []):
        action = entry.get("action")
        commit_sha = entry.get("commit_sha")
        if not isinstance(action, str) or not action:
            errors.append("release gate action lock entry missing action")
            continue
        if not isinstance(commit_sha, str) or re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None:
            errors.append(f"release gate action lock entry for {action} must use a 40-character commit_sha")
            continue
        if not entry.get("approved_version") or not entry.get("review_date") or not entry.get("update_owner"):
            errors.append(f"release gate action lock entry for {action} missing review metadata")
        locked_actions[action] = commit_sha

    for workflow in WORKFLOW_FILES:
        content = read(workflow)
        for pattern in MUTABLE_WORKFLOW_REF_PATTERNS:
            if pattern.search(content):
                errors.append(f"release gate mutable workflow action reference present in {workflow}")
        for match in re.finditer(r"uses:\s+([^\s#]+)", content):
            action_ref = match.group(1)
            if "@" not in action_ref:
                errors.append(f"release gate workflow action reference missing @ in {workflow}: {action_ref}")
                continue
            action, ref = action_ref.rsplit("@", 1)
            locked_commit = locked_actions.get(action)
            if locked_commit is None:
                continue
            if ref != locked_commit:
                errors.append(f"release gate workflow {workflow} uses {action}@{ref}, expected {locked_commit}")
    return errors


def assert_python_dependencies_are_hash_locked() -> list[str]:
    errors: list[str] = []
    workflow_text = {
        workflow: read(workflow)
        for workflow in WORKFLOW_FILES
    }
    required_installs = {
        ".github/workflows/ci.yml": "python -m pip install --require-hashes -r requirements-ci.lock",
        ".github/workflows/release-proof-input.yml": (
            "python -m pip install --require-hashes -r requirements-release.lock"
        ),
        ".github/workflows/release-proof-attest.yml": (
            "python -m pip install --require-hashes -r requirements-release.lock"
        ),
    }
    for workflow, required_command in required_installs.items():
        content = workflow_text[workflow]
        if required_command not in content:
            errors.append(f"release gate workflow {workflow} must install Python deps with {required_command}")
        for line in content.splitlines():
            if BARE_PIP_INSTALL_PATTERN.search(line) and "--require-hashes" not in line:
                errors.append(f"release gate bare pip install present in {workflow}: {line.strip()}")

    for lock_path in PYTHON_REQUIREMENT_LOCKS:
        content = read(lock_path)
        if "--require-hashes" in content or "-r " in content:
            errors.append(f"release gate Python lock {lock_path} must contain only pinned packages, not pip options")
        blocks = [
            block
            for block in content.split("\n\n")
            if REQUIREMENT_LINE_PATTERN.search(block)
        ]
        if not blocks:
            errors.append(f"release gate Python lock {lock_path} has no pinned packages")
            continue
        for block in blocks:
            lines = [
                line.rstrip()
                for line in block.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if not lines:
                continue
            if REQUIREMENT_LINE_PATTERN.match(lines[0]) is None:
                errors.append(f"release gate Python lock {lock_path} has unpinned requirement: {lines[0]}")
            if not any("--hash=sha256:" in line for line in lines):
                errors.append(f"release gate Python lock {lock_path} requirement missing hash: {lines[0]}")
    return errors


def main() -> int:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).exists()]
    if missing:
        for path in missing:
            print(f"release gate missing file: {path}", file=sys.stderr)
        return 1

    combined = "\n".join(read(path) for path in REQUIRED_FILES)
    failed = False
    for term in REQUIRED_TERMS:
        if term not in combined:
            print(f"release gate missing required term: {term}", file=sys.stderr)
            failed = True
    for claim in FORBIDDEN_CLAIMS:
        if claim in combined:
            print(f"release gate forbidden claim present: {claim}", file=sys.stderr)
            failed = True
    for error in assert_workflow_actions_are_pinned():
        print(error, file=sys.stderr)
        failed = True
    for error in assert_python_dependencies_are_hash_locked():
        print(error, file=sys.stderr)
        failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
