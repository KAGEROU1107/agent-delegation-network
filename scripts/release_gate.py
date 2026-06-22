"""Release-claim guard for ADN source and documentation."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "docs/release/criteria.md",
    "docs/security/claim-matrix.md",
    "docs/architecture/security-invariants.md",
]

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

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
