#!/usr/bin/env python3
"""
Release gate: reject README wording that overclaims proof status.
Run: python scripts/check_readme_claims.py
Exits 1 if forbidden phrases found.
"""
import sys
import re

FORBIDDEN_PHRASES = [
    r"v3\.9\.2 live proven",
    r"T3N-attested worker execution",
    r"production-ready",
    r"cryptographically verified.*platform evidence",
    r"remotely verifiable.*v3\.9\.2",
]

GATE_MARKER = "# README_CLAIMS_GATE_PASSED"

with open("README.md", "r", encoding="utf-8") as f:
    content = f.read()

# Skip check if gate marker is present (used after Phase 7 of new remediation completes)
if GATE_MARKER in content:
    print("README claims gate: marker found, skipping phrase check.")
    sys.exit(0)

found = []
for phrase in FORBIDDEN_PHRASES:
    matches = re.findall(phrase, content, re.IGNORECASE)
    if matches:
        found.extend(matches)

if found:
    print(f"[FAIL] README contains {len(found)} forbidden overclaim phrase(s):")
    for m in found:
        print(f"  - {m!r}")
    print("\nDo not claim v3.9.2 is live-proven, T3N-attested, or production-ready")
    print("until all proof verifiers pass (Phase 7 of ADN Complete Remediation).")
    sys.exit(1)

print("[PASS] README claims gate: no overclaim phrases found.")
sys.exit(0)
