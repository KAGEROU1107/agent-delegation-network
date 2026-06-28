"""Run the official ADN live TypeScript bridge.

This wrapper exists for reviewers who look for a root-level live runner. It does
not load `.env`; live mode must receive secrets from the shell or service
environment, matching the bridge's current security boundary.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BRIDGE_DIR = ROOT / "t3n-bridge"


def main() -> int:
    env = os.environ.copy()
    env["ADN_RUNTIME_MODE"] = "live"
    print("[ADN LIVE] Running official T3N bridge: npm run live", flush=True)
    print("[ADN LIVE] Working directory:", BRIDGE_DIR, flush=True)
    return subprocess.call(["npm", "run", "live"], cwd=BRIDGE_DIR, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
