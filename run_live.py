"""Run the ADN demo with real T3N credentials and print full output."""
import os, sys, io, logging
from pathlib import Path
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Load .env from project root if present
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

# Credentials loaded from environment (set T3N_API_KEY, DID, T3_MOCK before running)
os.environ.setdefault("T3_MOCK", "false")
os.environ["PYTHONIOENCODING"] = "utf-8"

# Suppress INFO logs for clean output
logging.disable(logging.WARNING)

sys.path.insert(0, ".")
from src.terminal3_agent_auth_adapter import _is_mock
print(f"[LIVE MODE: T3_MOCK={_is_mock()}]")
print()

from demo.adn_demo import main
sys.exit(main())
