"""Run the ADN demo with real T3N credentials and print full output."""
import os, sys, io, logging
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

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
