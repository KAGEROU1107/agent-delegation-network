"""Direct demo runner — writes output to demo_proof.txt"""
import os, sys, logging

os.environ.setdefault("T3_MOCK", "false")
# T3N_API_KEY and DID must be set in the environment before running this script.

logging.disable(9999)
sys.path.insert(0, os.path.dirname(__file__))

import io
buf = io.StringIO()
real_stdout = sys.stdout
sys.stdout = buf

try:
    from demo.adn_demo import main
    code = main() or 0
except Exception as exc:
    import traceback
    buf.write(f"\nFATAL: {exc}\n")
    traceback.print_exc(file=buf)
    code = 1

sys.stdout = real_stdout
output = buf.getvalue()

out_path = os.path.join(os.path.dirname(__file__), "demo_proof.txt")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(output)

print(output)
sys.exit(code)
