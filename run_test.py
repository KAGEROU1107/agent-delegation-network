"""Quick test runner — captures demo output and verifies it ran correctly."""
import os, sys, io
os.environ["T3_MOCK"] = "true"
os.environ["PYTHONIOENCODING"] = "utf-8"

# Capture stdout
old_stdout = sys.stdout
sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")

sys.path.insert(0, ".")
try:
    from demo.adn_demo import main
    exit_code = main()
except Exception as e:
    print(f"EXCEPTION: {e}", file=sys.stderr)
    import traceback; traceback.print_exc()
    exit_code = 1
finally:
    sys.stdout.seek(0)
    output = sys.stdout.buffer.read().decode("utf-8")
    sys.stdout = old_stdout

print(output)
print(f"\n--- exit code: {exit_code} ---")
