"""Capture the full live demo run to a file."""
import os, sys, io, logging, subprocess, pathlib

result = subprocess.run(
    [sys.executable, "run_live.py"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    cwd=str(pathlib.Path(__file__).parent)
)

out_path = pathlib.Path(__file__).parent / "demo_output.txt"
with open(out_path, "w", encoding="utf-8") as f:
    f.write("=== STDOUT ===\n")
    f.write(result.stdout)
    f.write("\n=== STDERR (last 50 lines) ===\n")
    stderr_lines = result.stderr.splitlines()[-50:]
    f.write("\n".join(stderr_lines))
    f.write(f"\n=== EXIT CODE: {result.returncode} ===\n")

print(result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout)
print(f"\n[exit code: {result.returncode}]")
if result.returncode != 0:
    print("--- LAST STDERR ---")
    print("\n".join(result.stderr.splitlines()[-20:]))
