import assert from "assert/strict";
import { runAdnWithRealDid } from "../src/adn_runner.ts";

const pythonExecutable = process.platform === "win32" ? "python" : "python3";
const previousRuntimeMode = process.env.ADN_RUNTIME_MODE;

try {
  // runAdnWithRealDid must throw immediately in live mode.
  process.env.ADN_RUNTIME_MODE = "live";
  let threwCorrectError = false;
  try {
    await runAdnWithRealDid("did:example:tenant", {}, {}, {}, { pythonExecutable });
  } catch (e) {
    threwCorrectError = /blocked in live mode/.test(e.message);
  }
  assert.equal(threwCorrectError, true, "runAdnWithRealDid must throw 'blocked in live mode' when ADN_RUNTIME_MODE=live");
  console.log("✓ runAdnWithRealDid throws in live mode");

  // In demo mode the guard must not fire (other errors are acceptable).
  process.env.ADN_RUNTIME_MODE = "demo";
  let threwLiveModeError = false;
  try {
    await runAdnWithRealDid("did:example:tenant", {}, {}, {}, { pythonExecutable });
  } catch (e) {
    threwLiveModeError = /blocked in live mode/.test(e.message);
  }
  assert.equal(threwLiveModeError, false, "runAdnWithRealDid must NOT throw live-mode guard when ADN_RUNTIME_MODE=demo");
  console.log("✓ runAdnWithRealDid does not throw live-mode guard in demo mode");

  console.log("\nAll legacy_guard tests passed.");
} finally {
  if (previousRuntimeMode === undefined) delete process.env.ADN_RUNTIME_MODE;
  else process.env.ADN_RUNTIME_MODE = previousRuntimeMode;
}
