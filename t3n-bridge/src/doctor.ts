import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  getRuntimeMode,
  requireReplayLedgerDir,
  resolveReplayKeyProvider,
} from "./runtime_config.js";

function assertWritableDirectory(dir: string): void {
  const probe = join(dir, `.adn-doctor-${process.pid}-${Date.now()}`);
  writeFileSync(probe, "ok", { encoding: "utf-8", mode: 0o600 });
  unlinkSync(probe);
}

async function main(): Promise<void> {
  // runtime doctor: validate local runtime safety before running the bridge.
  const tempDir = mkdtempSync(join(tmpdir(), "adn-doctor-"));
  try {
    const runtimeMode = getRuntimeMode();
    const replayLedgerDir = requireReplayLedgerDir(runtimeMode, tempDir);
    const replayKeyProvider = resolveReplayKeyProvider(runtimeMode);
    assertWritableDirectory(replayLedgerDir);
    console.log(JSON.stringify({
      status: "OK",
      runtimeMode,
      replayLedgerDir,
      replayKeyProvider: replayKeyProvider.source,
      replayKeyRef: replayKeyProvider.keyRef,
    }, null, 2));
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(`runtime doctor failed: ${(err as Error).message}`);
  process.exit(1);
});
