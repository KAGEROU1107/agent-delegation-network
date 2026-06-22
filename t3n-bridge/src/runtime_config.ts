import { randomBytes } from "crypto";
import { chmodSync, mkdirSync, readFileSync } from "fs";
import { resolve, sep } from "path";

export type AdnRuntimeMode = "live" | "test" | "demo";

export interface ReplayKeyProvider {
  source: "file" | "env-test-only" | "generated-test-only";
  keyRef: string;
  keyHex: string;
}

export function requireHexSecret(value: string | undefined, name: string): string {
  const normalized = value?.trim().replace(/^0x/i, "").toLowerCase();
  if (!normalized) {
    throw new Error(`${name} is required`);
  }
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`${name} must be 32 bytes of hex, with or without 0x.`);
  }
  return normalized;
}

export function requireHexEnv(name: string): string {
  return requireHexSecret(process.env[name], name);
}

export function getRuntimeMode(): AdnRuntimeMode {
  const mode = (process.env.ADN_RUNTIME_MODE ?? "live").trim().toLowerCase();
  if (mode !== "live" && mode !== "test" && mode !== "demo") {
    throw new Error("ADN_RUNTIME_MODE must be live, test, or demo");
  }
  return mode;
}

function pathIsInside(childPath: string, parentPath: string): boolean {
  const child = resolve(childPath);
  const parent = resolve(parentPath);
  return child === parent || child.startsWith(parent.endsWith(sep) ? parent : `${parent}${sep}`);
}

export function requireReplayLedgerDir(runtimeMode: AdnRuntimeMode, tempDir: string): string {
  const configured = process.env.ADN_REPLAY_LEDGER_DIR?.trim();
  if (runtimeMode === "live" && !configured) {
    throw new Error("ADN_REPLAY_LEDGER_DIR is required for durable live replay protection");
  }
  const dir = configured || `${tempDir}${sep}replay-ledger`;
  if (runtimeMode === "live" && pathIsInside(dir, tempDir)) {
    throw new Error("ADN_REPLAY_LEDGER_DIR must not be inside the bridge transient workspace");
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  return dir;
}

function readFileKey(ref: string): string {
  const path = ref.slice("file:".length);
  if (!path) {
    throw new Error("ADN_REPLAY_LEDGER_KEY_REF file provider requires file:<path>");
  }
  return requireHexSecret(readFileSync(path, "utf-8"), `ADN_REPLAY_LEDGER_KEY_REF ${ref}`);
}

export function resolveReplayKeyProvider(runtimeMode: AdnRuntimeMode): ReplayKeyProvider {
  const rawEnvSecret = process.env.ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX?.trim();
  const keyRef = process.env.ADN_REPLAY_LEDGER_KEY_REF?.trim();

  if (runtimeMode === "live") {
    if (rawEnvSecret) {
      throw new Error(
        "ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX is not accepted in live mode; " +
        "set ADN_REPLAY_LEDGER_KEY_REF=file:<path-to-0600-hex-key> or a supported secret-manager reference."
      );
    }
    if (!keyRef) {
      throw new Error("ADN_REPLAY_LEDGER_KEY_REF is required for durable live replay protection");
    }
    if (!keyRef.startsWith("file:")) {
      throw new Error(
        "ADN_REPLAY_LEDGER_KEY_REF provider is not supported in this build; use file:<path-to-0600-hex-key>."
      );
    }
    return {
      source: "file",
      keyRef,
      keyHex: readFileKey(keyRef),
    };
  }

  if (keyRef?.startsWith("file:")) {
    return {
      source: "file",
      keyRef,
      keyHex: readFileKey(keyRef),
    };
  }

  if (rawEnvSecret) {
    return {
      source: "env-test-only",
      keyRef: keyRef || "env:ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX",
      keyHex: requireHexSecret(rawEnvSecret, "ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX"),
    };
  }

  return {
    source: "generated-test-only",
    keyRef: keyRef || "transient-local-test-key",
    keyHex: randomBytes(32).toString("hex"),
  };
}
