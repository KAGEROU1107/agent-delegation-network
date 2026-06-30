#!/usr/bin/env node
/**
 * CI audit — blocks any forbidden legacy private-key symbol from appearing outside
 * their designated deprecated-stub locations.
 *
 * Allowed to contain these symbols (excluded from scan):
 *   src/adn_runner.ts       — deprecated stubs with live-mode guards
 *   src/gateway_executor.ts — key isolated inside executor process
 *   ../adn/worker_executor.py — legitimate worker executor
 *
 * Scan scope:
 *   src/*.ts (except adn_runner.ts, gateway_executor.ts)
 *   ../adn/*.py (except worker_executor.py)
 *
 * Any file that references a forbidden symbol causes exit 1.
 */
import { readFileSync, readdirSync } from "fs";
import { join, extname, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const FORBIDDEN_SYMBOLS = [
  "runAdnWithRealDid",
  "requireConfiguredGatewayKeyBundleFromEnv",
  "GatewayKeyBundle",
  "privateKeyHex",
  "ADN_GATEWAY_KEY_BUNDLE_PATH",
  "restore_gateway_identity",
  "prepareGatewayKeyBundle",
];

const SCAN_DIRS = [
  {
    dir: join(__dirname, "../src"),
    ext: ".ts",
    skip: new Set(["adn_runner.ts", "gateway_executor.ts"]),
    label: "src",
  },
  {
    dir: join(__dirname, "../../adn"),
    ext: ".py",
    skip: new Set(["worker_executor.py"]),
    label: "adn",
  },
];

let violations = 0;
const findings = [];

for (const { dir, ext, skip, label } of SCAN_DIRS) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    continue;
  }

  for (const file of entries) {
    if (extname(file) !== ext) continue;
    if (skip.has(file)) continue;

    const content = readFileSync(join(dir, file), "utf-8");
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const symbol of FORBIDDEN_SYMBOLS) {
        if (line.includes(symbol)) {
          findings.push({ file: `${label}/${file}`, line: i + 1, symbol, text: line.trim().slice(0, 120) });
          violations++;
        }
      }
    }
  }
}

if (violations === 0) {
  console.log("[audit] ✓ No forbidden legacy symbols in live-path source files.");
  process.exit(0);
} else {
  console.error(`[audit] ✗ ${violations} violation(s) — forbidden symbols in live-path source:`);
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}  '${f.symbol}':  ${f.text}`);
  }
  console.error("");
  console.error("[audit] These symbols must only exist in deprecated stubs (adn_runner.ts) or gateway_executor.ts.");
  process.exit(1);
}
