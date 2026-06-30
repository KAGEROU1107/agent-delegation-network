#!/usr/bin/env node
/**
 * CI audit — blocks any forbidden legacy private-key symbol from appearing outside
 * their designated deprecated-stub locations.
 *
 * Allowed to contain these symbols (excluded from scan):
 *   t3n-bridge/src/adn_runner.ts       — deprecated stubs with live-mode guards
 *   t3n-bridge/src/gateway_executor.ts — key isolated inside executor process
 *   t3n-bridge/test/**                 — test files may import stubs for guard-tests
 *   adn/worker_executor.py             — legitimate worker executor
 *
 * Any other scanned file that references a forbidden symbol causes exit 1.
 * Run: node scripts/audit_legacy_imports.mjs
 */

import { readFileSync, readdirSync } from "fs";
import { join, extname } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

const FORBIDDEN_SYMBOLS = [
  "runAdnWithRealDid",
  "requireConfiguredGatewayKeyBundleFromEnv",
  "GatewayKeyBundle",
  "privateKeyHex",
  "ADN_GATEWAY_KEY_BUNDLE_PATH",
  "restore_gateway_identity",
  "prepareGatewayKeyBundle",
];

// Files allowed to contain forbidden symbols (relative to ROOT, forward slashes)
const ALLOWED_FILES = new Set([
  "t3n-bridge/src/adn_runner.ts",
  "t3n-bridge/src/gateway_executor.ts",
  "adn/worker_executor.py",
]);

// Directories to scan (relative to ROOT)
const SCAN_DIRS = [
  { dir: join(ROOT, "t3n-bridge", "src"), base: "t3n-bridge/src" },
  { dir: join(ROOT, "adn"), base: "adn" },
];

const SCAN_EXTENSIONS = new Set([".ts", ".py", ".mjs", ".js"]);

let violations = 0;
const findings = [];

for (const { dir, base } of SCAN_DIRS) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    continue;
  }

  for (const file of entries) {
    if (!SCAN_EXTENSIONS.has(extname(file))) continue;
    const relPath = `${base}/${file}`;
    if (ALLOWED_FILES.has(relPath)) continue;

    const fullPath = join(dir, file);
    let content;
    try {
      content = readFileSync(fullPath, "utf-8");
    } catch {
      continue;
    }
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const symbol of FORBIDDEN_SYMBOLS) {
        if (line.includes(symbol)) {
          findings.push({ file: relPath, line: i + 1, symbol, text: line.trim().slice(0, 120) });
          violations++;
        }
      }
    }
  }
}

if (violations === 0) {
  console.log("[audit] ✓ No forbidden legacy symbols found in live-path source files.");
  process.exit(0);
} else {
  console.error(`[audit] ✗ Found ${violations} violation(s) — forbidden symbols in live-path source:`);
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}  symbol '${f.symbol}':  ${f.text}`);
  }
  console.error("");
  console.error("[audit] These symbols must only exist in deprecated stubs (adn_runner.ts) or gateway_executor.ts.");
  process.exit(1);
}
