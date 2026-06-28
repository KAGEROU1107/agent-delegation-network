#!/usr/bin/env node
// CI guard: fails if any src/*.ts file (except adn_runner.ts) imports legacy symbols
import { readFileSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = join(__dirname, "../src");
const FORBIDDEN = ["runAdnWithRealDid", "requireConfiguredGatewayKeyBundleFromEnv"];

let failed = false;
for (const f of readdirSync(SRC)) {
  if (!f.endsWith(".ts")) continue;
  if (f === "adn_runner.ts") continue; // definitions live here
  const src = readFileSync(join(SRC, f), "utf8");
  for (const sym of FORBIDDEN) {
    if (src.includes(sym)) {
      console.error(`AUDIT FAIL: ${f} uses legacy symbol: ${sym}`);
      failed = true;
    }
  }
}
if (failed) process.exit(1);
console.log("Audit passed — no production imports of legacy private-key symbols.");
