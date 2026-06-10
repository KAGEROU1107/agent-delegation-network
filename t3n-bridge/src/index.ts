/**
 * Terminal 3 Agent Delegation Network — ADK Bridge
 *
 * Full integration demo:
 * 1. Authenticate with Terminal 3 testnet (real T3nClient.handshake + authenticate)
 * 2. Obtain real DID from authenticated session (NOT hardcoded)
 * 3. Spawn Python ADN with real DID injected as coordinator identity
 * 4. Run multi-agent delegation workflow (4 distinct Ed25519 identities)
 * 5. [Optional] Register and invoke TEE contract if WASM available
 *
 * Usage:
 *   T3N_API_KEY=0x<key> node --loader ts-node/esm src/index.ts
 */

import { createT3nSession } from "./t3n_auth.js";
import { runAdnWithRealDid } from "./adn_runner.js";
import { registerAdnContract, invokeProcessData, invokeValidateQuality, fetchContractLogs } from "./contract_bridge.js";
import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, "../../contract/target/wasm32-wasip2/release/adn_processor.wasm");

async function main() {
  const apiKey = process.env.T3N_API_KEY;
  if (!apiKey) {
    console.error("ERROR: T3N_API_KEY environment variable is required.");
    process.exit(1);
  }

  console.log("=== Terminal 3 Agent Delegation Network — Full ADK Demo ===\n");

  // ── Phase 1: Real T3N Authentication ────────────────────────────────────────
  console.log("[Phase 1] Authenticating with Terminal 3 testnet...");
  let session;
  try {
    session = await createT3nSession(apiKey);
    console.log(`  [+] handshake() complete`);
    console.log(`  [+] authenticate() complete`);
    console.log(`  [+] Authenticated DID (from session): ${session.tenantDid}`);
    console.log(`  [+] Ethereum address: ${session.address}`);
    console.log(`  [+] TenantClient initialized`);
  } catch (err) {
    console.error(`  [-] T3N auth failed: ${(err as Error).message}`);
    console.log("\n  Note: Auth requires a valid T3N testnet API key and network access.");
    console.log("  The Python ADN layer (delegation protocol, Ed25519 signing,");
    console.log("  multi-agent identity, tamper detection) is fully functional");
    console.log("  independently of T3N network connectivity.\n");
    process.exit(1);
  }

  const { t3n, tenant, tenantDid } = session;

  // ── Phase 2: Python ADN with real DID ───────────────────────────────────────
  console.log("\n[Phase 2] Running Python ADN with authenticated DID...");
  console.log(`  DID injected into coordinator: ${tenantDid}`);

  let adnResult;
  try {
    adnResult = await runAdnWithRealDid(apiKey, tenantDid);
    console.log(`  [+] Unique cryptographic identities: ${adnResult.uniqueIdentities}/4`);
    console.log(`  [+] Records processed: ${adnResult.recordsProcessed}`);
    console.log(`  [+] Total revenue: $${adnResult.totalRevenue}`);
    console.log(`  [+] Quality score: ${adnResult.qualityScore} | passed: ${adnResult.qualityPassed}`);
    console.log(`  [+] Coordinator DID matches session: ${adnResult.coordinatorDid === tenantDid}`);
  } catch (err) {
    console.error(`  [-] ADN execution failed: ${(err as Error).message}`);
    process.exit(1);
  }

  // ── Phase 3: TEE Contract (if WASM compiled) ────────────────────────────────
  console.log("\n[Phase 3] TEE Contract...");

  let teeInvoked = false;
  if (!existsSync(WASM_PATH)) {
    console.log("  [~] WASM not yet compiled — skipping TEE invocation.");
    console.log("  Build the contract with:");
    console.log("    cd contract");
    console.log("    cargo build --target wasm32-wasip2 --release");
    console.log("  Then re-run this demo to enable Phase 3 (contract registration + invocation).");
  } else {
    try {
      console.log("  [+] Registering WASM contract with T3N...");
      const contractInfo = await registerAdnContract(tenant, tenantDid);
      console.log(`  [+] Registered: tail=${contractInfo.tail} version=${contractInfo.version}`);
      console.log(`  [+] Script: z:${tenantDid}:${contractInfo.tail}`);

      console.log("  [+] Invoking process-data in TEE...");
      const teeResult = await invokeProcessData(t3n, tenantDid, {
        data_source: "sales_database_v2",
        time_period: "Q1-2026",
        filters: ["region:US", "product_type:premium"],
      });
      console.log(`  [+] TEE result: ${teeResult.records_processed} records | avg=$${teeResult.avg_value}`);
      console.log(`  [+] processed_in_tee: ${teeResult.processed_in_tee}`);

      console.log("  [+] Invoking validate-quality in TEE...");
      const teeValidation = await invokeValidateQuality(t3n, tenantDid, teeResult as unknown as Record<string, unknown>);
      console.log(`  [+] TEE quality: score=${teeValidation.quality_score} | validated_in_tee: ${teeValidation.validated_in_tee}`);
      teeInvoked = true;

      const logs = await fetchContractLogs(tenant);
      if (logs.length > 0) console.log("  [+] Contract logs:", logs);
    } catch (err) {
      console.error(`  [-] Contract error: ${(err as Error).message}`);
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  console.log("\n" + "=".repeat(55));
  console.log("DEMO SUMMARY");
  console.log("=".repeat(55));
  console.log(`Real T3N auth:            YES`);
  console.log(`DID from session:         ${tenantDid}`);
  console.log(`Distinct agent identities: ${adnResult.uniqueIdentities}/4`);
  console.log(`Multi-agent delegation:   ${adnResult.success ? "PASSED" : "FAILED"}`);
  console.log(`Tamper detection:         ACTIVE (data_hash in signed payload)`);
  console.log(`WASM contract:            ${!existsSync(WASM_PATH) ? "NOT YET COMPILED" : teeInvoked ? "REGISTERED + INVOKED" : "REGISTERED (invocation failed)"}`);
  console.log("=".repeat(55));
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
