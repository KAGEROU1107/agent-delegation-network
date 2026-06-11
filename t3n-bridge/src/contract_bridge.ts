/**
 * TEE contract management: registration and invocation via Terminal 3 ADK.
 *
 * Invocation uses T3nClient.executeAndDecode() with the explicit
 * script_name / script_version / function_name / input payload.
 * script_name format: z:<40-hex-tid>:<tail>  (strip "did:t3n:" prefix)
 */

import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import type { TenantClient, T3nClient } from "@terminal3/t3n-sdk";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, "../../contract/target/wasm32-wasip2/release/adn_processor.wasm");
const CONTRACT_TAIL = "adn-processor";
const CONTRACT_VERSION = "3.5.0";

export interface ContractInfo {
  tail: string;
  version: string;
  tenantDid: string;
}

export async function registerAdnContract(
  tenant: TenantClient,
  tenantDid: string
): Promise<ContractInfo> {
  if (!existsSync(WASM_PATH)) {
    throw new Error(`WASM not found at ${WASM_PATH}. Run: cd contract && cargo build --target wasm32-wasip2 --release`);
  }

  const wasm = readFileSync(WASM_PATH);
  try {
    await tenant.contracts.register({ tail: CONTRACT_TAIL, version: CONTRACT_VERSION, wasm });
  } catch (err) {
    const msg = (err as Error).message ?? "";
    if (!msg.includes("not higher") && !msg.includes("already enabled")) throw err;
  }

  return { tail: CONTRACT_TAIL, version: CONTRACT_VERSION, tenantDid };
}

export async function invokeProcessData(
  t3n: T3nClient,
  tenantDid: string,
  params: { data_source: string; time_period: string; filters: string[]; records: number[] }
): Promise<ProcessDataResult> {
  const tid = tenantDid.slice("did:t3n:".length);
  return t3n.executeAndDecode<ProcessDataResult>({
    script_name: `z:${tid}:${CONTRACT_TAIL}`,
    script_version: CONTRACT_VERSION,
    function_name: "process-data",
    input: params,
  });
}

export async function invokeValidateQuality(
  t3n: T3nClient,
  tenantDid: string,
  data: Record<string, unknown>
): Promise<QualityResult> {
  const tid = tenantDid.slice("did:t3n:".length);
  return t3n.executeAndDecode<QualityResult>({
    script_name: `z:${tid}:${CONTRACT_TAIL}`,
    script_version: CONTRACT_VERSION,
    function_name: "validate-quality",
    input: data,
  });
}

export async function fetchContractLogs(tenant: TenantClient): Promise<string[]> {
  try {
    const result = await tenant.contracts.logs(CONTRACT_TAIL, { limit: 20 });
    return result.entries.map((e) => `[${e.level}] ${e.message}`);
  } catch {
    return [];
  }
}

export interface ProcessDataResult {
  records_processed: number;
  total_revenue: number;
  avg_value: number;
  min_value: number;
  max_value: number;
  trend: string;
  processed_in_tee: boolean;
}

export interface QualityResult {
  quality_score: number;
  passed: boolean;
  issues: string[];
  validated_in_tee: boolean;
}
