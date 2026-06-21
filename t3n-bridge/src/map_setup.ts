/**
 * TEE map setup — creates tenant KV maps with contract ACLs.
 *
 * Maps are optionally provisioned for a future state-capable contract; the
 * current WASM does not read or write them.
 *
 * Maps are created via TenantClient.maps.create().
 * contractId (number) is set as the sole writer and reader.
 */

import type { TenantClient } from "@terminal3/t3n-sdk";

export interface MapConfig {
  tail: string;
  description: string;
}

export const ADN_MAPS: MapConfig[] = [
  { tail: "auction-bids",    description: "Future state-capable blind auction bid storage" },
  { tail: "reputation-ledger", description: "Future state-capable agent reputation history" },
  { tail: "time-grants",     description: "Future state-capable temporal delegation grants" },
  { tail: "kyc-pipeline",    description: "Future state-capable KYC step completion records" },
  { tail: "agent-vault",     description: "Future state-capable secret vault storage" },
  { tail: "dao-votes",       description: "Future state-capable DAO vote records" },
  { tail: "decision-audit",  description: "Future state-capable AI decision audit trail" },
  { tail: "perf-bonds",      description: "Future state-capable performance bond escrow" },
];

export interface MapSetupResult {
  tail: string;
  created: boolean;
  error?: string;
}

/**
 * Create all ADN feature maps with contract-only ACLs when possible.
 *
 * contractId — numeric ID from register(). If undefined (BUG-001: SDK returns
 * no ID), map setup is skipped so ACLs are never weakened by a guessed or
 * historical contract ID.
 *
 * Safe to call repeatedly — skips maps that already exist.
 */
export async function setupAdnMaps(
  tenant: TenantClient,
  contractId: number | undefined
): Promise<MapSetupResult[]> {
  const results: MapSetupResult[] = [];

  // Fail closed: contract-only ACL is required. Callers must pass the ID returned
  // by the current contract registration rather than a guessed historical value.
  if (contractId === undefined) {
    throw new Error(
      "setupAdnMaps: contractId required for contract-only ACL — " +
      "refusing to create maps without the current deployed contract ID."
    );
  }
  const writers = { only: [contractId] };
  const readers = { only: [contractId] };
  console.log(`  [+] map ACL: contractId=${contractId} (contract-only ACL)`);

  for (const map of ADN_MAPS) {
    try {
      await tenant.maps.create({
        tail: map.tail,
        visibility: "private",
        writers,
        readers,
      });
      results.push({ tail: map.tail, created: true });
    } catch (err) {
      const msg = (err as Error).message ?? "";
      // Already exists → not a failure
      if (msg.includes("already exists") || msg.includes("conflict")) {
        results.push({ tail: map.tail, created: false });
      } else {
        results.push({ tail: map.tail, created: false, error: msg });
      }
    }
  }

  return results;
}

