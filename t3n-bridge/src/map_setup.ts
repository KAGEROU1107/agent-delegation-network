/**
 * TEE map setup — creates tenant KV maps with contract ACLs.
 *
 * Each feature phase uses a dedicated map so data is isolated per-phase.
 * Maps are private to the ADN contract — other contracts can't read them.
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
  { tail: "auction-bids",    description: "Phase 2 — blind auction bid storage" },
  { tail: "reputation-ledger", description: "Phase 3 — agent reputation history" },
  { tail: "time-grants",     description: "Phase 5 — temporal delegation grants" },
  { tail: "kyc-pipeline",    description: "Phase 7 — KYC step completion records" },
  { tail: "agent-vault",     description: "Phase 8 — TEE secret vault storage" },
  { tail: "dao-votes",       description: "Phase 9 — DAO vote records" },
  { tail: "decision-audit",  description: "Phase 10 — AI decision audit trail" },
  { tail: "perf-bonds",      description: "Phase 11 — performance bond escrow" },
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
 * no ID), maps are created with writers:"all" as a documented workaround so the
 * map layer is exercised even without per-contract ACL gating. See bugs_found.md.
 *
 * Safe to call repeatedly — skips maps that already exist.
 */
export async function setupAdnMaps(
  tenant: TenantClient,
  contractId: number | undefined
): Promise<MapSetupResult[]> {
  const results: MapSetupResult[] = [];

  // BUG-001 workaround: fall back to open write access when contractId unavailable.
  const writers = contractId !== undefined ? { only: [contractId] } : ("all" as const);
  const readers = contractId !== undefined ? { only: [contractId] } : ("all" as const);

  if (contractId !== undefined) {
    console.log(`  [+] map ACL: using contractId: ${contractId} (contract-only ACL)`);
  } else {
    console.log("  [!] map ACL: using writers/readers:'all' — BUG-001 workaround (no contractId from register())");
  }

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
