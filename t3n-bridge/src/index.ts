/**
 * Terminal 3 Agent Delegation Network — ADK Bridge
 *
 * Full live bridge run:
 * 1. Authenticate with Terminal 3 testnet (real T3nClient.handshake + authenticate)
 * 2. Obtain real DID from authenticated session (NOT hardcoded)
 * 3. Spawn Python ADN with real DID passed as session context
 * 4. Run multi-agent delegation workflow (4 distinct Ed25519 identities)
 * 5. [Optional] Register and invoke TEE contract if WASM available
 *
 * Usage:
 *   T3N_API_KEY=0x<key> ADN_RUNTIME_MODE=live ADN_BUILD_COMMIT=<commit> ADN_RUSTC_VERSION="<rustc --version>" ADN_TRUSTED_ISSUER=<issuer> ADN_TENANT_DID=<tenant-did> ADN_GATEWAY_PRIVATE_KEY_HEX=<ed25519-seed-hex> ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX=<ed25519-pubkey-hex> [ADN_GATEWAY_KEY_ID=<key-id>] npm run live
 */

import { createT3nSession } from "./t3n_auth.js";
import {
  prepareAdnExecution,
  runAdnWithSignedGateway,
  type TeeAuthorizationResult,
} from "./adn_runner.js";
import { spawnGatewayExecutor } from "./gateway_client.js";
import {
  registerAdnContract,
  recordFirstInvocationDigest,
  type ContractInfo,
  invokeProcessData, invokeValidateQuality,
  invokeDelegateTask,
  invokeSubmitBid, invokeResolveAuction,
  invokeRecordCompletion, invokeGetReputation,
  invokeSendPersonalizedOutreach,
  invokeIssueTimeGrant, invokeCheckGrant,
  invokeKycSubmitStep, invokeKycGetStatus,
  invokeStoreSecret, invokeInvokeWithSecret,
  invokeCastVote, invokeTallyVotes,
  invokeLogDecision, invokeAuditDecisions,
  invokeLockBond, invokeVerifyAndSettle,
  fetchContractLogs,
} from "./contract_bridge.js";
import { demonstrateAgentAuth, demonstrateNegativeEnvelopeTests, buildWireDelegationEnvelope } from "./agent_auth.js";
import { setupAdnMaps } from "./map_setup.js";
import { getRuntimeMode } from "./runtime_config.js";
import { b64uEncodeBytes } from "@terminal3/t3n-sdk";
import { existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

export {
  T3nAttestedEvidenceVerifier,
  buildEvidenceFromReceipt,
  type T3nInvocationEvidence,
  type T3nPlatformReceipt,
  type EvidenceVerificationResult,
  type EvidenceMode,
} from "./t3n_evidence.js";
export { verifyPlatformSignature, type T3nTrustAnchor } from "./t3n_evidence_crypto.js";
export { WorkerExecutorClient } from "./worker_client.js";
export type { WorkerPublicIdentity, WorkerSignResult } from "./worker_client.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, "../../contract/target/wasm32-wasip2/release/adn_processor.wasm");

// Load .env from project root if env vars not already set
const _envPath = join(__dirname, "../../.env");
function loadDotEnvIfAllowed(): void {
  if (!existsSync(_envPath)) {
    return;
  }
  if (getRuntimeMode() === "live") {
    console.log("  [~] Skipping .env load in live mode; provide production secrets through the service environment or key provider.");
    return;
  }
  for (const _line of readFileSync(_envPath, "utf-8").split("\n")) {
    const _t = _line.trim();
    if (_t && !_t.startsWith("#") && _t.includes("=")) {
      const _eq = _t.indexOf("=");
      const _k = _t.slice(0, _eq).trim();
      const _v = _t.slice(_eq + 1).trim();
      if (_k && !process.env[_k]) process.env[_k] = _v;
    }
  }
}
loadDotEnvIfAllowed();
const CSV_PATH = join(__dirname, "../../data/sales_Q1-2026_US_premium.csv");

function normalizeAddress(value: string): string {
  return value.trim().replace(/^0x/i, "").toLowerCase();
}

function requirePinnedRuntimeConfig(authenticatedAddress: string, authenticatedTenantDid: string): void {
  const pinnedIssuer = process.env.ADN_TRUSTED_ISSUER;
  if (!pinnedIssuer) {
    throw new Error(
      "ADN_TRUSTED_ISSUER is required before registering the v3.9.2 WASM contract. " +
      "Run `T3N_API_KEY=0x<key> node scripts/derive_issuer.mjs`, then rebuild the contract pinned to that issuer."
    );
  }

  const normalizedPinned = normalizeAddress(pinnedIssuer);
  const normalizedAuthenticated = normalizeAddress(authenticatedAddress);

  if (!/^[0-9a-f]{40}$/.test(normalizedPinned)) {
    throw new Error("ADN_TRUSTED_ISSUER must be a 40-hex Ethereum address, with or without 0x.");
  }
  if (normalizedPinned !== normalizedAuthenticated) {
    throw new Error(
      `ADN_TRUSTED_ISSUER does not match authenticated T3N issuer: expected 0x${normalizedAuthenticated}, got 0x${normalizedPinned}.`
    );
  }

  const pinnedTenantDid = process.env.ADN_TENANT_DID;
  if (!pinnedTenantDid) {
    throw new Error("ADN_TENANT_DID is required before registering the v3.9.2 WASM contract.");
  }
  if (pinnedTenantDid.trim() !== authenticatedTenantDid) {
    throw new Error(
      `ADN_TENANT_DID does not match authenticated T3N tenant DID: expected ${authenticatedTenantDid}, got ${pinnedTenantDid.trim()}.`
    );
  }

  console.log(`  [+] Pinned issuer matches authenticated T3N issuer: 0x${normalizedPinned}`);
  console.log(`  [+] Pinned tenant DID matches authenticated T3N tenant: ${authenticatedTenantDid}`);
}

function parseSaleAmounts(): number[] {
  const lines = readFileSync(CSV_PATH, "utf-8").trim().split("\n");
  // Header: id,region,product_type,sale_amount,sale_date,sales_rep
  return lines.slice(1).map((l) => parseFloat(l.split(",")[3])).filter((v) => !isNaN(v));
}

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

  // ── Contract pre-registration (before Phase 0 so the contract exists when called) ──
  // Cache the result: the first register() call is most likely to return contractId.
  // If Phase 3 re-registers the same version, the SDK may suppress the response.
  let preRegisteredContract: ContractInfo | null = null;
  if (existsSync(WASM_PATH)) {
    requirePinnedRuntimeConfig(session.address, session.tenantDid);
    preRegisteredContract = await registerAdnContract(tenant, tenantDid);
  }

  // ── Phase 0: Agent Auth SDK — User-to-Agent Delegation + Enforcement ─────────
  console.log("\n[Phase 0] Agent Auth SDK — delegation credential + enforcement cycle...");
  let agentAuthSucceeded = false;
  try {
    const authResult = await demonstrateAgentAuth(t3n, tenantDid, apiKey);
    console.log(`  [+] credential built: vc_id=${authResult.vcIdHex}`);
    console.log(`  [+] granted functions: ${authResult.grantedFunctions.join(", ")}`);
    console.log(`  [+] signed with EIP-191: user_sig=${authResult.userSigB64u.slice(0, 16)}...`);
    console.log(`  [+] envelope: agent_sig=${b64uEncodeBytes(authResult.envelope.agent_sig).slice(0, 16)}... nonce=${b64uEncodeBytes(authResult.envelope.nonce).slice(0, 8)}...`);
    console.log(`  [+] pre-revocation call:  ${authResult.preRevocationCallResult}`);
    if (!authResult.preRevocationCallResult.startsWith("ACCEPTED"))  throw new Error(`AgentAuth: pre-revocation call not accepted: ${authResult.preRevocationCallResult.slice(0, 80)}`);
    if (authResult.revoked) {
      console.log(`  [+] revocation: SUCCESS (tee:delegation/contracts::revoke)`);
    } else {
      console.log(`  [~] revocation: ${authResult.revokeError ?? "no error"}`);
    }
    const postLabel = authResult.postRevocationCallResult.startsWith("REJECTED") ? "[+]" : "[-]";
    console.log(`  ${postLabel} post-revocation call: ${authResult.postRevocationCallResult}`);
    if (!authResult.postRevocationCallResult.startsWith("REJECTED"))  throw new Error(`AgentAuth: post-expiry call not rejected: ${authResult.postRevocationCallResult.slice(0, 80)}`);

    // ── Negative envelope rejection tests (v3.9.2 hardening proof) ────────────
    console.log("  [+] Negative envelope tests — proving v3.9.2 cryptographic contract-layer verification...");
    const negResults = await demonstrateNegativeEnvelopeTests(t3n, tenantDid, apiKey);
    const sigLabel   = negResults.missingSig.startsWith("REJECTED")  ? "[+]" : "[-]";
    const nonceLabel = negResults.shortNonce.startsWith("REJECTED")  ? "[+]" : "[-]";
    const envLabel   = negResults.noEnvelope.startsWith("REJECTED")  ? "[+]" : "[-]";
    console.log(`  ${sigLabel}   missing agent_sig:    ${negResults.missingSig}`);
    console.log(`  ${nonceLabel} short nonce (4 bytes): ${negResults.shortNonce}`);
    console.log(`  ${envLabel}   no envelope at all:   ${negResults.noEnvelope}`);
    if (!negResults.missingSig.startsWith("REJECTED"))  throw new Error("C-01: empty agent_sig was accepted by contract");
    if (!negResults.shortNonce.startsWith("REJECTED"))  throw new Error("C-01: short nonce was accepted by contract");
    if (!negResults.noEnvelope.startsWith("REJECTED"))  throw new Error("C-01: missing envelope was ACCEPTED — mandatory enforcement broken");
    agentAuthSucceeded = true;
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.startsWith("C-01:") || msg.startsWith("AgentAuth:")) { console.error(`  [-] FATAL: ${msg}`); process.exit(1); }
    console.error(`  [-] Agent Auth error: ${msg}`);
  }

  // ── Phase 2: Python ADN with real DID ───────────────────────────────────────
  console.log("\n[Phase 2] Running Python ADN with authenticated DID...");
  console.log(`  DID injected into coordinator: ${tenantDid}`);

  let adnResult;
  try {
    if (!preRegisteredContract) {
      throw new Error(
        "Live Python ADN execution now requires a compiled v3.9.2 WASM contract, " +
        "because workers only accept real delegate-task authorization results."
      );
    }

    // Phase 2: spawn isolated executor — reads and scrubs ADN_GATEWAY_PRIVATE_KEY_HEX from THIS process
    console.log("  [+] Spawning gateway executor (Phase 2 security boundary)...");
    const gatewayClient = await spawnGatewayExecutor();
    const gatewayPubInfo = await gatewayClient.getPublicInfo();
    console.log(`  [+] Executor ready — gateway key id: ${gatewayPubInfo.gatewayKeyId}`);
    console.log(`  [+] ADN_GATEWAY_PRIVATE_KEY_HEX scrubbed from bridge process env`);

    const preparedExecution = await prepareAdnExecution(tenantDid);
    console.log(`  [+] Prepared worker target for PROCESS_DATA: ${preparedExecution.worker1.agentId}`);
    console.log(`  [+] Prepared worker target for VALIDATE_QUALITY: ${preparedExecution.validator.agentId}`);
    console.log(`  [+] Trusted gateway key id: ${gatewayPubInfo.gatewayKeyId}`);

    const expectedBuildConfigId = preRegisteredContract.deploymentManifest.build_config_id;

    const authorizeWorkerTarget = async (
      targetAgentId: string,
      action: "PROCESS_DATA" | "VALIDATE_QUALITY"
    ): Promise<TeeAuthorizationResult> => {
      const delegationEnvelope = await buildWireDelegationEnvelope(tenantDid, targetAgentId, apiKey, { action });
      const result = await invokeDelegateTask(t3n, tenantDid, {
        to_agent_id: targetAgentId,
        action,
        __delegation_envelope: delegationEnvelope,
      });
      if (result.status !== "ROUTED") {
        throw new Error(`delegate-task for ${action} did not return ROUTED`);
      }
      if (result.routed_to !== targetAgentId) {
        throw new Error(`delegate-task for ${action} returned unexpected target ${result.routed_to}`);
      }
      if (result.credential_enforced !== true) {
        throw new Error(`delegate-task for ${action} did not confirm credential_enforced=true`);
      }
      if (!result.credential_fingerprint) {
        throw new Error(`delegate-task for ${action} did not return credential_fingerprint`);
      }
      if (!result.build_config_id) {
        throw new Error(`delegate-task for ${action} did not return build_config_id`);
      }
      if (!result.authorization_expires_at) {
        throw new Error(`delegate-task for ${action} did not return authorization_expires_at`);
      }
      if (result.build_config_id !== expectedBuildConfigId) {
        throw new Error(
          `delegate-task for ${action} returned build_config_id ${result.build_config_id}, ` +
          `expected ${expectedBuildConfigId}`
        );
      }
      if (preRegisteredContract) {
        preRegisteredContract = recordFirstInvocationDigest(preRegisteredContract, result);
      }
      console.log(`  [+] delegate-task ${action}: ${result.delegation_id} -> ${result.routed_to}`);
      return {
        delegation_id: result.delegation_id,
        status: result.status,
        routed_to: result.routed_to,
        credential_fingerprint: result.credential_fingerprint,
        credential_enforced: result.credential_enforced,
        build_config_id: result.build_config_id,
        authorization_expires_at: result.authorization_expires_at,
      };
    };

    const teeAuthorizationBundle = {
      buildConfigId: expectedBuildConfigId,
      processData: await authorizeWorkerTarget(preparedExecution.worker1.agentId, "PROCESS_DATA"),
      validateQuality: await authorizeWorkerTarget(preparedExecution.validator.agentId, "VALIDATE_QUALITY"),
    };

    console.log("  [+] Real T3N authorization bundle acquired for prepared Python workers.");
    try {
      adnResult = await runAdnWithSignedGateway(tenantDid, preparedExecution, teeAuthorizationBundle, gatewayClient);
    } finally {
      gatewayClient.close();
    }
    console.log(`  [+] Unique cryptographic identities: ${adnResult.uniqueIdentities}/4`);
    console.log(`  [+] Records processed: ${adnResult.recordsProcessed}`);
    console.log(`  [+] Total revenue: $${adnResult.totalRevenue}`);
    console.log(`  [+] Quality score: ${adnResult.qualityScore} | passed: ${adnResult.qualityPassed}`);
    console.log(`  [+] Session DID injected correctly: ${adnResult.tenantDid === tenantDid}`);
  } catch (err) {
    console.error(`  [-] ADN execution failed: ${(err as Error).message}`);
    process.exit(1);
  }

  // ── Phase 3: TEE Contract (if WASM compiled) ────────────────────────────────
  console.log("\n[Phase 3] TEE Contract...");

  let teeInvoked = false;
  let allWitSucceeded = false;
  if (!existsSync(WASM_PATH)) {
    console.log("  [~] WASM not yet compiled — skipping TEE invocation.");
    console.log("  Build the contract with a pinned issuer/tenant:");
    console.log("    cd contract");
    console.log("    BUILD_COMMIT=$(git rev-parse HEAD)");
    console.log("    RUSTC_VERSION=\"$(rustc --version)\"");
    console.log("    ADN_BUILD_COMMIT=$BUILD_COMMIT ADN_RUSTC_VERSION=\"$RUSTC_VERSION\" ADN_TRUSTED_ISSUER=<issuer-address-without-0x> ADN_TENANT_DID=did:t3n:<tenant-hex> cargo build --locked --target wasm32-wasip2 --release");
    console.log("  Then re-run this demo to enable Phase 3 (contract registration + invocation).");
  } else {
    try {
      // Reuse pre-registration result to preserve contractId from the first register() call.
      let contractInfo = preRegisteredContract ?? await registerAdnContract(tenant, tenantDid);
      console.log(`  [+] Registered: tail=${contractInfo.tail} version=${contractInfo.version}`);

      console.log(`  [+] Script: z:${tenantDid.slice("did:t3n:".length)}:${contractInfo.tail}`);

      // ── Optional tenant KV maps: require a fresh contract ID for contract-only ACLs ──
      console.log("  [+] Setting up ADN tenant maps...");
      try {
        const mapResults = await setupAdnMaps(tenant, contractInfo.contractId);
        const created = mapResults.filter((r) => r.created).length;
        const skipped = mapResults.filter((r) => !r.created && !r.error).length;
        const failed = mapResults.filter((r) => r.error).map((r) => `${r.tail}:${r.error}`);
        console.log(`  [+] Maps: ${created} created, ${skipped} already existed${failed.length ? `, ${failed.length} failed: ${failed.join("; ")}` : ""}`);
      } catch (err) {
        console.log(`  [~] Map setup skipped: ${(err as Error).message}`);
      }

      console.log("  [+] Invoking process-data in TEE...");
      const salesRecords = parseSaleAmounts();
      console.log(`  [+] Sending ${salesRecords.length} sale records into TEE enclave for computation`);
      const teeResult = await invokeProcessData(t3n, tenantDid, {
        data_source: "sales_Q1-2026_US_premium.csv",
        time_period: "Q1-2026",
        filters: ["region:US", "product_type:premium"],
        records: salesRecords,
      });
      console.log(`  [+] TEE result: ${teeResult.records_processed} records | total=$${teeResult.total_revenue} | avg=$${teeResult.avg_value} | min=$${teeResult.min_value} | max=$${teeResult.max_value} | trend=${teeResult.trend}`);
      console.log(`  [+] processed_in_tee: ${teeResult.processed_in_tee}`);

      console.log("  [+] Invoking validate-quality in TEE...");
      const teeValidation = await invokeValidateQuality(t3n, tenantDid, teeResult as unknown as Record<string, unknown>);
      console.log(`  [+] TEE quality: score=${teeValidation.quality_score} | validated_in_tee: ${teeValidation.validated_in_tee}`);
      teeInvoked = true;

      const logs = await fetchContractLogs(tenant);
      if (logs.length > 0) console.log("  [+] Contract logs:", logs);

      // ── Negative live test: send invalid input to prove TEE enforces validation ─
      console.log("  [+] Negative test — empty records array (TEE must reject)...");
      try {
        await invokeProcessData(t3n, tenantDid, {
          data_source: "test", time_period: "Q1", filters: [], records: [],
        });
        console.log("  [-] UNEXPECTED: TEE accepted empty records (should have rejected)");
      } catch (err) {
        console.log(`  [+] TEE correctly rejected empty records: ${(err as Error).message.slice(0, 80)}`);
      }
    } catch (err) {
      console.error(`  [-] Contract error: ${(err as Error).message}`);
    }
  }

  // ── Phase 4: Full Contract Coverage — all 18 remaining WIT functions ─────────
  // Wait 65s for fuel_per_minute window to reset (Phase 3 used ~3 fuel units).
  console.log("\n[Phase 4] Full Feature Contract Coverage — invoking all 20 WIT exports...");
  console.log("  (waiting 65s for fuel window reset, then 7s/call — ~3 min total)");
  await new Promise(r => setTimeout(r, 65000));

  if (!existsSync(WASM_PATH)) {
    console.log("  [~] WASM not compiled — skipping Phase 4.");
  } else {
    const now = Math.floor(Date.now() / 1000);
    const workerDid = `did:key:ed25519:worker-demo-${now}`;
    const worker2Did = `did:key:ed25519:worker2-demo-${now}`;
    const agentDid = tenantDid;

    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

    let p4Passed = 0;
    let p4Failed = 0;
    const p4 = async (label: string, fn: () => Promise<unknown>) => {
      try {
        const r = await fn();
        console.log(`  [+] ${label}:`, JSON.stringify(r).slice(0, 120));
        p4Passed++;
      } catch (err) {
        console.error(`  [-] ${label}: ${(err as Error).message}`);
        p4Failed++;
      }
      await sleep(7000); // spread across fuel_per_minute window (~8 calls/min)
    };

    // C-01 fix: delegate-task now requires a signed credential envelope.
    // Build a fresh 5-minute credential so Phase 4 demonstrates authenticated delegation.
    const p4DelegEnv = await buildWireDelegationEnvelope(tenantDid, workerDid, apiKey, { action: "PROCESS_DATA" });
    await p4("delegate-task", () => invokeDelegateTask(t3n, tenantDid, {
      to_agent_id: workerDid,
      action: "PROCESS_DATA",
      __delegation_envelope: p4DelegEnv,
    }));

    await p4("submit-bid", () => invokeSubmitBid(t3n, tenantDid, { bidder_did: workerDid, item_id: "item-001", amount: 210.50, nonce: "nonce-abc" }));
    await p4("resolve-auction", () => invokeResolveAuction(t3n, tenantDid, {
      item_id: "item-001",
      bids: [{ bidder_did: workerDid, amount: 210.50 }, { bidder_did: worker2Did, amount: 185.00 }],
    }));

    await p4("record-completion", () => invokeRecordCompletion(t3n, tenantDid, { agent_did: workerDid, task_id: "task-001", quality_score: 0.92, on_time: true }));
    await p4("get-reputation", () => invokeGetReputation(t3n, tenantDid, {
      agent_did: workerDid,
      history: [{ quality_score: 0.92, on_time: true }, { quality_score: 0.85, on_time: false }, { quality_score: 0.97, on_time: true }],
    }));

    await p4("send-personalized-outreach", () => invokeSendPersonalizedOutreach(t3n, tenantDid, { customer_id: "cust-001", segment: "enterprise", template_id: "tmpl-premium", data_hash: "deadbeef" }));

    await p4("issue-time-grant", () => invokeIssueTimeGrant(t3n, tenantDid, { grantee_did: workerDid, action: "VALIDATE_DATA", valid_until_epoch: now + 3600, issuer_nonce: "nonce-xyz" }));
    await p4("check-grant", () => invokeCheckGrant(t3n, tenantDid, { grant_token: "token-demo", grantee_did: workerDid, action: "VALIDATE_DATA", valid_until_epoch: now + 3600, current_epoch: now }));

    await p4("kyc-submit-step", () => invokeKycSubmitStep(t3n, tenantDid, { agent_did: agentDid, applicant_id: "applicant-001", step: "identity_check", data_hash: "cafebabe" }));
    await p4("kyc-get-status", () => invokeKycGetStatus(t3n, tenantDid, { applicant_id: "applicant-001", steps_completed: ["identity_check"] }));

    await p4("store-secret", () => invokeStoreSecret(t3n, tenantDid, { owner_did: agentDid, secret_hash: "sha256-secret-hash", permission_hash: "perm-hash-001", label: "api-key" }));
    await p4("invoke-with-secret", () => invokeInvokeWithSecret(t3n, tenantDid, { vault_id: "vault-demo", requester_did: workerDid, action: "decrypt", permission_proof: "proof-001" }));

    await p4("cast-vote", () => invokeCastVote(t3n, tenantDid, { voter_did: workerDid, proposal_id: "prop-001", vote: "FOR", rationale_hash: "rationale-hash" }));
    await p4("tally-votes", () => invokeTallyVotes(t3n, tenantDid, {
      proposal_id: "prop-001",
      votes: [{ voter_did: workerDid, vote: "FOR" }, { voter_did: worker2Did, vote: "AGAINST" }, { voter_did: agentDid, vote: "FOR" }],
      quorum_threshold: 2,
    }));

    await p4("log-decision", () => invokeLogDecision(t3n, tenantDid, { agent_did: agentDid, decision_id: "dec-001", action: "approve-loan", rationale_hash: "rat-hash", confidence: 0.87 }));
    await p4("audit-decisions", () => invokeAuditDecisions(t3n, tenantDid, {
      auditor_did: agentDid,
      entries: [{ agent_did: workerDid, action: "approve-loan", confidence: 0.87 }, { agent_did: worker2Did, action: "flag-fraud", confidence: 0.42 }],
    }));

    await p4("lock-bond", () => invokeLockBond(t3n, tenantDid, { agent_did: workerDid, task_id: "task-001", bond_amount: 500.00, deadline_epoch: now + 86400 }));
    await p4("verify-and-settle", () => invokeVerifyAndSettle(t3n, tenantDid, { bond_id: "bond-demo", agent_did: workerDid, task_id: "task-001", bond_amount: 500.00, deadline_epoch: now + 86400, current_epoch: now, completed: true, quality_score: 0.92 }));

    console.log(`  [+] Phase 4: ${p4Passed}/18 passed | ${p4Failed} failed`);
    allWitSucceeded = p4Passed === 18 && teeInvoked;
    if (allWitSucceeded) {
      console.log("  [+] All 20 WIT exports invoked via live T3N TEE bridge.");
    } else if (p4Passed === 18 && !teeInvoked) {
      console.log("  [!] Phase 4: 18/18 passed but Phase 3 core calls failed — cannot claim 20/20");
      process.exitCode = 1;
    } else {
      console.log(`  [!] Phase 4 incomplete: ${p4Failed} call(s) failed — review [-] lines above`);
      process.exitCode = 1;
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  console.log("\n" + "=".repeat(55));
  console.log("DEMO SUMMARY");
  console.log("=".repeat(55));
  console.log(`Real T3N auth:             YES`);
  console.log(`DID from session:          ${tenantDid}`);
  console.log(`Agent Auth credential:     ${agentAuthSucceeded ? "BUILT + SIGNED + ENFORCED (EIP-191, SDK-native, C-01 live)" : "FAILED — see [-] lines above"}`);
  console.log(`Distinct agent identities: ${adnResult.uniqueIdentities}/4`);
  console.log(`Multi-agent delegation:    ${adnResult.success ? "PASSED" : "FAILED"}`);
  console.log(`Tamper detection:          ACTIVE (data_hash in signed payload)`);
  console.log(`WASM contract:             ${!existsSync(WASM_PATH) ? "NOT YET COMPILED" : allWitSucceeded ? "REGISTERED + INVOKED (20/20 WIT functions)" : teeInvoked ? "REGISTERED + INVOKED (Phase 3 OK; Phase 4 partial)" : "REGISTERED (Phase 3 invocation failed)"}`);
  console.log("=".repeat(55));
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
