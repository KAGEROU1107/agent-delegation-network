/**
 * TEE contract management: registration and invocation via Terminal 3 ADK.
 *
 * Invocation uses T3nClient.executeAndDecode() with the explicit
 * script_name / script_version / function_name / input payload.
 * script_name format: z:<40-hex-tid>:<tail>  (strip "did:t3n:" prefix)
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
} from "crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import type { TenantClient, T3nClient } from "@terminal3/t3n-sdk";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, "../../contract/target/wasm32-wasip2/release/adn_processor.wasm");
const PROOF_DIR = join(__dirname, "../../proof");
const RELEASE_PROOF_DIR = join(PROOF_DIR, "release");
const DEPLOYMENT_MANIFEST_PATH = join(RELEASE_PROOF_DIR, "deployment_manifest.json");
const DEPLOYMENT_MANIFEST_SIGNATURE_PATH = join(RELEASE_PROOF_DIR, "deployment_manifest.sig");
const REGISTRATION_RESPONSE_PATH = join(RELEASE_PROOF_DIR, "registration_response.json");
const INVOCATION_RECEIPT_PATH = join(RELEASE_PROOF_DIR, "invocation_receipt.json");
const T3N_EVIDENCE_PATH = join(RELEASE_PROOF_DIR, "t3n_evidence.json");
const LEGACY_DEPLOYMENT_MANIFEST_PATH = join(PROOF_DIR, "deployment_manifest_v3.9.2.local.json");
const CONTRACT_TAIL = "adn-processor";
const CONTRACT_VERSION = "3.9.2"; // mandatory-envelope enforcement (C-01 fix, rebuilt 2026-06-20)
const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface DeploymentManifest {
  schema_version: "adn-release-proof-v1";
  contract_tail: string;
  contract_version: string;
  build_commit: string;
  rustc_version: string;
  trusted_issuer: string;
  tenant_did: string;
  build_config_id: string;
  local_wasm_sha256: string;
  registration_status: "pending" | "registered";
  registered_at?: string;
  remote_contract_id?: number;
  raw_registration_response_digest?: string;
  raw_registration_response_path?: string;
  first_invocation_digest?: string;
  first_invocation_path?: string;
  t3n_evidence_digest?: string;
  t3n_evidence_path?: string;
  operator_public_key?: string;
  manifest_digest: string;
}

export interface ContractInfo {
  tail: string;
  version: string;
  tenantDid: string;
  /** Numeric contract ID if the SDK returns it; undefined if BUG-001 still present. */
  contractId?: number;
  /** SHA-256 of the local WASM artifact sent to register(). */
  localWasmSha256: string;
  /** External manifest binding build config to the actual post-build artifact hash. */
  deploymentManifest: DeploymentManifest;
}

/**
 * Attempt to extract a numeric contract ID from the raw SDK register() response.
 * SDK types register() as Promise<unknown> — BUG-001 — so we probe the actual
 * runtime value for any numeric `id` or `contractId` field.
 */
function extractContractId(raw: unknown): number | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  for (const key of ["id", "contractId", "contract_id"]) {
    const v = obj[key];
    if (typeof v === "number" && Number.isInteger(v) && v > 0) return v;
    if (typeof v === "string" && /^\d+$/.test(v)) return parseInt(v, 10);
  }
  return undefined;
}

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function normalizeHex(value: string | undefined): string | undefined {
  const normalized = value?.trim().replace(/^0x/i, "").toLowerCase();
  return normalized || undefined;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(",")}}`;
}

function buildConfigId(buildCommit: string, rustcVersion: string, trustedIssuer: string, tenantDid: string): string {
  const material = `adn-processor:v${CONTRACT_VERSION}:${buildCommit}:${rustcVersion}:${trustedIssuer}:${tenantDid}`;
  return `adn-build-${sha256Hex(material).slice(0, 32)}`;
}

function requireManifestEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required to write a deployment manifest for ${CONTRACT_TAIL} v${CONTRACT_VERSION}`);
  }
  return value;
}

function privateKeyFromSeedHex(seedHex: string) {
  if (!/^[0-9a-f]{64}$/.test(seedHex)) {
    throw new Error("ADN_RELEASE_OPERATOR_PRIVATE_KEY_HEX must be a 32-byte Ed25519 seed hex string");
  }
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, Buffer.from(seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
}

function derivePublicKeyHexFromSeed(seedHex: string): string {
  const privateKey = privateKeyFromSeedHex(seedHex);
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32).toString("hex");
}

function releaseOperatorPublicKeyHex(): string | undefined {
  const configuredPublicKey = normalizeHex(process.env.ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX);
  if (configuredPublicKey) {
    if (!/^[0-9a-f]{64}$/.test(configuredPublicKey)) {
      throw new Error("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX must be a 32-byte Ed25519 public key hex string");
    }
    return configuredPublicKey;
  }
  const seedHex = normalizeHex(process.env.ADN_RELEASE_OPERATOR_PRIVATE_KEY_HEX);
  return seedHex ? derivePublicKeyHexFromSeed(seedHex) : undefined;
}

function digestManifest(manifest: Omit<DeploymentManifest, "manifest_digest">): DeploymentManifest {
  return { ...manifest, manifest_digest: sha256Hex(canonicalJson(manifest)) };
}

function manifestWithoutDigest(manifest: DeploymentManifest): Omit<DeploymentManifest, "manifest_digest"> {
  const { manifest_digest: _manifestDigest, ...body } = manifest;
  return body;
}

function writeJsonArtifact(path: string, payload: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${canonicalJson(payload)}\n`, "utf-8");
}

function writeManifestSignatureIfConfigured(deploymentManifest: DeploymentManifest): void {
  const seedHex = normalizeHex(process.env.ADN_RELEASE_OPERATOR_PRIVATE_KEY_HEX);
  if (!seedHex) {
    rmSync(DEPLOYMENT_MANIFEST_SIGNATURE_PATH, { force: true });
    return;
  }

  const privateKey = privateKeyFromSeedHex(seedHex);
  const derivedPublicKeyHex = derivePublicKeyHexFromSeed(seedHex);
  const configuredPublicKeyHex = normalizeHex(process.env.ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX);
  const manifestPublicKeyHex = normalizeHex(deploymentManifest.operator_public_key);

  if (configuredPublicKeyHex && configuredPublicKeyHex !== derivedPublicKeyHex) {
    throw new Error("ADN_RELEASE_OPERATOR_PUBLIC_KEY_HEX does not match ADN_RELEASE_OPERATOR_PRIVATE_KEY_HEX");
  }
  if (manifestPublicKeyHex && manifestPublicKeyHex !== derivedPublicKeyHex) {
    throw new Error("deployment manifest operator_public_key does not match ADN_RELEASE_OPERATOR_PRIVATE_KEY_HEX");
  }

  const signedBody = Buffer.from(canonicalJson(manifestWithoutDigest(deploymentManifest)), "utf-8");
  const signatureDoc = {
    algorithm: "ed25519",
    public_key_hex: derivedPublicKeyHex,
    signature_hex: signBytes(null, signedBody, privateKey).toString("hex"),
  };
  writeJsonArtifact(DEPLOYMENT_MANIFEST_SIGNATURE_PATH, signatureDoc);
}

function writeDeploymentManifest(deploymentManifest: DeploymentManifest): DeploymentManifest {
  mkdirSync(RELEASE_PROOF_DIR, { recursive: true });
  writeJsonArtifact(DEPLOYMENT_MANIFEST_PATH, deploymentManifest);
  writeJsonArtifact(LEGACY_DEPLOYMENT_MANIFEST_PATH, deploymentManifest);
  writeManifestSignatureIfConfigured(deploymentManifest);
  return deploymentManifest;
}

function writePendingDeploymentManifest(localWasmSha256: string): DeploymentManifest {
  const buildCommit = requireManifestEnv("ADN_BUILD_COMMIT");
  const rustcVersion = requireManifestEnv("ADN_RUSTC_VERSION");
  const trustedIssuer = requireManifestEnv("ADN_TRUSTED_ISSUER").replace(/^0x/i, "").toLowerCase();
  const tenantDid = requireManifestEnv("ADN_TENANT_DID");
  const buildConfig = buildConfigId(buildCommit, rustcVersion, trustedIssuer, tenantDid);

  const unsignedManifest = {
    schema_version: "adn-release-proof-v1" as const,
    contract_tail: CONTRACT_TAIL,
    contract_version: CONTRACT_VERSION,
    build_commit: buildCommit,
    rustc_version: rustcVersion,
    trusted_issuer: trustedIssuer,
    tenant_did: tenantDid,
    build_config_id: buildConfig,
    local_wasm_sha256: localWasmSha256,
    registration_status: "pending" as const,
    operator_public_key: releaseOperatorPublicKeyHex(),
  };
  return writeDeploymentManifest(digestManifest(unsignedManifest));
}

export function finalizeDeploymentManifest(
  pendingManifest: DeploymentManifest,
  rawRegistrationResponse: unknown,
  contractId?: number,
): DeploymentManifest {
  writeJsonArtifact(REGISTRATION_RESPONSE_PATH, rawRegistrationResponse);
  const finalized = digestManifest({
    ...manifestWithoutDigest(pendingManifest),
    registration_status: "registered",
    registered_at: new Date().toISOString(),
    remote_contract_id: contractId,
    raw_registration_response_digest: sha256Hex(canonicalJson(rawRegistrationResponse)),
    raw_registration_response_path: "registration_response.json",
  });
  return writeDeploymentManifest(finalized);
}

export function recordFirstInvocationDigest(
  contractInfo: ContractInfo,
  invocationResult: unknown,
): ContractInfo {
  if (contractInfo.deploymentManifest.first_invocation_digest) {
    return contractInfo;
  }
  writeJsonArtifact(INVOCATION_RECEIPT_PATH, invocationResult);
  writeJsonArtifact(T3N_EVIDENCE_PATH, invocationResult);
  const deploymentManifest = writeDeploymentManifest(digestManifest({
    ...manifestWithoutDigest(contractInfo.deploymentManifest),
    first_invocation_digest: sha256Hex(canonicalJson(invocationResult)),
    first_invocation_path: "invocation_receipt.json",
    t3n_evidence_digest: sha256Hex(canonicalJson(invocationResult)),
    t3n_evidence_path: "t3n_evidence.json",
  }));
  return { ...contractInfo, deploymentManifest };
}

export async function registerAdnContract(
  tenant: TenantClient,
  tenantDid: string
): Promise<ContractInfo> {
  if (!existsSync(WASM_PATH)) {
    throw new Error(`WASM not found at ${WASM_PATH}. Run: cd contract && cargo build --target wasm32-wasip2 --release`);
  }

  const wasm = readFileSync(WASM_PATH);
  const localWasmSha256 = sha256Hex(wasm);
  let deploymentManifest = writePendingDeploymentManifest(localWasmSha256);
  console.log(`  [+] Local WASM SHA-256: ${localWasmSha256}`);
  console.log(`  [+] Deployment manifest digest: ${deploymentManifest.manifest_digest}`);
  console.log(`  [+] Deployment manifest: ${DEPLOYMENT_MANIFEST_PATH}`);
  let contractId: number | undefined;
  try {
    const raw = await tenant.contracts.register({ tail: CONTRACT_TAIL, version: CONTRACT_VERSION, wasm });
    contractId = extractContractId(raw);
    deploymentManifest = finalizeDeploymentManifest(deploymentManifest, raw, contractId);
    if (contractId !== undefined) {
      console.log(`  [+] register() returned contractId: ${contractId} (BUG-001 resolved by SDK)`);
    } else {
      console.log(`  [!] register() returned no contractId (BUG-001 active) — setupAdnMaps() will throw`);
    }
  } catch (err) {
    const msg = (err as Error).message ?? "";
    if (msg.includes("not higher") || msg.includes("already enabled")) {
      throw new Error(
        `Contract ${CONTRACT_TAIL}@${CONTRACT_VERSION} already exists remotely; ` +
        `refusing to continue without remote artifact identity verification. ` +
        `Local WASM SHA-256: ${localWasmSha256}. Bump CONTRACT_VERSION for a fresh immutable deployment.`
      );
    }
    throw err;
  }

  return { tail: CONTRACT_TAIL, version: CONTRACT_VERSION, tenantDid, contractId, localWasmSha256, deploymentManifest };
}

export function invokeProcessData(
  t3n: T3nClient,
  tenantDid: string,
  params: { data_source: string; time_period: string; filters: string[]; records: number[] }
): Promise<ProcessDataResult> {
  return invoke(t3n, tenantDid, "process-data", params);
}

export function invokeValidateQuality(
  t3n: T3nClient,
  tenantDid: string,
  params: { records_processed?: number; total_revenue?: number; [key: string]: unknown }
): Promise<QualityResult> {
  return invoke(t3n, tenantDid, "validate-quality", params);
}

export async function fetchContractLogs(tenant: TenantClient): Promise<string[]> {
  try {
    const result = await tenant.contracts.logs(CONTRACT_TAIL, { limit: 20 });
    return result.entries.map((e) => `[${e.level}] ${e.message}`);
  } catch {
    return [];
  }
}

// ── Shared invocation helper ───────────────────────────────────────────────────

function invoke<T>(t3n: T3nClient, tenantDid: string, functionName: string, input: unknown): Promise<T> {
  const tid = tenantDid.slice("did:t3n:".length);
  return t3n.executeAndDecode<T>({
    script_name: `z:${tid}:${CONTRACT_TAIL}`,
    script_version: CONTRACT_VERSION,
    function_name: functionName,
    input,
  });
}

// ── Phase 1 types & invoke ────────────────────────────────────────────────────

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

export interface DelegateTaskResult {
  delegation_id: string;
  status: string;
  routed_to: string;
  credential_enforced?: boolean;
  credential_fingerprint?: string;
  build_config_id?: string;
  authorization_expires_at?: string;
}

export interface DelegateTaskEnvelope {
  credential_jcs: string;
  user_sig?: string;
  agent_sig: string;
  nonce: string;
  request_hash?: string;
}

export function invokeDelegateTask(
  t3n: T3nClient, tenantDid: string,
  params: { to_agent_id: string; action?: string; __delegation_envelope?: DelegateTaskEnvelope }
): Promise<DelegateTaskResult> {
  return invoke(t3n, tenantDid, "delegate-task", params);
}

// ── Phase 2 — Blind Auction ───────────────────────────────────────────────────

export interface SubmitBidResult {
  bid_hash: string;
  item_id: string;
  sealed_in_tee: boolean;
  receipt: string;
}

export interface ResolveAuctionResult {
  winner_did: string;
  winning_amount: number;
  item_id: string;
  total_bids: number;
  resolved_in_tee: boolean;
}

export function invokeSubmitBid(
  t3n: T3nClient, tenantDid: string,
  params: { bidder_did: string; item_id: string; amount: number; nonce: string }
): Promise<SubmitBidResult> {
  return invoke(t3n, tenantDid, "submit-bid", params);
}

export function invokeResolveAuction(
  t3n: T3nClient, tenantDid: string,
  params: { item_id: string; bids: Array<{ bidder_did: string; amount: number }> }
): Promise<ResolveAuctionResult> {
  return invoke(t3n, tenantDid, "resolve-auction", params);
}

// ── Phase 3 — Agent Reputation Ledger ────────────────────────────────────────

export interface RecordCompletionResult {
  agent_did: string;
  task_id: string;
  reputation_delta: number;
  recorded_in_tee: boolean;
}

export interface GetReputationResult {
  agent_did: string;
  reputation_score: number;
  tier: string;
  tasks_evaluated: number;
  computed_in_tee: boolean;
}

export function invokeRecordCompletion(
  t3n: T3nClient, tenantDid: string,
  params: { agent_did: string; task_id: string; quality_score: number; on_time: boolean }
): Promise<RecordCompletionResult> {
  return invoke(t3n, tenantDid, "record-completion", params);
}

export function invokeGetReputation(
  t3n: T3nClient, tenantDid: string,
  params: { agent_did: string; history: Array<{ quality_score: number; on_time: boolean }> }
): Promise<GetReputationResult> {
  return invoke(t3n, tenantDid, "get-reputation", params);
}

// ── Phase 4 — Privacy-Preserving Personalization ──────────────────────────────

export interface PersonalizedOutreachResult {
  customer_id: string;
  message_variant: string;
  personalization_score: number;
  raw_data_exposed: boolean;
  processed_in_tee: boolean;
}

export function invokeSendPersonalizedOutreach(
  t3n: T3nClient, tenantDid: string,
  params: { customer_id: string; segment: string; template_id: string; data_hash: string }
): Promise<PersonalizedOutreachResult> {
  return invoke(t3n, tenantDid, "send-personalized-outreach", params);
}

// ── Phase 5 — Temporal Agent Delegation ──────────────────────────────────────

export interface IssueTimeGrantResult {
  grant_token: string;
  grantee_did: string;
  action: string;
  valid_until_epoch: number;
  issued_in_tee: boolean;
}

export interface CheckGrantResult {
  valid: boolean;
  reason: string;
  checked_in_tee: boolean;
}

export function invokeIssueTimeGrant(
  t3n: T3nClient, tenantDid: string,
  params: { grantee_did: string; action: string; valid_until_epoch: number; issuer_nonce: string }
): Promise<IssueTimeGrantResult> {
  return invoke(t3n, tenantDid, "issue-time-grant", params);
}

export function invokeCheckGrant(
  t3n: T3nClient, tenantDid: string,
  params: { grant_token: string; grantee_did: string; action: string; valid_until_epoch: number; current_epoch: number }
): Promise<CheckGrantResult> {
  return invoke(t3n, tenantDid, "check-grant", params);
}

// ── Phase 7 — Agentic KYC Pipeline ───────────────────────────────────────────

export interface KycSubmitStepResult {
  applicant_id: string;
  step: string;
  step_receipt: string;
  progress_pct: number;
  recorded_in_tee: boolean;
}

export interface KycGetStatusResult {
  applicant_id: string;
  status: string;
  steps_completed: number;
  steps_required: number;
  missing_steps: string[];
  verified_in_tee: boolean;
}

export function invokeKycSubmitStep(
  t3n: T3nClient, tenantDid: string,
  params: { agent_did: string; applicant_id: string; step: string; data_hash: string }
): Promise<KycSubmitStepResult> {
  return invoke(t3n, tenantDid, "kyc-submit-step", params);
}

export function invokeKycGetStatus(
  t3n: T3nClient, tenantDid: string,
  params: { applicant_id: string; steps_completed: string[] }
): Promise<KycGetStatusResult> {
  return invoke(t3n, tenantDid, "kyc-get-status", params);
}

// ── Phase 8 — TEE Secret Vault ────────────────────────────────────────────────

export interface StoreSecretResult {
  vault_id: string;
  owner_did: string;
  label: string;
  stored_in_tee: boolean;
}

export interface InvokeWithSecretResult {
  vault_id: string;
  action_executed: string;
  tee_attested: boolean;
  raw_secret_exposed: boolean;
}

export function invokeStoreSecret(
  t3n: T3nClient, tenantDid: string,
  params: { owner_did: string; secret_hash: string; permission_hash: string; label: string }
): Promise<StoreSecretResult> {
  return invoke(t3n, tenantDid, "store-secret", params);
}

export function invokeInvokeWithSecret(
  t3n: T3nClient, tenantDid: string,
  params: { vault_id: string; requester_did: string; action: string; permission_proof: string }
): Promise<InvokeWithSecretResult> {
  return invoke(t3n, tenantDid, "invoke-with-secret", params);
}

// ── Phase 9 — Autonomous Agent DAO ────────────────────────────────────────────

export interface CastVoteResult {
  voter_did: string;
  proposal_id: string;
  vote_receipt: string;
  recorded_in_tee: boolean;
}

export interface TallyVotesResult {
  proposal_id: string;
  result: string;
  votes_for: number;
  votes_against: number;
  quorum_met: boolean;
  tallied_in_tee: boolean;
}

export function invokeCastVote(
  t3n: T3nClient, tenantDid: string,
  params: { voter_did: string; proposal_id: string; vote: string; rationale_hash: string }
): Promise<CastVoteResult> {
  return invoke(t3n, tenantDid, "cast-vote", params);
}

export function invokeTallyVotes(
  t3n: T3nClient, tenantDid: string,
  params: { proposal_id: string; votes: Array<{ voter_did: string; vote: string }>; quorum_threshold: number }
): Promise<TallyVotesResult> {
  return invoke(t3n, tenantDid, "tally-votes", params);
}

// ── Phase 10 — Verifiable AI Decision Audit ───────────────────────────────────

export interface LogDecisionResult {
  decision_id: string;
  agent_did: string;
  entry_hash: string;
  logged_in_tee: boolean;
}

export interface AuditDecisionsResult {
  total_decisions: number;
  anomalies_detected: number;
  risk_score: number;
  attestation: string;
  audited_in_tee: boolean;
}

export function invokeLogDecision(
  t3n: T3nClient, tenantDid: string,
  params: { agent_did: string; decision_id: string; action: string; rationale_hash: string; confidence: number }
): Promise<LogDecisionResult> {
  return invoke(t3n, tenantDid, "log-decision", params);
}

export function invokeAuditDecisions(
  t3n: T3nClient, tenantDid: string,
  params: { auditor_did: string; entries: Array<{ agent_did: string; action: string; confidence: number }> }
): Promise<AuditDecisionsResult> {
  return invoke(t3n, tenantDid, "audit-decisions", params);
}

// ── Phase 11 — Agent Performance Bond ────────────────────────────────────────

export interface LockBondResult {
  bond_id: string;
  agent_did: string;
  task_id: string;
  bond_amount: number;
  locked_in_tee: boolean;
}

export interface VerifyAndSettleResult {
  bond_id: string;
  settlement: string;
  payout_pct: number;
  payout_amount: number;
  reason: string;
  settled_in_tee: boolean;
}

export function invokeLockBond(
  t3n: T3nClient, tenantDid: string,
  params: { agent_did: string; task_id: string; bond_amount: number; deadline_epoch: number }
): Promise<LockBondResult> {
  return invoke(t3n, tenantDid, "lock-bond", params);
}

export function invokeVerifyAndSettle(
  t3n: T3nClient, tenantDid: string,
  params: { bond_id: string; agent_did: string; task_id: string; bond_amount: number; deadline_epoch: number; current_epoch: number; completed: boolean; quality_score: number }
): Promise<VerifyAndSettleResult> {
  return invoke(t3n, tenantDid, "verify-and-settle", params);
}
