use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

wit_bindgen::generate!({
    world: "adn-processor",
    path: "wit",
});

mod crypto;

struct Component;

// Only emit the Wasm component-model ABI trampolines when targeting wasm32.
// On native (cargo test), the cabi_post_* symbol names contain `:` which is
// invalid in GNU-ld version-script syntax and causes rust-lld to fail.
#[cfg(target_arch = "wasm32")]
export!(Component);

// ── Shared helper ─────────────────────────────────────────────────────────────

fn parse_input<'a, T: Deserialize<'a>>(bytes: &'a [u8], ctx: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("{ctx}: bad input: {e}"))
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}

fn contract_build_config_id() -> String {
    let commit = option_env!("ADN_BUILD_COMMIT").unwrap_or("unknown-commit");
    let rustc = option_env!("ADN_RUSTC_VERSION").unwrap_or("unknown-rustc");
    let issuer = option_env!("ADN_TRUSTED_ISSUER")
        .map(|s| s.strip_prefix("0x").unwrap_or(s).to_ascii_lowercase())
        .unwrap_or_else(|| "unpinned-issuer".to_string());
    let tenant = option_env!("ADN_TENANT_DID").unwrap_or("unbound-tenant");
    let material = format!(
        "adn-processor:v{}:{commit}:{rustc}:{issuer}:{tenant}",
        env!("CARGO_PKG_VERSION")
    );
    let digest = Sha256::digest(material.as_bytes());
    format!("adn-build-{}", crypto::hex_lower(&digest[..16]))
}

fn epoch_to_rfc3339(epoch_secs: u64) -> Result<String, String> {
    let dt = OffsetDateTime::from_unix_timestamp(epoch_secs as i64)
        .map_err(|_| "delegate-task: invalid authorization expiry epoch".to_string())?;
    dt.format(&Rfc3339)
        .map_err(|_| "delegate-task: failed to format authorization expiry".to_string())
}

// ── Phase 1 types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProcessDataInput {
    data_source: String,
    time_period: String,
    #[serde(default)]
    filters: Vec<String>,
    // Actual sale amounts — the TEE computes stats from these inside the enclave.
    #[serde(default)]
    records: Vec<f64>,
}

#[derive(Serialize)]
struct ProcessDataOutput {
    records_processed: u32,
    total_revenue: f64,
    avg_value: f64,
    min_value: f64,
    max_value: f64,
    trend: String,
    processed_in_tee: bool,
    data_source: String,
    time_period: String,
}

#[derive(Deserialize)]
struct ValidateQualityInput {
    #[serde(default)]
    records_processed: u32,
    #[serde(default)]
    avg_value: f64,
    #[serde(default)]
    total_revenue: f64,
    #[serde(default)]
    trend: String,
}

#[derive(Serialize)]
struct ValidateQualityOutput {
    quality_score: f64,
    passed: bool,
    issues: Vec<String>,
    validated_in_tee: bool,
}

// ── Delegation credential envelope ───────────────────────────────────────────
// The TypeScript bridge embeds __delegation_envelope alongside normal call params.
// The contract extracts, decodes, and validates it before executing the function.

#[derive(Deserialize)]
struct DelegationEnvelopeFields {
    credential_jcs: String,     // base64url JCS bytes of the DelegationCredential
    #[serde(default)]
    user_sig: String,           // base64url 65-byte EIP-191 sig over credential JCS
    #[serde(default)]
    nonce: String,              // base64url 16-byte invocation nonce
    #[serde(default)]
    agent_sig: String,          // base64url 64-byte secp256k1 sig over invocation preimage
    #[serde(default)]
    request_hash: String,       // base64url 32-byte sha256 of canonical request
}

// Subset of DelegationCredential fields validated at contract-layer.
// Time fields are JSON strings (decimal) to preserve u64 precision past JS Number.
// vc_id: base64url of 16 bytes. agent_pubkey: base64url of 33-byte compressed secp256k1.
#[derive(Deserialize)]
struct CredentialBody {
    v: String,
    functions: Vec<String>,
    not_before_secs: String,
    not_after_secs: String,
    #[serde(default)]
    vc_id: String,          // base64url, decodes to 16 bytes
    #[serde(default)]
    agent_pubkey: String,   // base64url, decodes to 33-byte compressed secp256k1
    #[serde(default)]
    user_did: String,
    #[serde(default)]
    org_did: String,
    #[serde(default)]
    contract: String,
    #[serde(default)]
    metadata: BTreeMap<String, String>, // adn_authorization_v1 holds the signed policy (JSON string)
}

// Issuer-signed authorization policy embedded in credential metadata (and thus
// covered by user_sig). Binds the delegated target, allowed actions, and max TTL.
#[derive(Deserialize)]
struct AuthzPolicy {
    #[serde(default)]
    to_agent_id: String,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    max_ttl_secs: u64,
}

// Verification configuration. trusted_issuer/tenant_did are pinned at build time;
// when trusted_issuer is None the contract fails closed (refuses to authorize).
struct DelegationConfig {
    trusted_issuer: Option<[u8; 20]>,
    tenant_did: Option<String>,
    now_secs: u64,
    max_ttl_secs: u64,
    clock_skew_secs: u64,
}

fn parse_addr_hex(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 { return None; }
    let mut a = [0u8; 20];
    for i in 0..20 {
        a[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(a)
}

/// Tenant issuer address pinned at build time via ADN_TRUSTED_ISSUER (20-byte hex).
/// Unset => None => issuer authorization fails closed (every delegate-task rejected).
fn trusted_issuer() -> Option<[u8; 20]> {
    option_env!("ADN_TRUSTED_ISSUER").and_then(parse_addr_hex)
}

/// Optional tenant DID pin via ADN_TENANT_DID; when set, org_did/user_did must match.
fn configured_tenant_did() -> Option<String> {
    option_env!("ADN_TENANT_DID").map(|s| s.to_string())
}

/// Pure, host-testable delegated-authority verification (v3.9.1).
fn verify_delegate_task(bytes: &[u8], cfg: &DelegationConfig) -> Result<DelegateTaskOutput, String> {
    let r: DelegateTaskInput = parse_input(bytes, "delegate-task")?;

    let env = r.delegation_envelope.as_ref().ok_or(
        "delegate-task: __delegation_envelope required — unauthenticated delegation is not permitted",
    )?;

    let cred_bytes = URL_SAFE_NO_PAD
        .decode(&env.credential_jcs)
        .map_err(|_| "delegate-task: invalid credential_jcs encoding".to_string())?;
    let cred: CredentialBody = serde_json::from_slice(&cred_bytes)
        .map_err(|e| format!("delegate-task: invalid credential body: {e}"))?;

    if cred.v != "ot3.delegation/1" {
        return Err("delegate-task: invalid credential domain".to_string());
    }
    if cred.contract != "adn-processor" {
        return Err("delegate-task: credential contract mismatch".to_string());
    }
    if let Some(td) = &cfg.tenant_did {
        if &cred.org_did != td {
            return Err("delegate-task: credential org_did is not the configured tenant".to_string());
        }
        if &cred.user_did != td {
            return Err("delegate-task: credential user_did is not the configured tenant".to_string());
        }
    }
    if cred.vc_id.is_empty() {
        return Err("delegate-task: vc_id missing from credential".to_string());
    }
    if cred.agent_pubkey.is_empty() {
        return Err("delegate-task: agent_pubkey missing from credential".to_string());
    }

    let not_before: u64 = cred.not_before_secs.parse().map_err(|_| "delegate-task: invalid not_before_secs".to_string())?;
    let not_after: u64 = cred.not_after_secs.parse().map_err(|_| "delegate-task: invalid not_after_secs".to_string())?;
    if not_before >= not_after {
        return Err("delegate-task: credential window invalid (not_before >= not_after)".to_string());
    }
    if not_after - not_before > cfg.max_ttl_secs {
        return Err(format!("delegate-task: credential TTL exceeds maximum {}s", cfg.max_ttl_secs));
    }
    if not_before > cfg.now_secs + cfg.clock_skew_secs {
        return Err("delegate-task: credential not_before is too far in the future".to_string());
    }
    if cfg.now_secs < not_before {
        return Err("delegate-task: credential not yet valid".to_string());
    }
    if cfg.now_secs > not_after {
        return Err(format!("delegate-task: credential expired (expired epoch {not_after}, now {})", cfg.now_secs));
    }

    if !cred.functions.iter().any(|f| f == "delegate-task") {
        return Err("delegate-task: function not in delegated scope".to_string());
    }

    if env.nonce.is_empty() { return Err("delegate-task: nonce required".to_string()); }
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&env.nonce).map_err(|_| "delegate-task: invalid nonce encoding".to_string())?;
    if nonce_bytes.len() != 16 { return Err("delegate-task: nonce must be exactly 16 bytes".to_string()); }

    if env.agent_sig.is_empty() { return Err("delegate-task: agent_sig missing from envelope".to_string()); }
    let agent_sig = URL_SAFE_NO_PAD.decode(&env.agent_sig).map_err(|_| "delegate-task: invalid agent_sig encoding".to_string())?;

    if env.request_hash.is_empty() { return Err("delegate-task: request_hash required".to_string()); }
    let request_hash = URL_SAFE_NO_PAD.decode(&env.request_hash).map_err(|_| "delegate-task: invalid request_hash encoding".to_string())?;
    if request_hash.len() != 32 { return Err("delegate-task: request_hash must be 32 bytes".to_string()); }

    #[derive(Serialize)]
    struct CanonReq<'a> { to_agent_id: &'a str, action: &'a str }
    let canon = serde_json::to_vec(&CanonReq { to_agent_id: &r.to_agent_id, action: &r.action })
        .map_err(|e| format!("delegate-task: canonicalisation error: {e}"))?;
    if Sha256::digest(&canon).as_slice() != request_hash.as_slice() {
        return Err("delegate-task: request_hash does not bind this call (to_agent_id/action mismatch)".to_string());
    }

    let vc_id_bytes = URL_SAFE_NO_PAD.decode(&cred.vc_id).map_err(|_| "delegate-task: invalid vc_id encoding".to_string())?;
    if vc_id_bytes.len() != 16 { return Err("delegate-task: vc_id must be 16 bytes".to_string()); }
    let agent_pubkey = URL_SAFE_NO_PAD.decode(&cred.agent_pubkey).map_err(|_| "delegate-task: invalid agent_pubkey encoding".to_string())?;

    // Agent possession proof.
    let preimage = crypto::build_preimage(&vc_id_bytes, &nonce_bytes, &request_hash);
    crypto::verify_agent_sig(&agent_pubkey, &preimage, &agent_sig).map_err(|e| format!("delegate-task: {e}"))?;

    // Issuer authorization (MANDATORY): user_sig must recover the pinned tenant issuer.
    if env.user_sig.is_empty() {
        return Err("delegate-task: user_sig required — credential must be issuer-signed".to_string());
    }
    let user_sig = URL_SAFE_NO_PAD.decode(&env.user_sig).map_err(|_| "delegate-task: invalid user_sig encoding".to_string())?;
    let signer = crypto::recover_eip191_address(&cred_bytes, &user_sig).map_err(|e| format!("delegate-task: {e}"))?;
    let trusted = cfg.trusted_issuer.ok_or(
        "delegate-task: trusted issuer not pinned (build with ADN_TRUSTED_ISSUER) — refusing to authorize",
    )?;
    if signer != trusted {
        return Err("delegate-task: credential issuer is not the trusted tenant".to_string());
    }

    // Issuer-signed authorization policy: binds target, action, and TTL.
    let policy_str = cred.metadata.get("adn_authorization_v1")
        .ok_or("delegate-task: missing adn_authorization_v1 policy in credential")?;
    let policy: AuthzPolicy = serde_json::from_str(policy_str)
        .map_err(|e| format!("delegate-task: invalid authorization policy: {e}"))?;
    if policy.to_agent_id != r.to_agent_id {
        return Err("delegate-task: target not authorized by credential policy".to_string());
    }
    if !policy.actions.iter().any(|a| a == &r.action) {
        return Err("delegate-task: action not authorized by credential policy".to_string());
    }
    // Policy TTL is mandatory and bounded: 1..=global max. A zero/missing or
    // over-cap policy TTL is rejected rather than silently using the global cap.
    if policy.max_ttl_secs == 0 || policy.max_ttl_secs > cfg.max_ttl_secs {
        return Err(format!("delegate-task: policy max_ttl_secs must be in 1..={}", cfg.max_ttl_secs));
    }
    if (not_after - not_before) > policy.max_ttl_secs {
        return Err("delegate-task: credential TTL exceeds policy maximum".to_string());
    }

    let credential_digest = Sha256::digest(&cred_bytes);
    let mut id_material = Vec::with_capacity(vc_id_bytes.len() + nonce_bytes.len() + request_hash.len());
    id_material.extend_from_slice(&vc_id_bytes);
    id_material.extend_from_slice(&nonce_bytes);
    id_material.extend_from_slice(&request_hash);
    let id_digest = Sha256::digest(&id_material);
    Ok(DelegateTaskOutput {
        delegation_id: format!("tee-del-{}", crypto::hex_lower(&id_digest[..16])),
        status: "ROUTED".to_string(),
        routed_to: r.to_agent_id,
        credential_enforced: Some(true),
        credential_fingerprint: Some(format!("{credential_digest:x}")),
        user_signer: Some(format!("0x{}", crypto::hex_lower(&signer))),
        build_config_id: Some(contract_build_config_id()),
        authorization_expires_at: Some(epoch_to_rfc3339(not_after)?),
    })
}

#[derive(Deserialize)]
struct DelegateTaskInput {
    to_agent_id: String,
    #[serde(default)]
    action: String,
    // Optional delegation envelope — present when caller uses Agent Auth SDK.
    #[serde(rename = "__delegation_envelope")]
    delegation_envelope: Option<DelegationEnvelopeFields>,
}

#[derive(Serialize)]
struct DelegateTaskOutput {
    delegation_id: String,
    status: String,
    routed_to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_enforced: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_fingerprint: Option<String>, // SHA-256 hex of credential_jcs bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    user_signer: Option<String>, // EIP-191 recovered signer address (0x...) when user_sig present
    #[serde(skip_serializing_if = "Option::is_none")]
    build_config_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_expires_at: Option<String>,
}

// ── Phase 2 — Blind Multi-Agent Auction ───────────────────────────────────────

#[derive(Deserialize)]
struct SubmitBidInput {
    bidder_did: String,
    item_id: String,
    amount: f64,
    nonce: String,
}

#[derive(Serialize)]
struct SubmitBidOutput {
    bid_hash: String,
    item_id: String,
    sealed_in_tee: bool,
    receipt: String,
}

#[derive(Deserialize)]
struct ResolveAuctionInput {
    item_id: String,
    bids: Vec<AuctionBid>,
}

#[derive(Deserialize)]
struct AuctionBid {
    bidder_did: String,
    amount: f64,
}

#[derive(Serialize)]
struct ResolveAuctionOutput {
    winner_did: String,
    winning_amount: f64,
    item_id: String,
    total_bids: u32,
    resolved_in_tee: bool,
}

// ── Phase 3 — Agent Reputation Ledger ────────────────────────────────────────

#[derive(Deserialize)]
struct RecordCompletionInput {
    agent_did: String,
    task_id: String,
    quality_score: f64,
    on_time: bool,
}

#[derive(Serialize)]
struct RecordCompletionOutput {
    agent_did: String,
    task_id: String,
    reputation_delta: f64,
    recorded_in_tee: bool,
}

#[derive(Deserialize)]
struct GetReputationInput {
    agent_did: String,
    history: Vec<ReputationEntry>,
}

#[derive(Deserialize)]
struct ReputationEntry {
    quality_score: f64,
    on_time: bool,
}

#[derive(Serialize)]
struct GetReputationOutput {
    agent_did: String,
    reputation_score: f64,
    tier: String,
    tasks_evaluated: u32,
    computed_in_tee: bool,
}

// ── Phase 4 — Privacy-Preserving Personalization ──────────────────────────────

#[derive(Deserialize)]
struct PersonalizedOutreachInput {
    customer_id: String,
    segment: String,
    template_id: String,
    data_hash: String,
}

#[derive(Serialize)]
struct PersonalizedOutreachOutput {
    customer_id: String,
    message_variant: String,
    personalization_score: f64,
    raw_data_exposed: bool,
    processed_in_tee: bool,
}

// ── Phase 5 — Temporal Agent Delegation ──────────────────────────────────────

#[derive(Deserialize)]
struct IssueTimeGrantInput {
    grantee_did: String,
    action: String,
    valid_until_epoch: u64,
    issuer_nonce: String,
}

#[derive(Serialize)]
struct IssueTimeGrantOutput {
    grant_token: String,
    grantee_did: String,
    action: String,
    valid_until_epoch: u64,
    issued_in_tee: bool,
}

#[derive(Deserialize)]
struct CheckGrantInput {
    grant_token: String,
    grantee_did: String,
    action: String,
    valid_until_epoch: u64,
    current_epoch: u64,
}

#[derive(Serialize)]
struct CheckGrantOutput {
    valid: bool,
    reason: String,
    checked_in_tee: bool,
}

// ── Phase 7 — Agentic KYC Pipeline ────────────────────────────────────────────

#[derive(Deserialize)]
struct KycSubmitStepInput {
    agent_did: String,
    applicant_id: String,
    step: String,
    data_hash: String,
}

#[derive(Serialize)]
struct KycSubmitStepOutput {
    applicant_id: String,
    step: String,
    step_receipt: String,
    progress_pct: f64,
    recorded_in_tee: bool,
}

#[derive(Deserialize)]
struct KycGetStatusInput {
    applicant_id: String,
    steps_completed: Vec<String>,
}

#[derive(Serialize)]
struct KycGetStatusOutput {
    applicant_id: String,
    status: String,
    steps_completed: u32,
    steps_required: u32,
    missing_steps: Vec<String>,
    verified_in_tee: bool,
}

// ── Phase 8 — TEE Secret Vault ────────────────────────────────────────────────

#[derive(Deserialize)]
struct StoreSecretInput {
    owner_did: String,
    secret_hash: String,
    permission_hash: String,
    label: String,
}

#[derive(Serialize)]
struct StoreSecretOutput {
    vault_id: String,
    owner_did: String,
    label: String,
    stored_in_tee: bool,
}

#[derive(Deserialize)]
struct InvokeWithSecretInput {
    vault_id: String,
    requester_did: String,
    action: String,
    permission_proof: String,
}

#[derive(Serialize)]
struct InvokeWithSecretOutput {
    vault_id: String,
    action_executed: String,
    tee_attested: bool,
    raw_secret_exposed: bool,
}

// ── Phase 9 — Autonomous Agent DAO ────────────────────────────────────────────

#[derive(Deserialize)]
struct CastVoteInput {
    voter_did: String,
    proposal_id: String,
    vote: String,
    rationale_hash: String,
}

#[derive(Serialize)]
struct CastVoteOutput {
    voter_did: String,
    proposal_id: String,
    vote_receipt: String,
    recorded_in_tee: bool,
}

#[derive(Deserialize)]
struct TallyVotesInput {
    proposal_id: String,
    votes: Vec<VoteEntry>,
    quorum_threshold: u32,
}

#[derive(Deserialize)]
struct VoteEntry {
    voter_did: String,
    vote: String,
}

#[derive(Serialize)]
struct TallyVotesOutput {
    proposal_id: String,
    result: String,
    votes_for: u32,
    votes_against: u32,
    quorum_met: bool,
    tallied_in_tee: bool,
}

// ── Phase 10 — Verifiable AI Decision Audit ───────────────────────────────────

#[derive(Deserialize)]
struct LogDecisionInput {
    agent_did: String,
    decision_id: String,
    action: String,
    rationale_hash: String,
    confidence: f64,
}

#[derive(Serialize)]
struct LogDecisionOutput {
    decision_id: String,
    agent_did: String,
    entry_hash: String,
    logged_in_tee: bool,
}

#[derive(Deserialize)]
struct AuditDecisionsInput {
    auditor_did: String,
    entries: Vec<DecisionEntry>,
}

#[derive(Deserialize)]
struct DecisionEntry {
    agent_did: String,
    action: String,
    confidence: f64,
}

#[derive(Serialize)]
struct AuditDecisionsOutput {
    total_decisions: u32,
    anomalies_detected: u32,
    risk_score: f64,
    attestation: String,
    audited_in_tee: bool,
}

// ── Phase 11 — Agent Performance Bond ────────────────────────────────────────

#[derive(Deserialize)]
struct LockBondInput {
    agent_did: String,
    task_id: String,
    bond_amount: f64,
    deadline_epoch: u64,
}

#[derive(Serialize)]
struct LockBondOutput {
    bond_id: String,
    agent_did: String,
    task_id: String,
    bond_amount: f64,
    locked_in_tee: bool,
}

#[derive(Deserialize)]
struct VerifyAndSettleInput {
    bond_id: String,
    agent_did: String,
    task_id: String,
    bond_amount: f64,
    deadline_epoch: u64,
    current_epoch: u64,
    completed: bool,
    quality_score: f64,
}

#[derive(Serialize)]
struct VerifyAndSettleOutput {
    bond_id: String,
    settlement: String,
    payout_pct: f64,
    payout_amount: f64,
    reason: String,
    settled_in_tee: bool,
}

// ── Guest implementation ───────────────────────────────────────────────────────

use exports::z::adn_processor::contracts::{GenericInput, Guest};

impl Guest for Component {
    // ── Phase 1 ─────────────────────────────────────────────────────────────

    fn process_data(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("process-data: missing input")?;
        let params: ProcessDataInput = parse_input(&bytes, "process-data")?;

        if params.records.is_empty() {
            return Err("process-data: records array must not be empty".to_string());
        }

        let n = params.records.len();
        let total: f64 = params.records.iter().sum();
        let avg = (total / n as f64 * 100.0).round() / 100.0;
        let min_val = params.records.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = params.records.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        let mid = n / 2;
        let h1_avg = if mid > 0 { params.records[..mid].iter().sum::<f64>() / mid as f64 } else { avg };
        let h2_avg = if n - mid > 0 { params.records[mid..].iter().sum::<f64>() / (n - mid) as f64 } else { avg };
        let pct = if h1_avg != 0.0 { (h2_avg - h1_avg) / h1_avg } else { 0.0 };
        let trend = if pct > 0.05 { "increasing" } else if pct < -0.05 { "decreasing" } else { "stable" };

        encode(&ProcessDataOutput {
            records_processed: n as u32,
            total_revenue: (total * 100.0).round() / 100.0,
            avg_value: avg,
            min_value: (min_val * 100.0).round() / 100.0,
            max_value: (max_val * 100.0).round() / 100.0,
            trend: trend.to_string(),
            processed_in_tee: true,
            data_source: params.data_source,
            time_period: params.time_period,
        })
    }

    fn validate_quality(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("validate-quality: missing input")?;
        let data: ValidateQualityInput = parse_input(&bytes, "validate-quality")?;

        let mut score = 1.0_f64;
        let mut issues = Vec::new();
        if data.records_processed == 0 { issues.push("records_processed is zero".to_string()); score -= 0.4; }
        if data.avg_value <= 0.0 { issues.push("avg_value is non-positive".to_string()); score -= 0.3; }
        if data.total_revenue <= 0.0 { issues.push("total_revenue is non-positive".to_string()); score -= 0.2; }
        if !["increasing", "stable", "decreasing"].contains(&data.trend.as_str()) {
            issues.push(format!("unexpected trend: {:?}", data.trend));
            score -= 0.05;
        }

        encode(&ValidateQualityOutput {
            quality_score: (score.max(0.0) * 100.0).round() / 100.0,
            passed: score >= 0.8,
            issues,
            validated_in_tee: true,
        })
    }

    fn delegate_task(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("delegate-task: missing input")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "delegate-task: clock error")?
            .as_secs();
        let cfg = DelegationConfig {
            trusted_issuer: trusted_issuer(),
            tenant_did: configured_tenant_did(),
            now_secs: now,
            max_ttl_secs: 300,
            clock_skew_secs: 120,
        };
        let out = verify_delegate_task(&bytes, &cfg)?;
        encode(&out)
    }

    // ── Phase 2 — Blind Auction ──────────────────────────────────────────────

    fn submit_bid(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("submit-bid: missing input")?;
        let b: SubmitBidInput = parse_input(&bytes, "submit-bid")?;
        // Seal bid: hash(bidder_did + amount + nonce) — amount hidden from other agents
        let seal = format!("{:x}", simple_hash(&format!("{}:{}:{}", b.bidder_did, b.amount, b.nonce)));
        let receipt = format!("bid-receipt-{}", &seal[..12]);
        encode(&SubmitBidOutput {
            bid_hash: seal,
            item_id: b.item_id,
            sealed_in_tee: true,
            receipt,
        })
    }

    fn resolve_auction(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("resolve-auction: missing input")?;
        let r: ResolveAuctionInput = parse_input(&bytes, "resolve-auction")?;
        if r.bids.is_empty() {
            return Err("resolve-auction: no bids".to_string());
        }
        // Lowest bid wins (auction for work: agents compete on price)
        let winner = r.bids.iter().min_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap()).unwrap();
        encode(&ResolveAuctionOutput {
            winner_did: winner.bidder_did.clone(),
            winning_amount: winner.amount,
            item_id: r.item_id,
            total_bids: r.bids.len() as u32,
            resolved_in_tee: true,
        })
    }

    // ── Phase 3 — Reputation Ledger ──────────────────────────────────────────

    fn record_completion(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("record-completion: missing input")?;
        let r: RecordCompletionInput = parse_input(&bytes, "record-completion")?;
        // delta: quality contributes 0.7, timeliness contributes 0.3
        let delta = r.quality_score * 0.7 + if r.on_time { 1.0 * 0.3 } else { 0.0 };
        let delta = (delta * 100.0).round() / 100.0;
        encode(&RecordCompletionOutput {
            agent_did: r.agent_did,
            task_id: r.task_id,
            reputation_delta: delta,
            recorded_in_tee: true,
        })
    }

    fn get_reputation(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("get-reputation: missing input")?;
        let r: GetReputationInput = parse_input(&bytes, "get-reputation")?;
        if r.history.is_empty() {
            return Err("get-reputation: history is empty".to_string());
        }
        let n = r.history.len() as f64;
        let score: f64 = r.history.iter().map(|e| {
            e.quality_score * 0.7 + if e.on_time { 0.3 } else { 0.0 }
        }).sum::<f64>() / n;
        let score = (score * 100.0).round() / 100.0;
        let tier = if score >= 0.9 { "GOLD" } else if score >= 0.75 { "SILVER" } else { "BRONZE" };
        encode(&GetReputationOutput {
            agent_did: r.agent_did,
            reputation_score: score,
            tier: tier.to_string(),
            tasks_evaluated: r.history.len() as u32,
            computed_in_tee: true,
        })
    }

    // ── Phase 4 — Privacy-Preserving Personalization ─────────────────────────

    fn send_personalized_outreach(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("send-personalized-outreach: missing input")?;
        let r: PersonalizedOutreachInput = parse_input(&bytes, "send-personalized-outreach")?;
        // TEE selects message variant from segment without exposing raw customer data
        let variant = match r.segment.as_str() {
            "high_value"  => "premium_offer",
            "at_risk"     => "retention_offer",
            "new_user"    => "onboarding_offer",
            _             => "standard_offer",
        };
        let score = match r.segment.as_str() {
            "high_value" => 0.95,
            "at_risk"    => 0.82,
            "new_user"   => 0.78,
            _            => 0.70,
        };
        encode(&PersonalizedOutreachOutput {
            customer_id: r.customer_id,
            message_variant: format!("{}:{}", r.template_id, variant),
            personalization_score: score,
            raw_data_exposed: false,
            processed_in_tee: true,
        })
    }

    // ── Phase 5 — Temporal Delegation ────────────────────────────────────────

    fn issue_time_grant(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("issue-time-grant: missing input")?;
        let r: IssueTimeGrantInput = parse_input(&bytes, "issue-time-grant")?;
        // Token = hash(grantee + action + deadline + nonce)
        let token_seed = format!("{}:{}:{}:{}", r.grantee_did, r.action, r.valid_until_epoch, r.issuer_nonce);
        let token = format!("tgrant-{:x}", simple_hash(&token_seed));
        encode(&IssueTimeGrantOutput {
            grant_token: token,
            grantee_did: r.grantee_did,
            action: r.action,
            valid_until_epoch: r.valid_until_epoch,
            issued_in_tee: true,
        })
    }

    fn check_grant(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("check-grant: missing input")?;
        let r: CheckGrantInput = parse_input(&bytes, "check-grant")?;
        if r.current_epoch > r.valid_until_epoch {
            return encode(&CheckGrantOutput {
                valid: false,
                reason: "GRANT_EXPIRED".to_string(),
                checked_in_tee: true,
            });
        }
        if r.grant_token.is_empty() {
            return encode(&CheckGrantOutput {
                valid: false,
                reason: "MISSING_TOKEN".to_string(),
                checked_in_tee: true,
            });
        }
        encode(&CheckGrantOutput {
            valid: true,
            reason: format!("VALID until epoch {}", r.valid_until_epoch),
            checked_in_tee: true,
        })
    }

    // ── Phase 7 — KYC Pipeline ────────────────────────────────────────────────

    fn kyc_submit_step(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("kyc-submit-step: missing input")?;
        let r: KycSubmitStepInput = parse_input(&bytes, "kyc-submit-step")?;
        let all_steps = ["identity", "address", "financial", "compliance"];
        let step_idx = all_steps.iter().position(|&s| s == r.step.as_str()).unwrap_or(0);
        let progress = ((step_idx + 1) as f64 / all_steps.len() as f64 * 100.0).round();
        let receipt = format!("kyc-{}-{}", r.step, &r.data_hash[..8.min(r.data_hash.len())]);
        encode(&KycSubmitStepOutput {
            applicant_id: r.applicant_id,
            step: r.step,
            step_receipt: receipt,
            progress_pct: progress,
            recorded_in_tee: true,
        })
    }

    fn kyc_get_status(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("kyc-get-status: missing input")?;
        let r: KycGetStatusInput = parse_input(&bytes, "kyc-get-status")?;
        let all_steps = ["identity", "address", "financial", "compliance"];
        let missing: Vec<String> = all_steps.iter()
            .filter(|&&s| !r.steps_completed.iter().any(|c| c == s))
            .map(|s| s.to_string())
            .collect();
        let status = if missing.is_empty() { "APPROVED" } else { "PENDING" };
        encode(&KycGetStatusOutput {
            applicant_id: r.applicant_id,
            status: status.to_string(),
            steps_completed: r.steps_completed.len() as u32,
            steps_required: all_steps.len() as u32,
            missing_steps: missing,
            verified_in_tee: true,
        })
    }

    // ── Phase 8 — TEE Secret Vault ────────────────────────────────────────────

    fn store_secret(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("store-secret: missing input")?;
        let r: StoreSecretInput = parse_input(&bytes, "store-secret")?;
        let vault_id = format!("vault-{:x}", simple_hash(&format!("{}:{}:{}", r.owner_did, r.secret_hash, r.label)));
        encode(&StoreSecretOutput {
            vault_id,
            owner_did: r.owner_did,
            label: r.label,
            stored_in_tee: true,
        })
    }

    fn invoke_with_secret(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("invoke-with-secret: missing input")?;
        let r: InvokeWithSecretInput = parse_input(&bytes, "invoke-with-secret")?;
        if r.permission_proof.is_empty() {
            return Err("invoke-with-secret: permission_proof required".to_string());
        }
        encode(&InvokeWithSecretOutput {
            vault_id: r.vault_id,
            action_executed: r.action,
            tee_attested: true,
            raw_secret_exposed: false,
        })
    }

    // ── Phase 9 — Agent DAO ───────────────────────────────────────────────────

    fn cast_vote(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("cast-vote: missing input")?;
        let r: CastVoteInput = parse_input(&bytes, "cast-vote")?;
        let receipt = format!("vote-{:x}", simple_hash(&format!("{}:{}:{}", r.voter_did, r.proposal_id, r.vote)));
        encode(&CastVoteOutput {
            voter_did: r.voter_did,
            proposal_id: r.proposal_id,
            vote_receipt: receipt,
            recorded_in_tee: true,
        })
    }

    fn tally_votes(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("tally-votes: missing input")?;
        let r: TallyVotesInput = parse_input(&bytes, "tally-votes")?;
        let for_votes = r.votes.iter().filter(|v| v.vote == "FOR").count() as u32;
        let against = r.votes.iter().filter(|v| v.vote == "AGAINST").count() as u32;
        let total = r.votes.len() as u32;
        let quorum_met = total >= r.quorum_threshold;
        let result = if quorum_met && for_votes > against { "PASSED" } else if quorum_met { "REJECTED" } else { "NO_QUORUM" };
        encode(&TallyVotesOutput {
            proposal_id: r.proposal_id,
            result: result.to_string(),
            votes_for: for_votes,
            votes_against: against,
            quorum_met,
            tallied_in_tee: true,
        })
    }

    // ── Phase 10 — Decision Audit ─────────────────────────────────────────────

    fn log_decision(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("log-decision: missing input")?;
        let r: LogDecisionInput = parse_input(&bytes, "log-decision")?;
        let entry_hash = format!("{:x}", simple_hash(&format!("{}:{}:{}:{}", r.agent_did, r.decision_id, r.action, r.rationale_hash)));
        encode(&LogDecisionOutput {
            decision_id: r.decision_id,
            agent_did: r.agent_did,
            entry_hash,
            logged_in_tee: true,
        })
    }

    fn audit_decisions(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("audit-decisions: missing input")?;
        let r: AuditDecisionsInput = parse_input(&bytes, "audit-decisions")?;
        // Flag decisions with confidence < 0.5 as anomalies
        let anomalies = r.entries.iter().filter(|e| e.confidence < 0.5).count() as u32;
        let total = r.entries.len() as u32;
        let risk = if total > 0 { (anomalies as f64 / total as f64 * 100.0).round() / 100.0 } else { 0.0 };
        let attestation = format!("audit-{:x}", simple_hash(&r.auditor_did));
        encode(&AuditDecisionsOutput {
            total_decisions: total,
            anomalies_detected: anomalies,
            risk_score: risk,
            attestation,
            audited_in_tee: true,
        })
    }

    // ── Phase 11 — Performance Bond ───────────────────────────────────────────

    fn lock_bond(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("lock-bond: missing input")?;
        let r: LockBondInput = parse_input(&bytes, "lock-bond")?;
        let bond_id = format!("bond-{:x}", simple_hash(&format!("{}:{}", r.agent_did, r.task_id)));
        encode(&LockBondOutput {
            bond_id,
            agent_did: r.agent_did,
            task_id: r.task_id,
            bond_amount: r.bond_amount,
            locked_in_tee: true,
        })
    }

    fn verify_and_settle(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("verify-and-settle: missing input")?;
        let r: VerifyAndSettleInput = parse_input(&bytes, "verify-and-settle")?;
        let on_time = r.current_epoch <= r.deadline_epoch;

        let (payout_pct, reason, settlement) = if !r.completed {
            (0.0, "TASK_INCOMPLETE", "SLASHED")
        } else if !on_time {
            (0.5, "DELIVERED_LATE", "PARTIAL")
        } else if r.quality_score >= 0.9 {
            (1.0, "EXCELLENT_DELIVERY", "FULL")
        } else if r.quality_score >= 0.7 {
            (r.quality_score, "ACCEPTABLE_DELIVERY", "PARTIAL")
        } else {
            (0.25, "BELOW_THRESHOLD", "PENALIZED")
        };

        encode(&VerifyAndSettleOutput {
            bond_id: r.bond_id,
            settlement: settlement.to_string(),
            payout_pct,
            payout_amount: (r.bond_amount * payout_pct * 100.0).round() / 100.0,
            reason: reason.to_string(),
            settled_in_tee: true,
        })
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

// Lightweight hash for deterministic IDs inside the WASM enclave.
// Not cryptographic — for receipt/ID generation only.
fn simple_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}



// ── Contract-level delegate_task tests (v3.9.1) ───────────────────────────────
// Exercise the full verify_delegate_task authorization path (not just crypto helpers)
// by signing deterministically in-test with k256 and asserting accept/reject.
#[cfg(test)]
mod delegate_tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey};
    use sha3::{Digest as _, Keccak256};

    fn b64(b: &[u8]) -> String { B64.encode(b) }
    fn agent_key() -> SigningKey { SigningKey::from_slice(&[7u8; 32]).unwrap() }
    fn legit_user() -> SigningKey { SigningKey::from_slice(&[9u8; 32]).unwrap() }

    fn address_of(sk: &SigningKey) -> [u8; 20] {
        let pt = sk.verifying_key().to_encoded_point(false);
        let h = Keccak256::digest(&pt.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        a
    }

    fn req_hash(to: &str, action: &str) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct CR<'a> { to_agent_id: &'a str, action: &'a str }
        let canon = serde_json::to_vec(&CR { to_agent_id: to, action }).unwrap();
        Sha256::digest(&canon).to_vec()
    }

    fn eip191_sign(msg: &[u8], sk: &SigningKey) -> Vec<u8> {
        let mut pre = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
        pre.extend_from_slice(msg);
        let dig = Keccak256::digest(&pre);
        let (sig, rec): (Signature, RecoveryId) = sk.sign_prehash_recoverable(&dig).unwrap();
        let mut v = sig.to_bytes().to_vec();
        v.push(27 + rec.to_byte());
        v
    }

    struct Parts {
        to: String,
        action: String,
        nb: u64,
        na: u64,
        contract: String,
        tenant: String,
        policy_to: String,
        policy_actions: Vec<String>,
        policy_ttl: u64,
        user_sk: SigningKey,
        include_user_sig: bool,
        forge_agent_sig: bool,
        stale_request_hash: bool,
        omit_envelope: bool,
    }
    impl Default for Parts {
        fn default() -> Self {
            Parts {
                to: "did:key:ed25519:worker-1".into(),
                action: "PROCESS_DATA".into(),
                nb: 1_700_000_000,
                na: 1_700_000_200,
                contract: "adn-processor".into(),
                tenant: "did:t3n:test".into(),
                policy_to: "did:key:ed25519:worker-1".into(),
                policy_actions: vec!["PROCESS_DATA".into()],
                policy_ttl: 300,
                user_sk: legit_user(),
                include_user_sig: true,
                forge_agent_sig: false,
                stale_request_hash: false,
                omit_envelope: false,
            }
        }
    }

    fn cfg() -> DelegationConfig {
        DelegationConfig {
            trusted_issuer: Some(address_of(&legit_user())),
            tenant_did: Some("did:t3n:test".into()),
            now_secs: 1_700_000_100,
            max_ttl_secs: 300,
            clock_skew_secs: 120,
        }
    }

    fn assemble(p: &Parts) -> String {
        let ak = agent_key();
        let apk = ak.verifying_key().to_encoded_point(true);
        let vc_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let nonce: [u8; 16] = [0xaa; 16];

        let policy = serde_json::json!({
            "to_agent_id": p.policy_to,
            "actions": p.policy_actions,
            "max_ttl_secs": p.policy_ttl,
        }).to_string();

        let cred = serde_json::json!({
            "v": "ot3.delegation/1",
            "contract": p.contract,
            "functions": ["delegate-task", "process-data"],
            "not_before_secs": p.nb.to_string(),
            "not_after_secs": p.na.to_string(),
            "vc_id": b64(&vc_id),
            "agent_pubkey": b64(apk.as_bytes()),
            "user_did": p.tenant,
            "org_did": p.tenant,
            "metadata": { "adn_authorization_v1": policy },
        });
        let cred_bytes = serde_json::to_vec(&cred).unwrap();

        // request_hash binds the SIGNED (policy) action unless stale_request_hash.
        let rh = req_hash(&p.to, &p.action);
        let preimage = crypto::build_preimage(&vc_id, &nonce, &rh);
        let dig = Sha256::digest(&preimage);
        let sig: Signature = ak.sign_prehash(&dig).unwrap();
        let mut agent_sig = sig.to_bytes().to_vec();
        if p.forge_agent_sig { agent_sig[0] ^= 0xff; }

        let sent_rh = if p.stale_request_hash { req_hash(&p.to, "SOMETHING_ELSE") } else { rh };

        let mut envelope = serde_json::Map::new();
        envelope.insert("credential_jcs".into(), serde_json::json!(b64(&cred_bytes)));
        if p.include_user_sig {
            envelope.insert("user_sig".into(), serde_json::json!(b64(&eip191_sign(&cred_bytes, &p.user_sk))));
        }
        envelope.insert("nonce".into(), serde_json::json!(b64(&nonce)));
        envelope.insert("agent_sig".into(), serde_json::json!(b64(&agent_sig)));
        envelope.insert("request_hash".into(), serde_json::json!(b64(&sent_rh)));

        let mut input = serde_json::Map::new();
        input.insert("to_agent_id".into(), serde_json::json!(p.to));
        input.insert("action".into(), serde_json::json!(p.action));
        if !p.omit_envelope {
            input.insert("__delegation_envelope".into(), serde_json::Value::Object(envelope));
        }
        serde_json::to_string(&serde_json::Value::Object(input)).unwrap()
    }

    #[test]
    fn valid_trusted_issuer_accepts() {
        let out = verify_delegate_task(assemble(&Parts::default()).as_bytes(), &cfg());
        assert!(out.is_ok(), "expected accept, got {:?}", out.err());
    }

    #[test]
    fn delegation_id_uses_digest_not_target_prefix() {
        let out = verify_delegate_task(assemble(&Parts::default()).as_bytes(), &cfg()).unwrap();
        assert!(out.delegation_id.starts_with("tee-del-"));
        assert_eq!(out.delegation_id.len(), "tee-del-".len() + 32);
        assert_ne!(out.delegation_id, "tee-del-did:key:");
    }

    #[test]
    fn missing_user_sig_rejected() {
        let p = Parts { include_user_sig: false, ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn untrusted_issuer_rejected() {
        let p = Parts { user_sk: SigningKey::from_slice(&[3u8; 32]).unwrap(), ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn issuer_not_pinned_rejects() {
        let mut c = cfg();
        c.trusted_issuer = None;
        assert!(verify_delegate_task(assemble(&Parts::default()).as_bytes(), &c).is_err());
    }

    #[test]
    fn wrong_contract_rejected() {
        let p = Parts { contract: "evil-contract".into(), ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn wrong_tenant_did_rejected() {
        let p = Parts { tenant: "did:t3n:attacker".into(), ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn wrong_signed_target_rejected() {
        let p = Parts { policy_to: "did:key:ed25519:other".into(), ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn wrong_signed_action_rejected() {
        let p = Parts { action: "DELETE_ALL".into(), ..Default::default() };
        // request_hash binds DELETE_ALL, but policy only allows PROCESS_DATA.
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn modified_request_field_rejected() {
        let p = Parts { stale_request_hash: true, ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn ttl_exceeds_max_rejected() {
        let p = Parts { nb: 1_700_000_000, na: 1_700_000_500, ..Default::default() }; // 500s > 300s
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn forged_agent_sig_rejected() {
        let p = Parts { forge_agent_sig: true, ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn missing_envelope_rejected() {
        let p = Parts { omit_envelope: true, ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn policy_ttl_zero_rejected() {
        let p = Parts { policy_ttl: 0, ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn policy_ttl_over_max_rejected() {
        let p = Parts { policy_ttl: 400, ..Default::default() };
        assert!(verify_delegate_task(assemble(&p).as_bytes(), &cfg()).is_err());
    }

    #[test]
    fn sdk_generated_policy_credential_accepts() {
        // End-to-end: full credential built by the real @terminal3/t3n-sdk
        // (scripts/gen_policy_fixture.mjs) with adn_authorization_v1 in metadata,
        // pinned-issuer user_sig, and agent_sig — proves the JCS wire format
        // round-trips through verify_delegate_task.
        let fx = include_str!("../tests/policy_fixture.json");
        let v: serde_json::Value = serde_json::from_str(fx).unwrap();
        let input = v["input_json"].as_str().unwrap();
        let issuer = parse_addr_hex(v["trusted_issuer_hex"].as_str().unwrap()).unwrap();
        let cfg = DelegationConfig {
            trusted_issuer: Some(issuer),
            tenant_did: Some(v["tenant_did"].as_str().unwrap().to_string()),
            now_secs: v["now_secs"].as_u64().unwrap(),
            max_ttl_secs: 300,
            clock_skew_secs: 120,
        };
        let out = verify_delegate_task(input.as_bytes(), &cfg);
        assert!(out.is_ok(), "SDK fixture rejected: {:?}", out.err());
    }

    fn current_guest_input(tenant: &str) -> GenericInput {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let p = Parts {
            nb: now.saturating_sub(10),
            na: now + 120,
            tenant: tenant.to_string(),
            ..Default::default()
        };
        GenericInput {
            input: Some(assemble(&p).into_bytes()),
            user_profile: None,
            context: None,
        }
    }

    #[test]
    fn guest_delegate_task_fails_closed_without_pinned_issuer() {
        if trusted_issuer().is_some() {
            return;
        }
        let out = <Component as Guest>::delegate_task(current_guest_input("did:t3n:test"));
        assert!(
            out.unwrap_err().contains("trusted issuer not pinned"),
            "expected production path to fail closed without ADN_TRUSTED_ISSUER"
        );
    }

    #[test]
    fn guest_delegate_task_accepts_when_build_pinned_to_test_issuer() {
        let test_issuer = parse_addr_hex("58da990a8f4a3a6ca7cb6315d68a140105917352").unwrap();
        let pinned_fixture =
            trusted_issuer() == Some(test_issuer)
                && configured_tenant_did().as_deref() == Some("did:t3n:fixture");
        if !pinned_fixture {
            return;
        }

        let out = <Component as Guest>::delegate_task(current_guest_input("did:t3n:fixture"));
        assert!(out.is_ok(), "pinned production path rejected: {:?}", out.err());
    }
}
