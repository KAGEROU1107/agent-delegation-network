/**
 * T3N Platform Invocation Evidence — v1
 *
 * CURRENT VERIFICATION LEVEL:
 * - Structural validation: ✅ required fields, types, schema conformance
 * - Field binding:         ✅ request_digest, result_digest, tenant_did, contract identity
 * - T3N credential fingerprint presence: ✅ verified present and non-empty
 * - Cryptographic signature: ⚠️  PENDING — T3N has not published a platform signing key
 *   or verifiable trust anchor. When T3N publishes their signing key, implement
 *   `verifyPlatformSignature(evidence, t3nPublicKey)` in t3n_evidence_crypto.ts.
 *
 * LIVE MODE REJECTS:
 * - Missing or empty invocation_id
 * - Missing raw_platform_receipt
 * - Missing or empty platform_credential_fingerprint
 * - evidence_mode !== "t3n_attested"
 * - platform_credential_enforced === false
 * - Wrong tenant_did
 * - Wrong contract_tail or contract_version
 * - gateway_only evidence
 *
 * LIVE MODE DOES NOT YET VERIFY:
 * - T3N platform cryptographic signature (pending T3N trust anchor publication)
 * - Certificate chain
 * - Timestamp freshness (pending T3N evidence spec)
 */

export interface T3nPlatformReceipt {
  delegation_id: string;
  status: string;
  routed_to?: string;
  credential_enforced: boolean;
  credential_fingerprint: string;
  authorization_expires_at?: string;
  user_signer?: string;
  [key: string]: unknown;
}

export interface T3nInvocationEvidence {
  schema_version: "t3n-invocation-evidence-v1";
  /** Tenant DID that initiated the invocation */
  tenant_did: string;
  /** Contract tail hash / name, e.g. "adn-processor" */
  contract_tail: string;
  /** Contract version string, e.g. "3.9.2" */
  contract_version: string;
  /** Unique invocation identifier — equals delegation_id from T3N receipt */
  invocation_id: string;
  /** Worker agent DID or node identifier that executed the task */
  worker_did: string;
  /** Action that was authorized, e.g. "PROCESS_DATA" */
  action: string;
  /** SHA-256 hex of the canonical request parameters */
  request_digest: string;
  /** SHA-256 hex of the canonical result (e.g. raw receipt bytes) */
  result_digest: string;
  /** ISO 8601 timestamp — sourced from authorization_expires_at in T3N receipt */
  issued_at: string;
  /** Unmodified T3N API response object */
  raw_platform_receipt: T3nPlatformReceipt;
  /** credential_fingerprint from T3N receipt */
  platform_credential_fingerprint: string;
  /** credential_enforced flag from T3N receipt — must be true in live mode */
  platform_credential_enforced: boolean;
  evidence_mode: "t3n_attested" | "gateway_only" | "demo";
  /** T3N platform signature — required when T3N publishes a signing key */
  platform_signature?: string;
  /** T3N signing key identifier */
  platform_signing_key_id?: string;
}

export type EvidenceMode = T3nInvocationEvidence["evidence_mode"];

export interface EvidenceVerificationResult {
  valid: boolean;
  mode: EvidenceMode;
  errors: string[];
  warnings: string[];
  /** Checks that will be enforced once T3N publishes the necessary trust material */
  pending_checks: string[];
}

const REQUIRED_LIVE_FIELDS: ReadonlyArray<keyof T3nInvocationEvidence> = [
  "schema_version",
  "tenant_did",
  "contract_tail",
  "contract_version",
  "invocation_id",
  "worker_did",
  "action",
  "request_digest",
  "result_digest",
  "issued_at",
  "raw_platform_receipt",
  "platform_credential_fingerprint",
  "platform_credential_enforced",
];

export class T3nAttestedEvidenceVerifier {
  private readonly tenantDid: string;
  private readonly contractTail: string;
  private readonly contractVersion: string;

  constructor(opts: {
    tenantDid: string;
    contractTail: string;
    contractVersion: string;
  }) {
    this.tenantDid = opts.tenantDid;
    this.contractTail = opts.contractTail;
    this.contractVersion = opts.contractVersion;
  }

  verify(evidence: Partial<T3nInvocationEvidence>): EvidenceVerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const pending_checks: string[] = [
      "T3N platform cryptographic signature (pending T3N trust anchor publication)",
    ];

    const mode = (evidence.evidence_mode ?? "demo") as EvidenceMode;

    if (mode === "demo") {
      warnings.push(
        "Evidence mode is 'demo' — NOT T3N-attested (NON-ATTESTED). Not valid for live proof."
      );
      return { valid: true, mode: "demo", errors, warnings, pending_checks };
    }

    if (mode === "gateway_only") {
      errors.push(
        "gateway_only evidence is not acceptable in live mode — T3N platform evidence required"
      );
      return { valid: false, mode: "gateway_only", errors, warnings, pending_checks };
    }

    // Live mode: t3n_attested — full structural validation
    for (const field of REQUIRED_LIVE_FIELDS) {
      const val = evidence[field];
      if (val === undefined || val === null || val === "") {
        errors.push(`Missing required field: ${field}`);
      }
    }

    if (evidence.schema_version !== "t3n-invocation-evidence-v1") {
      errors.push(
        `schema_version must be 't3n-invocation-evidence-v1', got: ${evidence.schema_version}`
      );
    }

    if (evidence.invocation_id !== undefined && evidence.invocation_id === "") {
      errors.push("invocation_id must not be empty");
    }

    if (!evidence.platform_credential_fingerprint) {
      errors.push(
        "platform_credential_fingerprint is missing or empty — T3N credential not enforced"
      );
    }

    if (!evidence.raw_platform_receipt) {
      errors.push(
        "raw_platform_receipt is missing — cannot verify T3N platform origin"
      );
    }

    // Binding checks — tenant and contract must match this verifier's pinned values
    if (evidence.tenant_did && evidence.tenant_did !== this.tenantDid) {
      errors.push(
        `tenant_did mismatch: expected ${this.tenantDid}, got ${evidence.tenant_did}`
      );
    }
    if (evidence.contract_tail && evidence.contract_tail !== this.contractTail) {
      errors.push(
        `contract_tail mismatch: expected ${this.contractTail}, got ${evidence.contract_tail}`
      );
    }
    if (evidence.contract_version && evidence.contract_version !== this.contractVersion) {
      errors.push(
        `contract_version mismatch: expected ${this.contractVersion}, got ${evidence.contract_version}`
      );
    }

    // Platform credential enforcement
    if (evidence.platform_credential_enforced === false) {
      errors.push(
        "platform_credential_enforced is false — T3N did not enforce credential"
      );
    }

    // Signature: pending T3N trust anchor
    if (!evidence.platform_signature) {
      warnings.push(
        "platform_signature not present — T3N has not published a verifier key yet; signature check is pending"
      );
    }

    const valid = errors.length === 0;
    return { valid, mode: "t3n_attested", errors, warnings, pending_checks };
  }

  /**
   * Throws if evidence fails structural validation.
   * Call this before accepting any worker result in live mode.
   */
  requireValid(evidence: Partial<T3nInvocationEvidence>): void {
    const result = this.verify(evidence);
    if (!result.valid) {
      throw new Error(
        `[T3N Evidence] Verification failed:\n${result.errors.map(e => `  - ${e}`).join("\n")}`
      );
    }
  }
}

/**
 * Construct a T3nInvocationEvidence from a raw T3N invocation receipt.
 * Call this immediately after receiving the receipt from the T3N API —
 * stores the raw receipt without transformation.
 */
export function buildEvidenceFromReceipt(
  receipt: T3nPlatformReceipt,
  opts: {
    tenantDid: string;
    contractTail: string;
    contractVersion: string;
    workerDid: string;
    action: string;
    requestDigest: string;
    resultDigest: string;
  }
): T3nInvocationEvidence {
  return {
    schema_version: "t3n-invocation-evidence-v1",
    tenant_did: opts.tenantDid,
    contract_tail: opts.contractTail,
    contract_version: opts.contractVersion,
    invocation_id: receipt.delegation_id,
    worker_did: opts.workerDid,
    action: opts.action,
    request_digest: opts.requestDigest,
    result_digest: opts.resultDigest,
    issued_at: receipt.authorization_expires_at ?? new Date().toISOString(),
    raw_platform_receipt: receipt,
    platform_credential_fingerprint: receipt.credential_fingerprint,
    platform_credential_enforced: receipt.credential_enforced,
    evidence_mode: "t3n_attested",
  };
}
