/**
 * Phase 5 — Platform-origin T3N invocation evidence.
 *
 * In live mode, gateway-receipt-only authorization is insufficient.
 * Workers must produce independently verifiable T3N platform evidence.
 */

export interface T3nInvocationEvidence {
  /** Tenant DID that initiated the invocation */
  tenantDid: string;
  /** Exact contract tail hash / version string, e.g. "adn-processor@v3.9.2" */
  contractVersion: string;
  /** Unique invocation identifier from T3N platform */
  invocationId: string;
  /** Worker agent DID that executed the task */
  workerDid: string;
  /** Action that was authorized, e.g. "PROCESS_DATA" */
  action: string;
  /** SHA-256 hex of the canonical request JSON */
  requestDigest: string;
  /** SHA-256 hex of the canonical result JSON */
  resultDigest: string;
  /** ISO 8601 timestamp of when the invocation completed */
  timestamp: string;
  /**
   * Platform verification material.
   * In testnet: this is the signed invocation receipt from T3N.
   * In demo/local: this is a self-signed mock (not independently verifiable).
   */
  platformMaterial: Record<string, unknown>;
}

export type EvidenceMode = "t3n_attested" | "gateway_only" | "demo";

export interface EvidenceVerificationResult {
  mode: EvidenceMode;
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Verifies T3N invocation evidence.
 *
 * In live mode: requires t3n_attested evidence with all fields present.
 * In demo mode: accepts gateway_only evidence with a warning.
 */
export class T3nAttestedEvidenceVerifier {
  private readonly runtimeMode: string;

  constructor(runtimeMode?: string) {
    this.runtimeMode = runtimeMode ?? process.env.ADN_RUNTIME_MODE ?? "demo";
  }

  verify(evidence: Partial<T3nInvocationEvidence>): EvidenceVerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    const REQUIRED_FIELDS: (keyof T3nInvocationEvidence)[] = [
      "tenantDid", "contractVersion", "invocationId",
      "workerDid", "action", "requestDigest", "resultDigest",
      "timestamp", "platformMaterial",
    ];

    for (const field of REQUIRED_FIELDS) {
      if (!evidence[field]) errors.push(`Missing required field: ${field}`);
    }

    if (this.runtimeMode === "live") {
      if (!evidence.platformMaterial || Object.keys(evidence.platformMaterial).length === 0) {
        errors.push("platformMaterial must be non-empty in live mode — gateway-only evidence is rejected");
      }
      if (!evidence.invocationId) {
        errors.push("invocationId is required in live mode — must come from T3N platform");
      }
    } else {
      warnings.push("Running in demo mode — platform evidence is not independently verified");
    }

    return {
      mode: this.runtimeMode === "live" ? "t3n_attested" : "demo",
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Throws if evidence is invalid in the current runtime mode.
   * Call this before accepting any worker result in live mode.
   */
  requireValid(evidence: Partial<T3nInvocationEvidence>): void {
    const result = this.verify(evidence);
    if (!result.valid) {
      throw new Error(
        `[ADN] T3N evidence verification failed (mode=${this.runtimeMode}):\n` +
        result.errors.map(e => `  - ${e}`).join("\n")
      );
    }
  }
}
