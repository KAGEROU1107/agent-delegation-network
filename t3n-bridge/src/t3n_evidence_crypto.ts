/**
 * T3N Evidence Cryptographic Verification
 *
 * CURRENT STATUS: STUB — T3N has not published a platform signing key or trust anchor.
 * When available, implement verifyPlatformSignature() using the T3N-provided public key.
 *
 * DO NOT remove this stub — it documents the pending work and is referenced in Phase 3
 * of the ADN remediation plan.
 *
 * When T3N publishes their signing key:
 * 1. Load the trust anchor from the T3N SDK or well-known endpoint
 * 2. Reconstruct the canonical signing payload:
 *    JSON.stringify(evidence without platform_signature, sorted keys)
 * 3. Verify Ed25519 or ECDSA-P256 signature over that payload
 * 4. Replace the stub return below with real verification
 */
import type { T3nInvocationEvidence } from "./t3n_evidence.js";

export interface T3nTrustAnchor {
  publicKeyHex: string;
  keyId: string;
  algorithm: "Ed25519" | "P-256";
}

export async function verifyPlatformSignature(
  evidence: T3nInvocationEvidence,
  trustAnchor: T3nTrustAnchor
): Promise<{ verified: boolean; reason: string }> {
  // STUB: Replace with real signature verification when T3N publishes signing key.
  // Suppress lint warnings for unused params — they document the intended interface.
  void evidence;
  void trustAnchor;
  return {
    verified: false,
    reason:
      "T3N platform signing key not yet published — cryptographic signature verification is pending",
  };
}
