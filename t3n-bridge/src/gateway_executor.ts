/**
 * Gateway Executor — isolated signing process.
 *
 * This is the ONLY process that holds ADN_GATEWAY_PRIVATE_KEY_HEX.
 * The bridge spawns it with the key in the child environment and
 * immediately deletes the key from its own process.env.
 *
 * Protocol: newline-delimited JSON over loopback TCP (127.0.0.1).
 * On startup, prints "GATEWAY_EXECUTOR_READY:<port>" to stdout.
 *
 * Supported methods:
 *   get_public_key  → { publicKeyHex, agentId, did, gatewayKeyId }
 *   sign_receipt    → { receipt: <signed_tee_authorization_receipt> }
 *
 * The receipt format exactly matches Python's build_tee_authorization_receipt
 * so that Python's verify_tee_authorization_receipt can validate it without
 * any changes to the verification logic.
 */

import * as net from "net";
import * as crypto from "crypto";
import { ed25519 } from "@noble/curves/ed25519";

// ─── Crypto helpers (must exactly match Python's terminal3_agent_auth_adapter) ───

const AUDIENCE = "t3n-adn-v1";
const PROOF_TTL_SECONDS = 300;
const RECEIPT_VERSION = "adn.tee_authorization/1";
const RECEIPT_ACTION = "TEE_AUTHORIZATION";

/**
 * Canonical JSON — matches Python's json.dumps(obj, sort_keys=True, separators=(",",":")).
 * Keys are sorted recursively. Arrays preserve order.
 */
function canonicalJson(obj: unknown): string {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJson).join(",") + "]";
  }
  const rec = obj as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`);
  return "{" + pairs.join(",") + "}";
}

/** SHA-256 of a UTF-8 string, returned as hex (matches Python's _sha256). */
function sha256hex(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Key fingerprint — matches Python's key_fingerprint:
 *   sha256("terminal3\0" + pub_bytes)[:12]
 */
function keyFingerprint(pubKeyHex: string): string {
  const prefix = Buffer.from("terminal3\x00", "utf8");
  const pub = Buffer.from(pubKeyHex, "hex");
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([prefix, pub]))
    .digest("hex")
    .slice(0, 12);
}

/** ISO-8601 with +00:00 suffix — matches Python's datetime.now(utc).isoformat(). */
function isoNow(): string {
  return new Date().toISOString().replace("Z", "+00:00");
}

function isoFromMs(ms: number): string {
  return new Date(ms).toISOString().replace("Z", "+00:00");
}

// ─── Identity ──────────────────────────────────────────────────────────────────

interface GatewayIdentity {
  privateKeyBytes: Uint8Array;
  publicKeyHex: string;
  agentId: string;
  did: string;
  gatewayKeyId: string;
}

function loadGatewayIdentity(): GatewayIdentity {
  const raw = process.env.ADN_GATEWAY_PRIVATE_KEY_HEX;
  if (!raw?.trim()) {
    throw new Error("ADN_GATEWAY_PRIVATE_KEY_HEX is required");
  }
  const privHex = raw.trim().replace(/^0x/i, "");
  if (!/^[0-9a-f]{64}$/i.test(privHex)) {
    throw new Error("ADN_GATEWAY_PRIVATE_KEY_HEX must be 32 bytes (64 hex chars)");
  }
  const privateKeyBytes = Buffer.from(privHex, "hex");
  const pubBytes = ed25519.getPublicKey(privateKeyBytes);
  const publicKeyHex = Buffer.from(pubBytes).toString("hex");
  const agentId = keyFingerprint(publicKeyHex);
  const did = `did:key:ed25519:${agentId}`;
  const gatewayKeyId =
    process.env.ADN_GATEWAY_KEY_ID?.trim() || `gateway-${publicKeyHex.slice(0, 12)}`;
  return { privateKeyBytes, publicKeyHex, agentId, did, gatewayKeyId };
}

// ─── Signing (matches Python's sign_action_request) ───────────────────────────

interface ActionProof {
  agent_id: string;
  did: string;
  public_key_hex: string;
  action: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  audience: string;
  data_hash?: string;
  payload_hash: string;
  signature_hex: string;
}

function signAction(
  identity: GatewayIdentity,
  action: string,
  nonce: string,
  data?: unknown,
): ActionProof {
  const issuedAt = isoNow();
  const expiresAt = isoFromMs(Date.now() + PROOF_TTL_SECONDS * 1000);
  const dataHash = data !== undefined ? sha256hex(canonicalJson(data)) : undefined;

  // Build payload exactly as Python does
  const payload: Record<string, unknown> = {
    agent_id: identity.agentId,
    did: identity.did,
    public_key_hex: identity.publicKeyHex,
    action,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    audience: AUDIENCE,
  };
  if (dataHash !== undefined) {
    payload.data_hash = dataHash;
  }

  const payloadHash = sha256hex(canonicalJson(payload));

  // Python: priv.sign(payload_hash.encode())
  // .encode() = UTF-8 bytes of the hex string
  const sigBytes = ed25519.sign(
    new TextEncoder().encode(payloadHash),
    identity.privateKeyBytes,
  );

  return {
    ...payload,
    payload_hash: payloadHash,
    signature_hex: Buffer.from(sigBytes).toString("hex"),
  } as ActionProof;
}

// ─── Receipt builder (matches Python's build_tee_authorization_receipt) ────────

function teeAuthorizationRequestHash(
  toAgentId: string,
  action: string,
  parameters: Record<string, unknown> = {},
): string {
  return sha256hex(canonicalJson({ to_agent_id: toAgentId, action, parameters }));
}

export function buildSignedReceipt(
  identity: GatewayIdentity,
  teeResult: Record<string, unknown>,
  action: string,
  parameters: Record<string, unknown> = {},
): Record<string, unknown> {
  const delegationId = teeResult["delegation_id"] as string | undefined;
  const toAgentId = teeResult["routed_to"] as string | undefined;
  if (!delegationId || !toAgentId) {
    throw new Error("TEE authorization requires delegation_id and routed_to");
  }
  if (!identity.gatewayKeyId) {
    throw new Error("TEE authorization requires gateway_key_id");
  }
  const authorizationExpiresAt = teeResult["authorization_expires_at"] as string | undefined;
  if (!authorizationExpiresAt) {
    throw new Error("TEE authorization requires authorization_expires_at");
  }

  const authorizedAt = isoNow();

  const body: Record<string, unknown> = {
    v: RECEIPT_VERSION,
    delegation_id: delegationId,
    tee_delegation_id: delegationId,
    status: teeResult["status"],
    to_agent_id: toAgentId,
    action,
    request_hash: teeAuthorizationRequestHash(toAgentId, action, parameters),
    credential_fingerprint: teeResult["credential_fingerprint"],
    credential_enforced: teeResult["credential_enforced"],
    build_config_id: teeResult["build_config_id"],
    tee_result_digest: sha256hex(canonicalJson(teeResult)),
    gateway_key_id: identity.gatewayKeyId,
    authorization_expires_at: authorizationExpiresAt,
    authorized_at: authorizedAt,
  };

  // Sign the body: action=TEE_AUTHORIZATION, nonce=delegation_id
  const proof = signAction(identity, RECEIPT_ACTION, delegationId, body);

  return {
    ...body,
    gateway_public_key_hex: proof.public_key_hex,
    gateway_proof: proof,
  };
}

// ─── TCP Server ────────────────────────────────────────────────────────────────

function handleRequest(
  identity: GatewayIdentity,
  req: Record<string, unknown>,
): Record<string, unknown> {
  const id = req.id;
  const method = req.method as string;

  if (method === "get_public_key") {
    return {
      id,
      publicKeyHex: identity.publicKeyHex,
      agentId: identity.agentId,
      did: identity.did,
      gatewayKeyId: identity.gatewayKeyId,
    };
  }

  if (method === "sign_receipt") {
    const teeResult = req.teeResult as Record<string, unknown>;
    const action = req.action as string;
    const parameters = (req.parameters as Record<string, unknown>) ?? {};
    const receipt = buildSignedReceipt(identity, teeResult, action, parameters);
    return { id, receipt };
  }

  return { id, error: `unknown method: ${method}` };
}

function startExecutor(): void {
  let identity: GatewayIdentity;
  try {
    identity = loadGatewayIdentity();
  } catch (err) {
    process.stderr.write(`[gateway_executor] startup error: ${(err as Error).message}\n`);
    process.exit(1);
  }

  // Security: scrub the private key from this process's env now that it's loaded
  delete process.env.ADN_GATEWAY_PRIVATE_KEY_HEX;

  const server = net.createServer((socket) => {
    let buf = "";
    socket.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let req: Record<string, unknown>;
        try {
          req = JSON.parse(line) as Record<string, unknown>;
        } catch {
          socket.write(JSON.stringify({ error: "invalid JSON" }) + "\n");
          continue;
        }
        let resp: Record<string, unknown>;
        try {
          resp = handleRequest(identity, req);
        } catch (err) {
          resp = { id: req.id, error: (err as Error).message };
        }
        socket.write(JSON.stringify(resp) + "\n");
      }
    });
    socket.on("error", () => {
      /* ignore individual socket errors */
    });
  });

  server.listen(0, "127.0.0.1", () => {
    const addr = server.address() as net.AddressInfo;
    // Signal readiness to parent — parent reads this line and connects
    process.stdout.write(`GATEWAY_EXECUTOR_READY:${addr.port}\n`);
  });

  server.on("error", (err) => {
    process.stderr.write(`[gateway_executor] server error: ${err.message}\n`);
    process.exit(1);
  });

  // Shut down cleanly when parent closes stdin or sends SIGTERM
  process.on("SIGTERM", () => {
    server.close(() => process.exit(0));
  });
}

startExecutor();
