import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
} from "crypto";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = join(__dirname, "../../schemas/adn-release-proof-v1.schema.json");
const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue | undefined };

function compareJsonKeys(left: string, right: string): number {
  const leftPoints = Array.from(left, (char) => char.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (char) => char.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const delta = leftPoints[index] - rightPoints[index];
    if (delta !== 0) return delta;
  }
  return leftPoints.length - rightPoints.length;
}

export function canonicalJson(value: unknown): string {
  if (value === undefined) {
    throw new Error("canonical JSON cannot encode undefined");
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonical JSON cannot encode non-finite numbers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, JsonValue | undefined>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => compareJsonKeys(left, right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(",")}}`;
  }
  throw new Error(`canonical JSON cannot encode ${typeof value}`);
}

export function digestCanonicalJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function loadReleaseProofSchema(): Record<string, unknown> {
  return JSON.parse(readFileSync(SCHEMA_PATH, "utf-8")) as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`release manifest schema ${label} must be a non-empty string`);
  }
  return value;
}

export function validateReleaseManifestAgainstSchema(manifest: Record<string, unknown>): void {
  const schema = loadReleaseProofSchema();
  const required = schema.required as string[];
  const properties = schema.properties as Record<string, Record<string, unknown>>;
  const allowed = new Set(Object.keys(properties));

  for (const key of required) {
    if (manifest[key] === undefined || manifest[key] === null || manifest[key] === "") {
      throw new Error(`release manifest schema missing required field: ${key}`);
    }
  }

  for (const key of Object.keys(manifest)) {
    if (!allowed.has(key)) {
      throw new Error(`release manifest schema additional property not allowed: ${key}`);
    }
  }

  for (const [key, value] of Object.entries(manifest)) {
    const rule = properties[key];
    if (!rule || value === undefined) continue;

    if (rule.const !== undefined && value !== rule.const) {
      throw new Error(`release manifest schema ${key} must equal ${rule.const}`);
    }
    if (Array.isArray(rule.enum) && !rule.enum.includes(value)) {
      throw new Error(`release manifest schema ${key} must be one of ${rule.enum.join(", ")}`);
    }
    if (rule.type === "string") {
      const stringValue = requireString(value, key);
      const minLength = typeof rule.minLength === "number" ? rule.minLength : 0;
      if (stringValue.length < minLength) {
        throw new Error(`release manifest schema ${key} is shorter than ${minLength}`);
      }
      if (typeof rule.pattern === "string" && !new RegExp(rule.pattern).test(stringValue)) {
        throw new Error(`release manifest schema ${key} does not match ${rule.pattern}`);
      }
    }
    if (rule.type === "integer") {
      if (!Number.isInteger(value)) {
        throw new Error(`release manifest schema ${key} must be an integer`);
      }
      const minimum = typeof rule.minimum === "number" ? rule.minimum : undefined;
      if (minimum !== undefined && (value as number) < minimum) {
        throw new Error(`release manifest schema ${key} must be >= ${minimum}`);
      }
    }
  }
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

export function deriveEd25519PublicKeyHexFromSeed(seedHex: string): string {
  const privateKey = privateKeyFromSeedHex(seedHex);
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32).toString("hex");
}

export function signReleaseManifestWithSeed(manifestBody: Record<string, unknown>, seedHex: string) {
  const normalizedSeed = seedHex.trim().replace(/^0x/i, "").toLowerCase();
  const privateKey = privateKeyFromSeedHex(normalizedSeed);
  const signedBody = Buffer.from(canonicalJson(manifestBody), "utf-8");
  return {
    algorithm: "ed25519",
    public_key_hex: deriveEd25519PublicKeyHexFromSeed(normalizedSeed),
    signature_hex: signBytes(null, signedBody, privateKey).toString("hex"),
  };
}
