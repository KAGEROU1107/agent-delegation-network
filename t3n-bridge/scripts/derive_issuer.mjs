// Derive the tenant issuer Ethereum address from T3N_API_KEY so the contract can
// be built with ADN_TRUSTED_ISSUER pinned. The address is public (not secret).
//
//   T3N_API_KEY=0x<key> node scripts/derive_issuer.mjs
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

const key = (process.env.T3N_API_KEY || "").replace(/^0x/, "");
if (key.length !== 64) {
  console.error("Set T3N_API_KEY=0x<64-hex> in the environment first.");
  process.exit(1);
}
const sk = Uint8Array.from(Buffer.from(key, "hex"));
const pub = secp256k1.getPublicKey(sk, false);            // 65-byte uncompressed
const addr = keccak_256(pub.slice(1)).slice(-20);          // last 20 bytes of keccak(pubkey)
const hex = Buffer.from(addr).toString("hex");
console.log("Tenant issuer address: 0x" + hex);
console.log("");
console.log("Build the contract pinned to this issuer:");
console.log(`  cd contract`);
console.log(`  ADN_TRUSTED_ISSUER=${hex} cargo test --locked`);
console.log(`  ADN_TRUSTED_ISSUER=${hex} cargo build --locked --target wasm32-wasip2 --release`);
console.log("");
console.log("Optional tenant-DID pin (use the DID printed in Phase 1):");
console.log(`  ADN_TRUSTED_ISSUER=${hex} ADN_TENANT_DID=did:t3n:<tenant-hex> cargo test --locked`);
console.log(`  ADN_TRUSTED_ISSUER=${hex} ADN_TENANT_DID=did:t3n:<tenant-hex> cargo build --locked --target wasm32-wasip2 --release`);
