import { buildDelegationCredential, canonicaliseCredential, signCredential, eip191Digest, ethRecoverEip191 } from "@terminal3/t3n-sdk";
import { secp256k1 } from "@noble/curves/secp256k1.js";

const agentSecret = Uint8Array.from(Buffer.from("11".repeat(32), "hex"));
const agentPubkey = secp256k1.getPublicKey(agentSecret, true);
const userSecret  = Uint8Array.from(Buffer.from("22".repeat(32), "hex"));
const vcId = Uint8Array.from(Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"));

const cred = buildDelegationCredential({
  user_did: "did:t3n:abc", agent_pubkey: agentPubkey, org_did: "did:t3n:abc",
  contract: "adn-processor", functions: ["delegate-task","process-data"],
  scopes: [], metadata: { role: "adn-worker" },
  not_before_secs: 1700000000n, not_after_secs: 1700000300n, vc_id: vcId,
});
const jcs = canonicaliseCredential(cred);
const jcsStr = Buffer.from(jcs).toString("utf-8");
console.log("JCS_STRING:");
console.log(jcsStr);
const { sig } = signCredential(jcs, userSecret);
const recovered = ethRecoverEip191(jcs, sig);
console.log("USER_SIG_LEN:", sig.length, "USER_SIG_HEX:", Buffer.from(sig).toString("hex"));
console.log("RECOVERED_ADDR:", Buffer.from(recovered).toString("hex"));