// SDK-generated end-to-end policy fixture (audit H-10/H-02).
// Builds the EXACT bridge wire format: credential with adn_authorization_v1 +
// pinned-issuer user_sig + agent_sig + request_hash, then dumps it so a Rust test
// can run it through verify_delegate_task and prove the JCS metadata round-trips.
import {
  buildDelegationCredential, canonicaliseCredential, signCredential,
  buildInvocationPreimage, signAgentInvocation, b64uEncodeBytes,
} from "@terminal3/t3n-sdk";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

const b64u = (u8) => Buffer.from(u8).toString("base64url");
const issuerSecret = Uint8Array.from(Buffer.from("22".repeat(32), "hex"));
const agentSecret  = Uint8Array.from(Buffer.from("11".repeat(32), "hex"));
const agentPubkey  = secp256k1.getPublicKey(agentSecret, true);
const issuerPubUnc = secp256k1.getPublicKey(issuerSecret, false);
const issuerAddr   = Buffer.from(keccak_256(issuerPubUnc.slice(1)).slice(-20)).toString("hex");

const tenant = "did:t3n:fixture";
const to = "did:key:ed25519:worker-fixture";
const action = "PROCESS_DATA";
const vcId = Uint8Array.from(Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"));
const policy = JSON.stringify({ to_agent_id: to, actions: [action], max_ttl_secs: 300 });

const credential = buildDelegationCredential({
  user_did: tenant, agent_pubkey: agentPubkey, org_did: tenant,
  contract: "adn-processor", functions: ["delegate-task", "process-data"],
  scopes: [], metadata: { role: "adn-worker", adn_authorization_v1: policy },
  not_before_secs: 1700000000n, not_after_secs: 1700000200n, vc_id: vcId,
});
const jcs = canonicaliseCredential(credential);
const { sig: userSig } = signCredential(jcs, issuerSecret);

const callJson = JSON.stringify({ to_agent_id: to, action });
const reqHash = sha256(new TextEncoder().encode(callJson));
const nonce = Uint8Array.from(Buffer.from("aabbccddeeff00112233445566778899", "hex"));
const preimage = buildInvocationPreimage(vcId, nonce, reqHash);
const agentSig = signAgentInvocation(preimage, agentSecret);

const input = {
  to_agent_id: to, action,
  __delegation_envelope: {
    credential_jcs: b64uEncodeBytes(jcs),
    user_sig: b64uEncodeBytes(userSig),
    agent_sig: b64uEncodeBytes(agentSig),
    nonce: b64u(nonce),
    request_hash: b64u(reqHash),
  },
};
console.log(JSON.stringify({ trusted_issuer_hex: issuerAddr, tenant_did: tenant, now_secs: 1700000100, input_json: JSON.stringify(input) }, null, 2));
