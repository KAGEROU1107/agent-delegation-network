// Ground-truth crypto vector generator — imports the REAL SDK and dumps exact bytes.
import {
  buildInvocationPreimage,
  signAgentInvocation,
  DELEGATION_INVOCATION_DOMAIN,
  VC_ID_LEN, NONCE_LEN, REQUEST_HASH_LEN, AGENT_PUBKEY_LEN,
} from "@terminal3/t3n-sdk";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

const hex = (u8) => Buffer.from(u8).toString("hex");
const b64u = (u8) => Buffer.from(u8).toString("base64url");

const agentSecret = Uint8Array.from(Buffer.from("1111111111111111111111111111111111111111111111111111111111111111", "hex"));
const agentPubkey = secp256k1.getPublicKey(agentSecret, true);
const vcId  = Uint8Array.from(Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"));
const nonce = Uint8Array.from(Buffer.from("aabbccddeeff00112233445566778899", "hex"));

const callParams = { to_agent_id: "did:key:ed25519:worker-1", action: "PROCESS_DATA" };
const callJson = JSON.stringify(callParams);
const reqHash = sha256(new TextEncoder().encode(callJson));

const preimage = buildInvocationPreimage(vcId, nonce, reqHash);
const agentSig = signAgentInvocation(preimage, agentSecret);
const digest = sha256(preimage);
const ok = secp256k1.verify(agentSig, digest, agentPubkey, { prehash: false });

const out = {
  meta: {
    domain_utf8: DELEGATION_INVOCATION_DOMAIN,
    domain_hex: hex(new TextEncoder().encode(DELEGATION_INVOCATION_DOMAIN)),
    VC_ID_LEN, NONCE_LEN, REQUEST_HASH_LEN, AGENT_PUBKEY_LEN,
    agent_sig_len: agentSig.length,
    noble_self_verify: ok,
  },
  vector: {
    agent_secret_hex: hex(agentSecret),
    agent_pubkey_hex: hex(agentPubkey),
    vc_id_hex: hex(vcId),
    nonce_hex: hex(nonce),
    call_params_json: callJson,
    request_hash_hex: hex(reqHash),
    preimage_hex: hex(preimage),
    agent_sig_hex: hex(agentSig),
    nonce_b64u: b64u(nonce),
    request_hash_b64u: b64u(reqHash),
    agent_sig_b64u: b64u(agentSig),
    agent_pubkey_b64u: b64u(agentPubkey),
  },
};
console.log(JSON.stringify(out, null, 2));