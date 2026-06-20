//! Cryptographic verification for delegation envelopes (v3.9.0).
//!
//! Pure-Rust secp256k1 (k256) + Keccak-256 (sha3). Compiles to wasm32-wasip2
//! with no host primitive — refuting the prior "needs secp256k1 host prim" note.
//!
//! Byte formats are pinned to the @terminal3/t3n-sdk ground-truth vectors:
//!   - agent_sig    : 64-byte compact secp256k1 over sha256(preimage)
//!   - preimage     : "ot3.invocation/1" || vc_id(16) || nonce(16) || request_hash(32)
//!   - user_sig     : 65-byte EIP-191 recoverable secp256k1 over the credential JCS bytes
//!   - agent_pubkey : 33-byte compressed secp256k1 (base64url in the credential JCS)

use sha2::{Digest as _, Sha256};
use sha3::{Digest as _, Keccak256};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// SDK DELEGATION_INVOCATION_DOMAIN (ground-truth: "ot3.invocation/1").
pub const INVOCATION_DOMAIN: &[u8] = b"ot3.invocation/1";

/// Build the agent-invocation preimage exactly as the SDK does.
pub fn build_preimage(vc_id: &[u8], nonce: &[u8], request_hash: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(INVOCATION_DOMAIN.len() + vc_id.len() + nonce.len() + request_hash.len());
    p.extend_from_slice(INVOCATION_DOMAIN);
    p.extend_from_slice(vc_id);
    p.extend_from_slice(nonce);
    p.extend_from_slice(request_hash);
    p
}

/// Verify the agent signature: ECDSA(secp256k1) over sha256(preimage) against agent_pubkey.
/// Rejects malformed, wrong-key, and any forged-but-non-empty signature.
pub fn verify_agent_sig(agent_pubkey: &[u8], preimage: &[u8], agent_sig: &[u8]) -> Result<(), String> {
    if agent_pubkey.len() != 33 {
        return Err("agent_pubkey must be 33 bytes (compressed secp256k1)".to_string());
    }
    if agent_sig.len() != 64 {
        return Err("agent_sig must be 64 bytes (compact secp256k1)".to_string());
    }
    let vk = VerifyingKey::from_sec1_bytes(agent_pubkey).map_err(|_| "agent_pubkey not a valid point".to_string())?;
    let sig = Signature::from_slice(agent_sig).map_err(|_| "agent_sig malformed".to_string())?;
    let digest = Sha256::digest(preimage);
    vk.verify_prehash(&digest, &sig).map_err(|_| "agent_sig verification failed".to_string())
}

/// Recover the EIP-191 (personal_sign) signer address over `message`.
/// Returns the 20-byte Ethereum address of whoever produced `sig65`.
/// Proves the signature is a real secp256k1 signature over these exact bytes.
pub fn recover_eip191_address(message: &[u8], sig65: &[u8]) -> Result<[u8; 20], String> {
    if sig65.len() != 65 {
        return Err("user_sig must be 65 bytes (r||s||v)".to_string());
    }
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    prefixed.extend_from_slice(message);
    let digest = Keccak256::digest(&prefixed);

    let v = sig65[64];
    let rec_raw = v.checked_sub(27).ok_or_else(|| "user_sig recovery id out of range".to_string())?;
    let rec_id = RecoveryId::from_byte(rec_raw).ok_or_else(|| "user_sig invalid recovery id".to_string())?;
    let sig = Signature::from_slice(&sig65[..64]).map_err(|_| "user_sig malformed".to_string())?;
    let vk = VerifyingKey::recover_from_prehash(&digest, &sig, rec_id)
        .map_err(|_| "user_sig recovery failed".to_string())?;

    let point = vk.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let addr_hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash[12..]);
    Ok(addr)
}

/// Lower-hex encode (no external crate).
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Ground-truth vectors generated from @terminal3/t3n-sdk (scripts/gen_vectors.mjs).
    const AGENT_PUBKEY: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const VC_ID: &str = "0102030405060708090a0b0c0d0e0f10";
    const NONCE: &str = "aabbccddeeff00112233445566778899";
    const REQ_HASH: &str = "186c87d8447e0000dcb1099e9e3475bb19493d547e3e6ce25e546935a919078b";
    const AGENT_SIG: &str = "e15e54e74c34d36f00ee8c26e5194e8222d6038e1145eeb35ec029be375cf2144785bc8a67433b51e4663b12041ee78cbf5335f3e2d10ec597aba5d481367be7";

    #[test]
    fn preimage_matches_sdk() {
        let p = build_preimage(&unhex(VC_ID), &unhex(NONCE), &unhex(REQ_HASH));
        let expected = "6f74332e696e766f636174696f6e2f310102030405060708090a0b0c0d0e0f10aabbccddeeff00112233445566778899186c87d8447e0000dcb1099e9e3475bb19493d547e3e6ce25e546935a919078b";
        assert_eq!(hex_lower(&p), expected);
    }

    #[test]
    fn valid_agent_sig_accepted() {
        let p = build_preimage(&unhex(VC_ID), &unhex(NONCE), &unhex(REQ_HASH));
        assert!(verify_agent_sig(&unhex(AGENT_PUBKEY), &p, &unhex(AGENT_SIG)).is_ok());
    }

    #[test]
    fn forged_nonempty_agent_sig_rejected() {
        let p = build_preimage(&unhex(VC_ID), &unhex(NONCE), &unhex(REQ_HASH));
        let mut bad = unhex(AGENT_SIG);
        bad[0] ^= 0xff; // flip a byte — still 64 bytes, still non-empty
        assert!(verify_agent_sig(&unhex(AGENT_PUBKEY), &p, &bad).is_err());
    }

    #[test]
    fn tampered_request_hash_breaks_sig() {
        // Altering the bound request_hash invalidates the agent signature.
        let mut rh = unhex(REQ_HASH);
        rh[5] ^= 0x01;
        let p = build_preimage(&unhex(VC_ID), &unhex(NONCE), &rh);
        assert!(verify_agent_sig(&unhex(AGENT_PUBKEY), &p, &unhex(AGENT_SIG)).is_err());
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let p = build_preimage(&unhex(VC_ID), &unhex(NONCE), &unhex(REQ_HASH));
        let mut pk = unhex(AGENT_PUBKEY);
        pk[10] ^= 0x01;
        assert!(verify_agent_sig(&pk, &p, &unhex(AGENT_SIG)).is_err());
    }

    #[test]
    fn user_sig_recovers_expected_address() {
        // Ground truth from scripts/gen_jcs.mjs (userSecret = 0x22*32).
        let jcs = r#"{"agent_pubkey":"A081W9y3zAr3KO88zrlhXZBoS7Wyyl-FmrDwtwQHWHGq","contract":"adn-processor","functions":["delegate-task","process-data"],"metadata":{"role":"adn-worker"},"not_after_secs":"1700000300","not_before_secs":"1700000000","org_did":"did:t3n:abc","scopes":[],"user_did":"did:t3n:abc","v":"ot3.delegation/1","vc_id":"AQIDBAUGBwgJCgsMDQ4PEA"}"#;
        let user_sig = unhex("987640f3ff30a199f78c0e8b2a8af738770da0b2243e35752458e0a0c2857a503c05442f41d4f75294a52d83c39cc6cdbd7ef1a2de8a25352e81c400414f5f721b");
        let addr = recover_eip191_address(jcs.as_bytes(), &user_sig).unwrap();
        assert_eq!(hex_lower(&addr), "1563915e194d8cfba1943570603f7606a3115508");
    }

    #[test]
    fn tampered_credential_recovers_wrong_address() {
        // Flipping a JCS byte changes the recovered signer — tamper-evident.
        let jcs = r#"{"agent_pubkey":"A081W9y3zAr3KO88zrlhXZBoS7Wyyl-FmrDwtwQHWHGq","contract":"adn-processor","functions":["delegate-task","process-data"],"metadata":{"role":"adn-worker"},"not_after_secs":"1700000300","not_before_secs":"1700000000","org_did":"did:t3n:abc","scopes":[],"user_did":"did:t3n:abc","v":"ot3.delegation/1","vc_id":"AQIDBAUGBwgJCgsMDQ4PEB"}"#; // vc_id last char A->B
        let user_sig = unhex("987640f3ff30a199f78c0e8b2a8af738770da0b2243e35752458e0a0c2857a503c05442f41d4f75294a52d83c39cc6cdbd7ef1a2de8a25352e81c400414f5f721b");
        let addr = recover_eip191_address(jcs.as_bytes(), &user_sig).unwrap();
        assert_ne!(hex_lower(&addr), "1563915e194d8cfba1943570603f7606a3115508");
    }
}