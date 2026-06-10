import os
import json
import hashlib
import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.terminal3_api_client import get_configured_did, get_t3n_api_key

ADAPTER_AUTHORITY = "ED25519_LOCAL"   # coordinator: T3N_SESSION  workers: ED25519_EPHEMERAL
AUDIENCE = "t3n-adn-v1"
PROOF_TTL_SECONDS = 300
MOCK_AGENT_ID = "mock-agent-001"
MOCK_PUBLIC_KEY_HEX = "aabbcc" + "0" * 58  # 64 hex chars = 32 bytes


def key_fingerprint(raw_key_hex: str) -> str:
    """sha256('terminal3\x00' + key_bytes)[:12] — never the raw key."""
    return hashlib.sha256(b"terminal3\x00" + bytes.fromhex(raw_key_hex)).hexdigest()[:12]


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _is_mock() -> bool:
    return os.getenv("T3_MOCK", "false").lower() == "true"


def _load_private_key() -> tuple:
    """Returns (Ed25519PrivateKey, pub_key_hex, agent_id, did) or raises."""
    raw = get_t3n_api_key()
    if not raw:
        raise ValueError("T3N_API_KEY not set")
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 64:
        raise ValueError("T3N_API_KEY must be 32 bytes (64 hex chars) after 0x")
    key_bytes = bytes.fromhex(raw)
    priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_hex = pub_bytes.hex()
    agent_id = key_fingerprint(pub_hex)
    did = get_configured_did()
    return priv, pub_hex, agent_id, did


def sign_action_request(
    action: str,
    nonce: str,
    data: dict = None,
    _private_key=None,
    _pub_hex: str = None,
    _agent_id: str = None,
    _did: str = None,
) -> dict:
    """
    Build and sign a payload binding agent identity + action + nonce + audience.

    If `data` is provided, its canonical SHA-256 hash is included in the signed
    payload as `data_hash`, so any post-signing mutation to the data is detectable.

    The private-key override parameters (_private_key/_pub_hex/_agent_id/_did)
    allow ephemeral per-agent signing without env-var loading.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(seconds=PROOF_TTL_SECONDS)
    data_hash = _sha256(_canonical(data)) if data is not None else None

    if _is_mock():
        payload = {
            "agent_id": MOCK_AGENT_ID,
            "did": get_configured_did() or "did:t3n:mock-agent",
            "public_key_hex": MOCK_PUBLIC_KEY_HEX,
            "action": action,
            "nonce": nonce,
            "issued_at": now.isoformat(),
            "expires_at": expires.isoformat(),
            "audience": AUDIENCE,
        }
        if data_hash is not None:
            payload["data_hash"] = data_hash
        payload_hash = _sha256(_canonical(payload))
        return {
            **payload,
            "payload_hash": payload_hash,
            "signature_hex": "deadbeef" + "0" * 120,
        }

    if _private_key is not None:
        priv, pub_hex, agent_id, did = _private_key, _pub_hex, _agent_id, _did
    else:
        priv, pub_hex, agent_id, did = _load_private_key()

    payload = {
        "agent_id": agent_id,
        "did": did,
        "public_key_hex": pub_hex,
        "action": action,
        "nonce": nonce,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "audience": AUDIENCE,
    }
    if data_hash is not None:
        payload["data_hash"] = data_hash
    payload_hash = _sha256(_canonical(payload))
    signature = priv.sign(payload_hash.encode())
    return {
        **payload,
        "payload_hash": payload_hash,
        "signature_hex": signature.hex(),
    }


def verify_action_request(proof: dict, expected_action: str) -> tuple[bool, str]:
    """
    Verify a signed action request.
    Checks: required fields, action match, audience, expiry, agent_id=fingerprint(pubkey),
    payload hash integrity, Ed25519 signature.
    Mock mode: skips Ed25519 and fingerprint checks but still validates structure.
    """
    required = [
        "agent_id", "did", "public_key_hex", "action", "nonce",
        "issued_at", "expires_at", "audience", "signature_hex", "payload_hash",
    ]
    for field in required:
        if field not in proof:
            return (False, "IDENTITY_MISSING")

    if proof["action"] != expected_action:
        return (False, "IDENTITY_INVALID")

    if proof["audience"] != AUDIENCE:
        return (False, "IDENTITY_INVALID")

    try:
        expires = datetime.datetime.fromisoformat(proof["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        if now > expires:
            return (False, "PROOF_EXPIRED")
    except ValueError:
        return (False, "IDENTITY_INVALID")

    # Reconstruct payload exactly as sign_action_request built it (excludes payload_hash + sig)
    _PAYLOAD_KEYS = ["agent_id", "did", "public_key_hex", "action", "nonce", "issued_at", "expires_at", "audience"]
    if "data_hash" in proof:
        _PAYLOAD_KEYS = _PAYLOAD_KEYS + ["data_hash"]
    payload_fields = {k: proof[k] for k in _PAYLOAD_KEYS}
    expected_hash = _sha256(_canonical(payload_fields))
    if proof["payload_hash"] != expected_hash:
        return (False, "IDENTITY_INVALID")

    if _is_mock():
        return (True, "")

    # Live: verify agent_id == fingerprint(public_key)
    try:
        pub_key_hex = proof["public_key_hex"]
        if len(bytes.fromhex(pub_key_hex)) != 32:
            return (False, "IDENTITY_INVALID")
        expected_fp = key_fingerprint(pub_key_hex)
        if proof["agent_id"] != expected_fp:
            return (False, "IDENTITY_INVALID")
    except ValueError:
        return (False, "IDENTITY_INVALID")

    # Live: Ed25519 signature over payload_hash
    try:
        pub_bytes = bytes.fromhex(proof["public_key_hex"])
        sig_bytes = bytes.fromhex(proof["signature_hex"])
        if len(sig_bytes) != 64:
            return (False, "IDENTITY_INVALID")
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, proof["payload_hash"].encode())
        return (True, "")
    except Exception:
        return (False, "IDENTITY_INVALID")
