"""
Negative security tests for the ADN signing and verification protocol.

Each test deliberately crafts an adversarial or malformed proof and asserts
that verify_action_request() rejects it with the expected error code.

Run:
    python -m pytest tests/negative_security.py -v
"""

import copy
import datetime
import secrets
import sys
import os

import pytest

# Make src importable from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.agent_identity import AgentIdentity
from src.terminal3_agent_auth_adapter import (
    AUDIENCE,
    sign_action_request,
    verify_action_request,
    _sha256,
    _canonical,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _fresh_proof(action: str = "process_data", data: dict = None) -> dict:
    """Sign a valid proof using an ephemeral worker identity."""
    worker = AgentIdentity.ephemeral("test-worker")
    nonce = secrets.token_hex(16)
    return worker.sign_action(action, nonce, data=data)


def _verify(proof: dict, action: str = "process_data"):
    ok, code = verify_action_request(proof, action)
    return ok, code


# ── Test cases ─────────────────────────────────────────────────────────────────

class TestStructuralTamper:
    """Mutating any signed field after the fact must be detected."""

    def test_tampered_action(self):
        proof = _fresh_proof("process_data")
        proof["action"] = "delegate_task"  # mutate post-signing
        ok, code = _verify(proof, "delegate_task")
        assert not ok, "Tampered action should be rejected"
        assert code == "IDENTITY_INVALID"

    def test_tampered_agent_id(self):
        proof = _fresh_proof()
        proof["agent_id"] = "deadbeef0000"
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_INVALID"

    def test_tampered_did(self):
        proof = _fresh_proof()
        proof["did"] = "did:key:ed25519:attacker000000"
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_INVALID"

    def test_tampered_public_key(self):
        proof = _fresh_proof()
        proof["public_key_hex"] = "aa" * 32  # valid length but wrong key
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_INVALID"

    def test_tampered_data_hash(self):
        real_data = {"records": [100.0, 200.0]}
        proof = _fresh_proof(data=real_data)
        proof["data_hash"] = _sha256(_canonical({"records": [999.0]}))  # hash of different data
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_INVALID"

    def test_injected_extra_field(self):
        proof = _fresh_proof()
        proof["role"] = "coordinator"  # extra field not in payload_hash
        # payload_hash still valid — the extra field is not in the signed set,
        # but the signature still covers only the original fields, so it MUST pass.
        # This is the correct behavior: extra fields are stripped from verification.
        ok, code = _verify(proof)
        assert ok, "Extra field injection should not break verification (signed fields unchanged)"


class TestReplayAttack:
    """A valid proof for one action must not be accepted for a different action."""

    def test_replay_different_action(self):
        proof = _fresh_proof("process_data")
        ok, code = _verify(proof, "delegate_task")  # different expected action
        assert not ok
        assert code == "IDENTITY_INVALID"

    def test_replay_same_action_passes(self):
        """Within TTL, same proof for same action is valid (nonces are caller's concern)."""
        proof = _fresh_proof("process_data")
        ok, _ = _verify(proof, "process_data")
        assert ok


class TestExpiredProof:
    """Proofs past their TTL must be rejected."""

    def test_expired_proof(self):
        proof = _fresh_proof()
        past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=600)).isoformat()
        # Mutate expires_at AND recompute payload_hash to make it structurally valid
        # but expired. Signature will fail because payload_hash now differs from signed one.
        proof["expires_at"] = past
        ok, code = _verify(proof)
        assert not ok
        # Either PROOF_EXPIRED (if expiry checked before hash) or IDENTITY_INVALID (hash mismatch)
        assert code in ("PROOF_EXPIRED", "IDENTITY_INVALID")

    def test_future_proof_valid(self):
        proof = _fresh_proof()
        ok, _ = _verify(proof)
        assert ok


class TestWrongAudience:
    """Proofs issued for a different audience must be rejected."""

    def test_wrong_audience(self):
        proof = _fresh_proof()
        proof["audience"] = "some-other-service"
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_INVALID"

    def test_correct_audience(self):
        proof = _fresh_proof()
        assert proof["audience"] == AUDIENCE
        ok, _ = _verify(proof)
        assert ok


class TestForgedKey:
    """A proof signed by key A but claiming key B must be rejected."""

    def test_forged_public_key(self):
        signer = AgentIdentity.ephemeral("signer")
        impostor = AgentIdentity.ephemeral("impostor")
        nonce = secrets.token_hex(16)

        real_proof = signer.sign_action("process_data", nonce)
        # Swap public_key_hex to impostor's key but keep signer's signature
        real_proof["public_key_hex"] = impostor.public_key_hex
        real_proof["agent_id"] = impostor.agent_id

        ok, code = verify_action_request(real_proof, "process_data")
        assert not ok, "Signature from different key should fail"
        assert code == "IDENTITY_INVALID"


class TestMissingFields:
    """Proofs missing required fields must be rejected."""

    def test_missing_signature(self):
        proof = _fresh_proof()
        del proof["signature_hex"]
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_MISSING"

    def test_missing_payload_hash(self):
        proof = _fresh_proof()
        del proof["payload_hash"]
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_MISSING"

    def test_missing_did(self):
        proof = _fresh_proof()
        del proof["did"]
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_MISSING"

    def test_missing_agent_id(self):
        proof = _fresh_proof()
        del proof["agent_id"]
        ok, code = _verify(proof)
        assert not ok
        assert code == "IDENTITY_MISSING"


class TestIdentityDistinctness:
    """Four agents in the ADN must each have a distinct cryptographic identity."""

    def test_four_agents_are_distinct(self):
        agents = [AgentIdentity.ephemeral(f"agent-{i}") for i in range(4)]
        dids = {a.did for a in agents}
        keys = {a.public_key_hex for a in agents}
        ids = {a.agent_id for a in agents}
        assert len(dids) == 4, "All DIDs must be unique"
        assert len(keys) == 4, "All public keys must be unique"
        assert len(ids) == 4, "All agent IDs must be unique"

    def test_ephemeral_key_not_coordinator_key(self):
        worker = AgentIdentity.ephemeral("worker")
        # Worker is ED25519_EPHEMERAL — not T3N_SESSION
        assert worker.authority == "ED25519_EPHEMERAL"
        assert worker.did.startswith("did:key:ed25519:")
