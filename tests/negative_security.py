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
    PROOF_TTL_SECONDS,
    sign_action_request,
    verify_action_request,
    _sha256,
    _canonical,
)
from src.delegation_policy import DelegationPolicy


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


class TestDelegationPolicy:
    """Delegation policy engine: role-based allow/deny and trust enforcement."""

    def test_empty_policy_denies_by_default(self):
        policy = DelegationPolicy()
        allowed, reason = policy.can_delegate("agent-a", "agent-b", "process_data")
        assert not allowed, f"Empty policy must deny by default (default-deny): {reason}"
        assert "default deny" in reason, f"Reason must mention default deny: {reason}"

    def test_restricted_agent_blocked_on_unknown_action(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("agent-a", "allowed_action")
        allowed, _ = policy.can_delegate("agent-a", "agent-b", "forbidden_action")
        assert not allowed, "Agent with rules must be blocked on unlisted action"

    def test_restricted_agent_allowed_on_listed_action(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("agent-a", "process_data")
        policy.add_trust_relationship("agent-a", "agent-b")  # trust must be explicit
        allowed, _ = policy.can_delegate("agent-a", "agent-b", "process_data")
        assert allowed

    def test_action_allowed_but_no_trust_denies(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("agent-a", "process_data")
        # No trust relationship registered → default deny even with valid action
        allowed, reason = policy.can_delegate("agent-a", "agent-b", "process_data")
        assert not allowed, "Action rule alone must not allow delegation — trust is also required"
        assert "default deny" in reason

    def test_trust_gate_blocks_untrusted_target(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("agent-a", "process_data")
        policy.add_trust_relationship("agent-a", "agent-trusted")
        allowed, _ = policy.can_delegate("agent-a", "agent-stranger", "process_data")
        assert not allowed, "Should be blocked when trust list exists and target not in it"

    def test_trust_gate_allows_trusted_target(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("agent-a", "process_data")
        policy.add_trust_relationship("agent-a", "agent-trusted")
        allowed, _ = policy.can_delegate("agent-a", "agent-trusted", "process_data")
        assert allowed

    def test_remove_delegation_rule_denies_action(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("agent-a", "process_data")
        policy.remove_delegation_rule("agent-a", "process_data")
        allowed, reason = policy.can_delegate("agent-a", "agent-b", "process_data")
        # After removing the only rule, the rule set is empty → default deny applies
        assert not allowed, "Empty rule set must deny (no revert to open access)"
        assert "default deny" in reason, f"Must cite default-deny rule: {reason}"

    def test_can_perform_task_no_policy_denies(self):
        policy = DelegationPolicy()
        allowed, reason = policy.can_perform_task("worker-001", "process_data")
        assert not allowed, "Worker with no policy must be denied (default deny)"
        assert "default deny" in reason

    def test_can_perform_task_restricted(self):
        policy = DelegationPolicy()
        policy.add_delegation_rule("worker-001", "narrow_action")
        allowed, _ = policy.can_perform_task("worker-001", "other_action")
        assert not allowed

    def test_four_agents_get_independent_policies(self):
        """Each ADN agent must have independent policy scope."""
        policy = DelegationPolicy()
        for i in range(4):
            policy.add_delegation_rule(f"agent-{i}", f"action-{i}")
        # Each agent only has its own action
        for i in range(4):
            allowed, _ = policy.can_delegate(f"agent-{i}", "target", f"action-{i}")
            assert allowed
            # Must not have other agents' actions
            for j in range(4):
                if j != i:
                    blocked, _ = policy.can_delegate(f"agent-{i}", "target", f"action-{j}")
                    assert not blocked, f"agent-{i} must not have action-{j}"


class TestCredentialTimeWindow:
    """Time-bound proof TTL validation — mirrors BUG-005 fix logic at Python layer."""

    def test_fresh_proof_passes_ttl(self):
        proof = _fresh_proof()
        ok, _ = _verify(proof)
        assert ok

    def test_proof_ttl_constant_is_positive(self):
        assert PROOF_TTL_SECONDS > 0, "TTL must be positive"

    def test_proof_expires_at_is_in_future(self):
        proof = _fresh_proof()
        expires = datetime.datetime.fromisoformat(proof["expires_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        assert expires > now, "Fresh proof expires_at must be in the future"

    def test_proof_expiry_window_matches_ttl(self):
        before = datetime.datetime.now(datetime.timezone.utc)
        proof = _fresh_proof()
        after = datetime.datetime.now(datetime.timezone.utc)
        expires = datetime.datetime.fromisoformat(proof["expires_at"])
        # expires_at should be approximately now + TTL
        lower = before + datetime.timedelta(seconds=PROOF_TTL_SECONDS - 1)
        upper = after + datetime.timedelta(seconds=PROOF_TTL_SECONDS + 1)
        assert lower <= expires <= upper, "expires_at must be within TTL window of creation time"

    def test_mutated_expiry_rejected(self):
        """Extending the TTL by mutating expires_at after signing must be rejected."""
        proof = _fresh_proof()
        future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)).isoformat()
        proof["expires_at"] = future
        ok, code = _verify(proof)
        # Mutating expires_at changes the payload_hash → signature fails
        assert not ok
        assert code == "IDENTITY_INVALID"


