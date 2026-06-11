"""
Phase 5 — Temporal Agent Delegation

The coordinator issues time-bounded grants to workers inside the T3N TEE.
Each grant is cryptographically bound to: grantee DID, permitted action, and expiry epoch.
Workers prove they hold a valid grant before executing privileged actions.

This demonstrates T3N's capability as a time-locked access control system —
grants expire automatically, no revocation infrastructure needed.

T3N TEE functions used:
  - issue-time-grant: issues a time-bounded grant token inside the enclave
  - check-grant: verifies a grant is still valid against the current epoch
"""

import time
from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity


class TemporalDelegation:
    """
    Manages time-bounded delegation grants issued and verified via the T3N TEE.
    """

    def __init__(self, coordinator: AgentIdentity):
        self.coordinator = coordinator
        self._grants: Dict[str, Dict] = {}  # grant_token → grant metadata

    def issue_grant(
        self,
        grantee: AgentIdentity,
        action: str,
        duration_seconds: int,
        tee_invoke_fn,
    ) -> Dict:
        """
        Issue a time-bounded grant to a worker agent.
        The TEE seals the grant — only it can verify expiry.
        """
        current_epoch = int(time.time())
        valid_until = current_epoch + duration_seconds
        issuer_nonce = f"{self.coordinator.agent_id}:{current_epoch}"

        payload = {
            "grantee_did": grantee.did,
            "action": action,
            "valid_until_epoch": valid_until,
            "issuer_nonce": issuer_nonce,
        }
        result = tee_invoke_fn("issue-time-grant", payload)

        token = result.get("grant_token", "")
        self._grants[token] = {
            "grantee_did": grantee.did,
            "action": action,
            "valid_until_epoch": valid_until,
            "grant_token": token,
            "issued_in_tee": result.get("issued_in_tee", False),
        }
        return result

    def check_grant(self, grant_token: str, grantee: AgentIdentity, action: str, tee_invoke_fn) -> Dict:
        """
        Worker proves they hold a valid grant before executing a privileged action.
        TEE verifies expiry without needing a separate revocation mechanism.
        """
        grant = self._grants.get(grant_token, {})
        current_epoch = int(time.time())

        payload = {
            "grant_token": grant_token,
            "grantee_did": grantee.did,
            "action": action,
            "valid_until_epoch": grant.get("valid_until_epoch", 0),
            "current_epoch": current_epoch,
        }
        return tee_invoke_fn("check-grant", payload)

    def run_demo(self, workers: List[AgentIdentity], tee_invoke_fn) -> Dict:
        """
        Demo: issue a short-lived grant to a worker, verify it's valid.
        Then simulate an expired grant and verify it's rejected.
        """
        worker = workers[0]

        # Grant 1: valid for 300 seconds
        grant_result = self.issue_grant(worker, "process_premium_data", 300, tee_invoke_fn)
        token = grant_result.get("grant_token", "")
        check_valid = self.check_grant(token, worker, "process_premium_data", tee_invoke_fn)

        # Grant 2: simulate expired (issued with -600s deadline)
        expired_payload = {
            "grant_token": "tgrant-expired-test",
            "grantee_did": worker.did,
            "action": "process_premium_data",
            "valid_until_epoch": int(time.time()) - 600,  # already expired
            "current_epoch": int(time.time()),
        }
        check_expired = tee_invoke_fn("check-grant", expired_payload)

        return {
            "phase": "temporal_delegation",
            "grant_token": token[:20] + "...",
            "grantee_did": worker.did,
            "valid_grant_check": check_valid.get("valid"),
            "valid_grant_reason": check_valid.get("reason"),
            "expired_grant_check": check_expired.get("valid"),
            "expired_grant_reason": check_expired.get("reason"),
            "checked_in_tee": check_valid.get("checked_in_tee", False),
        }
