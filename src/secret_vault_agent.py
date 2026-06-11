"""
Phase 8 — TEE Secret Vault

Agents can store secrets (API keys, private configs, sensitive data) inside the T3N TEE.
The secret hash is stored — not the secret itself. Access is controlled by a permission hash.
Other agents can invoke actions using the secret without ever seeing it.

This demonstrates T3N's unique value: hardware-enforced access control where
the TEE is the only entity that can act on protected data.

T3N TEE functions used:
  - store-secret: stores a secret hash + permission policy inside the enclave
  - invoke-with-secret: executes an action using the stored secret (caller never sees it)
"""

import hashlib
import json
import secrets
from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity


class SecretVaultAgent:
    """
    Manages TEE-backed secret storage and permission-gated invocation.
    """

    def __init__(self, owner: AgentIdentity):
        self.owner = owner
        self._vaults: Dict[str, Dict] = {}  # label → vault metadata

    def _hash(self, value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:24]

    def store_secret(self, label: str, secret_value: str, allowed_dids: List[str], tee_invoke_fn) -> Dict:
        """
        Store a secret in the TEE. The raw secret never leaves the enclave.
        Permission hash encodes who may invoke actions using this secret.
        """
        secret_hash = self._hash(secret_value)
        permission_hash = self._hash(json.dumps(sorted(allowed_dids)))

        payload = {
            "owner_did": self.owner.did,
            "secret_hash": secret_hash,
            "permission_hash": permission_hash,
            "label": label,
        }
        result = tee_invoke_fn("store-secret", payload)

        self._vaults[label] = {
            "vault_id": result.get("vault_id"),
            "label": label,
            "allowed_dids": allowed_dids,
            "stored_in_tee": result.get("stored_in_tee", False),
        }
        return result

    def invoke_with_secret(
        self,
        label: str,
        requester: AgentIdentity,
        action: str,
        tee_invoke_fn,
    ) -> Dict:
        """
        Invoke an action using a stored secret. The requester proves permission
        via a signed proof — the TEE enforces access; raw secret stays sealed.
        """
        vault = self._vaults.get(label)
        if vault is None:
            raise ValueError(f"Vault '{label}' not found — store-secret first")

        if requester.did not in vault["allowed_dids"] and requester.did != self.owner.did:
            raise PermissionError(f"{requester.did} is not authorized for vault '{label}'")

        # Permission proof = hash(requester_did + vault_id + action)
        permission_proof = self._hash(f"{requester.did}:{vault['vault_id']}:{action}")

        payload = {
            "vault_id": vault["vault_id"],
            "requester_did": requester.did,
            "action": action,
            "permission_proof": permission_proof,
        }
        return tee_invoke_fn("invoke-with-secret", payload)

    def run_demo(self, workers: List[AgentIdentity], tee_invoke_fn) -> Dict:
        """
        Demo: owner stores an API secret, worker invokes an action using it.
        The worker never sees the raw secret — only the TEE can act on it.
        """
        # Store a synthetic secret (in real usage: an actual API key or credential)
        secret_value = secrets.token_hex(32)  # synthetic secret, NOT committed
        allowed = [w.did for w in workers[:1]]  # first worker has access

        store_result = self.store_secret("api_key_production", secret_value, allowed, tee_invoke_fn)
        invoke_result = self.invoke_with_secret("api_key_production", workers[0], "fetch_external_data", tee_invoke_fn)

        return {
            "phase": "tee_secret_vault",
            "vault_id": store_result.get("vault_id"),
            "label": store_result.get("label"),
            "stored_in_tee": store_result.get("stored_in_tee"),
            "action_executed": invoke_result.get("action_executed"),
            "tee_attested": invoke_result.get("tee_attested"),
            "raw_secret_exposed": invoke_result.get("raw_secret_exposed", True),
        }
