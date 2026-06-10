"""
Agent Identity Management for Terminal 3 Agent Delegation Network
Builds on the existing terminal3_agent_auth_adapter to provide
multi-agent identity management capabilities.
"""

import os
import secrets
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.terminal3_agent_auth_adapter import (
    sign_action_request,
    verify_action_request,
    _load_private_key,
    key_fingerprint,
    _is_mock,
    _sha256,
    _canonical,
)
from src.terminal3_api_client import get_configured_did, get_t3n_api_key


class AgentIdentity:
    """
    Represents an agent's identity in the Terminal 3 network.

    Two construction modes:
    - No private_key_hex → loads from T3N_API_KEY env var (primary/coordinator agent)
    - private_key_hex provided → ephemeral identity (worker/validator agents)

    Each agent has a distinct key pair, agent_id (fingerprint), and DID so that
    multi-agent delegation is cryptographically distinct, not a single-key illusion.
    """

    def __init__(self, agent_name: str = None, private_key_hex: Optional[str] = None):
        self.agent_name = agent_name or f"agent-{os.getpid()}"
        self._private_key_hex = private_key_hex
        self._private_key_obj = None
        self._did = None
        self._agent_id = None
        self._public_key_hex = None
        self._load_identity()

    def _load_identity(self):
        if self._private_key_hex:
            # Ephemeral sub-agent — short-lived identity bound to coordinator's T3N session.
            # Uses did:key: (W3C standard for key-based DIDs) to signal that authority derives
            # from the cryptographic key, not a registered T3N tenant.
            key_bytes = bytes.fromhex(self._private_key_hex)
            priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            pub_hex = pub_bytes.hex()
            agent_id = key_fingerprint(pub_hex)
            self._private_key_obj = priv
            self._public_key_hex = pub_hex
            self._agent_id = agent_id
            self._did = f"did:key:ed25519:{agent_id}"
            self._authority = "ED25519_EPHEMERAL"
            return

        try:
            priv, pub_key_hex, agent_id, did = _load_private_key()
            self._private_key_obj = priv
            self._public_key_hex = pub_key_hex
            self._agent_id = agent_id
            self._did = did
            self._authority = "T3N_SESSION"  # DID came from authenticated T3N handshake
        except Exception as e:
            if _is_mock():
                mock_pub = "aabbcc" + "0" * 58
                self._private_key_obj = None
                self._public_key_hex = mock_pub
                self._agent_id = key_fingerprint(mock_pub)
                self._did = "did:t3n:mock-agent"
                self._authority = "MOCK"
            else:
                raise RuntimeError(f"Failed to load agent identity: {e}")

    @classmethod
    def ephemeral(cls, agent_name: str = None) -> "AgentIdentity":
        """Create an agent with a freshly generated Ed25519 key pair."""
        return cls(agent_name=agent_name, private_key_hex=secrets.token_hex(32))

    @property
    def did(self) -> str:
        return self._did

    @property
    def authority(self) -> str:
        return getattr(self, "_authority", "UNKNOWN")

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    def sign_action(self, action: str, nonce: str, data: dict = None) -> Dict:
        """Sign an action request with this agent's key, binding optional data hash."""
        if self._private_key_obj is None:
            # Mock mode fallback
            return sign_action_request(action, nonce, data=data)
        return sign_action_request(
            action,
            nonce,
            data=data,
            _private_key=self._private_key_obj,
            _pub_hex=self._public_key_hex,
            _agent_id=self._agent_id,
            _did=self._did,
        )

    def verify_action(self, proof: Dict, expected_action: str) -> Tuple[bool, str]:
        return verify_action_request(proof, expected_action)

    def to_dict(self) -> Dict:
        return {
            "agent_name": self.agent_name,
            "did": self.did,
            "authority": self.authority,
            "agent_id": self.agent_id,
            "public_key_hex": self.public_key_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AgentIdentity":
        identity = cls(data.get("agent_name"))
        return identity


def create_agent_identity(agent_name: str = None, private_key_hex: Optional[str] = None) -> AgentIdentity:
    return AgentIdentity(agent_name, private_key_hex=private_key_hex)


class AgentRoles:
    COORDINATOR = "coordinator"
    WORKER = "worker"
    VALIDATOR = "validator"
    AUDITOR = "auditor"
    DATA_PROCESSOR = "data_processor"
