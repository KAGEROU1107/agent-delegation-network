"""
Delegation Protocol for Terminal 3 Agent Delegation Network
Defines the structure and workflow for secure agent-to-agent delegation.
"""

import json
import uuid
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from src.agent_identity import AgentIdentity, create_agent_identity
from src.replay_ledger import (
    REQUEST_STATE_COMPLETED,
    REQUEST_STATE_RETRYABLE_FAILURE,
    begin_request_execution,
    finalize_request_execution,
    heartbeat_request_execution,
)
from src.terminal3_agent_auth_adapter import _canonical, _sha256, sign_action_request, verify_action_request
from src.tee_authorization import receipt_fingerprint


class DelegationAction(Enum):
    """Standard actions in the delegation protocol."""
    DELEGATE_TASK = "DELEGATE_TASK"
    TASK_RESULT = "TASK_RESULT"
    TASK_FAILED = "TASK_FAILED"
    QUERY_AGENT = "QUERY_AGENT"
    AGENT_INFO = "AGENT_INFO"
    REVOKE_DELEGATION = "REVOKE_DELEGATION"


class DelegationStatus(Enum):
    """Status of a delegation request."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REVOKED = "REVOKED"


@dataclass
class DelegationRequest:
    """
    A delegation request from one agent to another.
    This gets signed and sent as an action request.
    """
    # Request metadata - all required first
    delegation_id: str
    from_agent_id: str
    to_agent_id: str
    action: str  # The task action to perform (e.g., "PROCESS_DATA", "ANALYZE_REPORT")
    task_description: str
    parameters: Dict[str, Any]
    nonce: str
    
    # Security/context - then the ones with defaults
    deadline: Optional[float] = None  # Unix timestamp
    issued_at: float = 0.0  # Unix timestamp
    expires_at: float = 0.0  # Unix timestamp
    tee_authorization: Optional[Dict[str, Any]] = None
    
    # Optional: delegator can specify required capabilities
    required_capabilities: List[str] = None
    
    def __post_init__(self):
        if self.required_capabilities is None:
            self.required_capabilities = []
        # Set timestamps if not provided
        if self.issued_at == 0.0:
            self.issued_at = time.time()
        if self.expires_at == 0.0:
            self.expires_at = self.issued_at + 3600  # Default 1 hour expiration
    
    def to_action_request(self, agent_identity: AgentIdentity) -> Dict:
        """
        Convert this delegation request to a signed action request.
        
        Args:
            agent_identity: The identity of the agent making this request
            
        Returns:
            Signed action request ready to send to the governed action gate
        """
        # Build the payload that matches what sign_action_request expects
        payload = {
            "delegation_id": self.delegation_id,
            "from_agent_id": self.from_agent_id,
            "to_agent_id": self.to_agent_id,
            "action": self.action,
            "task_description": self.task_description,
            "parameters": self.parameters,
            "deadline": self.deadline,
            "required_capabilities": self.required_capabilities,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            # Note: We don't include the signature here - that's added by sign_action_request
            # The action type for the gate will be "DELEGATE_TASK"
        }
        if self.tee_authorization is not None:
            payload["tee_authorization"] = self.tee_authorization
        
        # Sign with the delegating agent's own key, binding the delegation payload hash.
        # data_hash is included INSIDE the signed fields so any post-signing tampering
        # to delegation_data is detected by verify_action_request.
        signed = agent_identity.sign_action("DELEGATE_TASK", self.nonce, data=payload)

        return {
            **signed,
            "delegation_data": payload,
        }
    
    @classmethod
    def from_action_request(cls, signed_request: Dict) -> 'DelegationRequest':
        """
        Reconstruct a delegation request from a signed action request.
        
        Args:
            signed_request: The signed action request received from another agent
            
        Returns:
            DelegationRequest instance
        """
        # Extract the delegation data from the signed request
        delegation_data = signed_request.get("delegation_data", {})
        
        # issued_at / expires_at come from delegation_data (Unix floats),
        # not from the signed envelope (which uses ISO strings).
        return cls(
            delegation_id=delegation_data.get("delegation_id", ""),
            from_agent_id=delegation_data.get("from_agent_id", ""),
            to_agent_id=delegation_data.get("to_agent_id", ""),
            action=delegation_data.get("action", ""),
            task_description=delegation_data.get("task_description", ""),
            parameters=delegation_data.get("parameters", {}),
            deadline=delegation_data.get("deadline"),
            required_capabilities=delegation_data.get("required_capabilities", []),
            nonce=delegation_data.get("nonce", signed_request.get("nonce", "")),
            issued_at=delegation_data.get("issued_at", 0.0),
            expires_at=delegation_data.get("expires_at", 0.0),
            tee_authorization=delegation_data.get("tee_authorization")
        )
    
    def is_expired(self) -> bool:
        """Check if this delegation request has expired."""
        return time.time() > self.expires_at
    
    def time_until_deadline(self) -> Optional[float]:
        """Get seconds until deadline (None if no deadline)."""
        if self.deadline is None:
            return None
        return max(0, self.deadline - time.time())


@dataclass
class DelegationResult:
    """
    Result of a delegated task.
    This gets signed and returned to the delegating agent.
    """
    delegation_id: str
    from_agent_id: str  # The agent that performed the task
    to_agent_id: str    # The agent that requested the task
    status: DelegationStatus
    result: Any = None
    error: str = None
    nonce: str = None
    issued_at: float = None
    tee_authorization: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.issued_at is None:
            self.issued_at = time.time()
        if self.nonce is None:
            self.nonce = str(uuid.uuid4())
    
    def to_action_request(self, agent_identity: AgentIdentity) -> Dict:
        """
        Convert this delegation result to a signed action request.
        
        Args:
            agent_identity: The identity of the agent sending this result
            
        Returns:
            Signed action request
        """
        payload = {
            "delegation_id": self.delegation_id,
            "from_agent_id": self.from_agent_id,
            "to_agent_id": self.to_agent_id,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
        }
        if self.tee_authorization is not None:
            payload["tee_authorization"] = self.tee_authorization
        # Sign with the performing agent's own key; bind result_data hash so
        # the result payload cannot be tampered with after signing.
        signed = agent_identity.sign_action("TASK_RESULT", self.nonce, data=payload)
        return {
            **signed,
            "result_data": payload,
        }
    
    @classmethod
    def from_action_request(cls, signed_request: Dict) -> 'DelegationResult':
        """
        Reconstruct a delegation result from a signed action request.
        """
        result_data = signed_request.get("result_data", {})
        
        return cls(
            delegation_id=result_data.get("delegation_id", ""),
            from_agent_id=result_data.get("from_agent_id", ""),
            to_agent_id=result_data.get("to_agent_id", ""),
            status=DelegationStatus(result_data.get("status", DelegationStatus.FAILED.value)),
            result=result_data.get("result"),
            error=result_data.get("error"),
            nonce=result_data.get("nonce"),
            issued_at=result_data.get("issued_at", 0.0),
            tee_authorization=result_data.get("tee_authorization")
        )


class DelegationProtocol:
    """
    Handles the delegation protocol logic for agents.
    """
    
    @staticmethod
    def create_delegation_request(
        from_agent: AgentIdentity,
        to_agent_id: str,
        action: str,
        task_description: str,
        parameters: Dict = None,
        deadline: float = None,
        required_capabilities: List[str] = None,
        tee_authorization: Optional[Dict[str, Any]] = None
    ) -> DelegationRequest:
        """
        Create a new delegation request.
        
        Args:
            from_agent: The agent making the request
            to_agent_id: The target agent's ID
            action: The action to perform
            task_description: Human-readable description
            parameters: Task parameters
            deadline: Unix timestamp for deadline
            required_capabilities: Required capabilities for the target agent
            
        Returns:
            DelegationRequest instance
        """
        if parameters is None:
            parameters = {}
        
        delegation_id = (
            str(tee_authorization.get("delegation_id"))
            if tee_authorization and tee_authorization.get("delegation_id")
            else str(uuid.uuid4())
        )
        nonce = str(uuid.uuid4())
        now = time.time()
        expires_at = now + 3600  # Default 1 hour expiration
        
        return DelegationRequest(
            delegation_id=delegation_id,
            from_agent_id=from_agent.agent_id,
            to_agent_id=to_agent_id,
            action=action,
            task_description=task_description,
            parameters=parameters,
            deadline=deadline,
            required_capabilities=required_capabilities or [],
            nonce=nonce,
            issued_at=now,
            expires_at=expires_at,
            tee_authorization=tee_authorization
        )
    
    @staticmethod
    def validate_delegation_request(
        signed_request: Dict,
        receiver_agent_id: str,
        expected_gateway_public_key_hex: str,
        expected_gateway_key_id: str,
        expected_build_config_id: str,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Validate a signed delegation request received over the wire.

        Args:
            signed_request: The raw signed dict from to_action_request()
            receiver_agent_id: The agent_id of the agent receiving this request

        Returns:
            Tuple of (is_valid, error_message)
        """
        from src.terminal3_agent_auth_adapter import verify_action_request, _sha256, _canonical
        from src.tee_authorization import verify_tee_authorization_receipt

        # Step 1: Ed25519 signature + payload-hash integrity
        is_valid, err = verify_action_request(signed_request, "DELEGATE_TASK")
        if not is_valid:
            return False, f"Signature verification failed: {err}", None

        if not expected_gateway_public_key_hex:
            return False, "Expected gateway public key is required", None
        if not expected_gateway_key_id:
            return False, "Expected gateway key id is required", None
        if not expected_build_config_id:
            return False, "Expected build_config_id is required", None

        # Step 2: Verify delegation_data wasn't tampered with after signing.
        # data_hash (inside the signed fields) must match SHA-256 of actual delegation_data.
        if "data_hash" in signed_request:
            delegation_data = signed_request.get("delegation_data", {})
            expected_data_hash = _sha256(_canonical(delegation_data))
            if signed_request["data_hash"] != expected_data_hash:
                return False, "DELEGATION_DATA_TAMPERED: payload hash mismatch", None

        request = DelegationRequest.from_action_request(signed_request)

        if request.is_expired():
            return False, "Delegation request has expired", None

        if request.to_agent_id != receiver_agent_id:
            return False, (
                f"Delegation not addressed to this agent "
                f"(expected {receiver_agent_id}, got {request.to_agent_id})"
            ), None

        if not request.tee_authorization:
            return False, "TEE authorization receipt required before worker execution", None
        try:
            verify_tee_authorization_receipt(
                request.tee_authorization,
                expected_gateway_pubkey_hex=expected_gateway_public_key_hex,
                expected_gateway_key_id=expected_gateway_key_id,
                expected_delegation_id=request.delegation_id,
                expected_to_agent_id=receiver_agent_id,
                expected_action=request.action,
                expected_parameters=request.parameters,
                expected_build_config_id=expected_build_config_id,
            )
        except RuntimeError as exc:
            return False, f"TEE authorization invalid: {exc}", None

        request_hash = signed_request.get("data_hash") or _sha256(_canonical(signed_request.get("delegation_data", {})))
        replay_key = _sha256(_canonical({
            "delegation_id": request.delegation_id,
            "request_hash": request_hash,
            "gateway_receipt_fingerprint": receipt_fingerprint(request.tee_authorization),
        }))
        if not replay_key:
            return False, "Delegation request replay key missing", None

        return True, "Delegation request is valid", replay_key

    @staticmethod
    def begin_delegation_request_execution(
        replay_key: str,
        replay_expires_at: float,
        owner_agent_id: str = "",
        delegation_id: str = "",
        payload_fingerprint: str = "",
        integrity_secret_hex: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        return begin_request_execution(
            replay_key=replay_key,
            replay_expires_at=replay_expires_at,
            owner_agent_id=owner_agent_id,
            delegation_id=delegation_id,
            payload_fingerprint=payload_fingerprint,
            integrity_secret_hex=integrity_secret_hex,
        )

    @staticmethod
    def heartbeat_delegation_request_execution(
        replay_key: str,
        integrity_secret_hex: Optional[str] = None,
        execution_token: Optional[str] = None,
    ) -> bool:
        return heartbeat_request_execution(replay_key, integrity_secret_hex, execution_token)

    @staticmethod
    def finalize_delegation_request_execution(
        replay_key: str,
        state: str,
        integrity_secret_hex: Optional[str] = None,
        error: Optional[str] = None,
        execution_token: Optional[str] = None,
    ) -> bool:
        if state not in {REQUEST_STATE_COMPLETED, REQUEST_STATE_RETRYABLE_FAILURE}:
            raise ValueError(f"Unsupported replay state: {state}")
        return finalize_request_execution(
            replay_key=replay_key,
            final_state=state,
            integrity_secret_hex=integrity_secret_hex,
            last_error=error,
            execution_token=execution_token,
        )
    
    @staticmethod
    def create_delegation_result(
        delegation_request: DelegationRequest,
        performing_agent: AgentIdentity,
        status: DelegationStatus,
        result: Any = None,
        error: str = None
    ) -> DelegationResult:
        """
        Create a delegation result from a request.
        
        Args:
            delegation_request: The original request
            performing_agent: The agent that performed the task
            status: The status of the task
            result: The task result (if successful)
            error: Error message (if failed)
            
        Returns:
            DelegationResult instance
        """
        return DelegationResult(
            delegation_id=delegation_request.delegation_id,
            from_agent_id=performing_agent.agent_id,
            to_agent_id=delegation_request.from_agent_id,
            status=status,
            result=result,
            error=error,
            tee_authorization=delegation_request.tee_authorization
        )


def delegate_task(
    from_agent: AgentIdentity,
    to_agent_id: str,
    action: str,
    task_description: str,
    parameters: Dict = None,
    deadline: float = None,
    tee_authorization: Optional[Dict[str, Any]] = None
) -> DelegationRequest:
    """
    Convenience function to create a delegation request.
    
    Args:
        from_agent: The agent making the request
        to_agent_id: The target agent's ID
        action: The action to perform
        task_description: Human-readable description
        parameters: Task parameters
        deadline: Unix timestamp for deadline
        
    Returns:
        DelegationRequest ready to be sent
    """
    return DelegationProtocol.create_delegation_request(
        from_agent=from_agent,
        to_agent_id=to_agent_id,
        action=action,
        task_description=task_description,
        parameters=parameters,
        deadline=deadline,
        tee_authorization=tee_authorization
    )


# Example usage patterns
class DelegationPatterns:
    """Common delegation patterns in agent networks."""
    
    @staticmethod
    def data_processing_pipeline() -> List[Dict]:
        """Define a data processing pipeline delegation pattern."""
        return [
            {
                "step": "extract",
                "action": "EXTRACT_DATA",
                "description": "Extract raw data from source"
            },
            {
                "step": "transform", 
                "action": "TRANSFORM_DATA",
                "description": "Transform data to target format"
            },
            {
                "step": "validate",
                "action": "VALIDATE_DATA", 
                "description": "Validate transformed data"
            },
            {
                "step": "load",
                "action": "LOAD_DATA",
                "description": "Load data into target system"
            }
        ]
    
    @staticmethod
    def approval_workflow() -> List[Dict]:
        """Define an approval workflow delegation pattern."""
        return [
            {
                "step": "submit",
                "action": "SUBMIT_FOR_REVIEW",
                "description": "Submit item for review"
            },
            {
                "step": "review",
                "action": "REVIEW_ITEM",
                "description": "Review submitted item"
            },
            {
                "step": "approve",
                "action": "APPROVE_ITEM",
                "description": "Approve or reject item"
            }
        ]
