"""
Agent Delegation Network (ADN) - Main Implementation
The core system that enables secure agent delegation using Terminal 3's Agent Auth SDK.
"""

import json
import os
import time
import uuid
import logging
import datetime
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from threading import Event, Lock, Thread

from src.agent_identity import AgentIdentity, create_agent_identity, AgentRoles
from src.delegation_protocol import (
    DelegationRequest, 
    DelegationResult, 
    DelegationProtocol,
    DelegationStatus
)
from src.delegation_policy import DelegationPolicyEngine, DelegationPolicy
from src.terminal3_agent_auth_adapter import sign_action_request, verify_action_request
from src.tee_authorization import receipt_fingerprint
from src.execution_receipt import build_receipt, verify_receipt
from src.replay_ledger import configured_integrity_key, derive_integrity_key


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _delegation_request_replay_expires_at(delegation_request: DelegationRequest) -> float:
    """Bound request replay retention to the shortest trusted authorization window."""
    expires_at = float(delegation_request.expires_at or time.time())
    receipt = delegation_request.tee_authorization or {}
    authorization_expires_at = receipt.get("authorization_expires_at")
    if authorization_expires_at:
        try:
            parsed = datetime.datetime.fromisoformat(str(authorization_expires_at))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            expires_at = min(expires_at, parsed.timestamp())
        except ValueError:
            pass
    return expires_at


def _request_replay_integrity_key(identity: AgentIdentity) -> Optional[str]:
    configured = configured_integrity_key("request")
    if configured:
        return configured
    return derive_integrity_key(identity.private_key_hex, "request")


def _runtime_requires_tee_authorization() -> bool:
    return os.environ.get("ADN_RUNTIME_MODE", "live").strip().lower() == "live"


def _gateway_context_configured(
    expected_gateway_public_key_hex: Optional[str],
    expected_gateway_key_id: Optional[str],
    expected_build_config_id: Optional[str],
) -> bool:
    return bool(expected_gateway_public_key_hex or expected_gateway_key_id or expected_build_config_id)


def _trusted_tee_authorization_requirement(
    require_tee_authorization: Optional[bool],
    expected_gateway_public_key_hex: Optional[str],
    expected_gateway_key_id: Optional[str],
    expected_build_config_id: Optional[str],
) -> bool:
    if _runtime_requires_tee_authorization() or _gateway_context_configured(
        expected_gateway_public_key_hex,
        expected_gateway_key_id,
        expected_build_config_id,
    ):
        return True
    if require_tee_authorization is not None:
        return bool(require_tee_authorization)
    return False


def _start_request_replay_heartbeat(
    replay_key: str,
    integrity_secret_hex: Optional[str],
    execution_token: Optional[str],
):
    stop_event = Event()

    def _loop():
        while not stop_event.wait(60.0):
            DelegationProtocol.heartbeat_delegation_request_execution(
                replay_key,
                integrity_secret_hex,
                execution_token,
            )

    thread = Thread(target=_loop, daemon=True)
    thread.start()
    return stop_event, thread


class AgentDelegationNetwork:
    """
    The Agent Delegation Network (ADN) enables secure, verifiable
    delegation of tasks between AI agents using Terminal 3's Agent Auth SDK.
    
    Key features:
    - Each agent has a verifiable identity (DID) via Terminal 3
    - Delegation requests are signed and verified
    - Policy engine governs what agents can delegate to whom
    - Execution receipts provide audit trail
    - Nonce replay protection prevents attacks
    """
    
    def __init__(
        self,
        agent_name: str = None,
        policy_file: Optional[Path] = None,
        private_key_hex: Optional[str] = None,
    ):
        """
        Initialize an agent in the delegation network.

        Args:
            agent_name: Optional name for this agent
            policy_file: Optional path to delegation policy configuration
            private_key_hex: 64-char hex Ed25519 private key for ephemeral agents.
                             If omitted, loads from T3N_API_KEY env var (primary agent).
        """
        self.agent_id = str(uuid.uuid4())[:8]
        self.agent_name = agent_name or f"adn-agent-{self.agent_id}"
        self.identity = create_agent_identity(self.agent_name, private_key_hex=private_key_hex)
        
        # Internal state
        self._delegations: Dict[str, DelegationRequest] = {}  # delegation_id -> request
        self._results: Dict[str, DelegationResult] = {}       # delegation_id -> result
        self._task_handlers: Dict[str, Callable] = {}         # action -> handler function
        self._delegation_log: List[Dict] = []                 # Audit trail
        
        # Concurrency safety
        self._lock = Lock()
        
        # Policy engine
        self.policy_engine = DelegationPolicyEngine()
        if policy_file:
            self.policy_engine.policy = DelegationPolicy(policy_file)
        
        # Register built-in task handlers
        self._register_builtin_handlers()
        
        logger.info(f"Agent Delegation Network initialized: {self.agent_name} ({self.identity.agent_id})")
    
    def _register_builtin_handlers(self):
        """Register built-in task handlers for common actions."""
        self._task_handlers.update({
            "ECHO": self._handle_echo,
            "GET_AGENT_INFO": self._handle_get_agent_info,
            "PING": self._handle_ping,
        })
    
    def _handle_echo(self, parameters: Dict) -> Any:
        """Echo handler - returns the input parameters."""
        return {
            "echo": parameters.get("message", ""),
            "timestamp": time.time(),
            "agent_id": self.identity.agent_id
        }
    
    def _handle_get_agent_info(self, parameters: Dict) -> Dict:
        """Return information about this agent."""
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "did": self.identity.did,
            "public_key_hex": self.identity.public_key_hex,
            "available_handlers": list(self._task_handlers.keys()),
            "policy_info": self.policy_engine.policy.get_agent_info(self.identity.agent_id)
        }
    
    def _handle_ping(self, parameters: Dict) -> Dict:
        """Simple ping handler for connectivity testing."""
        return {
            "pong": True,
            "timestamp": time.time(),
            "agent_id": self.identity.agent_id
        }
    
    def register_task_handler(self, action: str, handler: Callable[[Dict], Any]):
        """
        Register a custom task handler for a specific action.
        
        Args:
            action: The action name (e.g., "PROCESS_DATA", "ANALYZE_REPORT")
            handler: Function that takes parameters and returns result
        """
        self._task_handlers[action] = handler
        logger.info(f"Registered task handler for action: {action}")
    
    def unregister_task_handler(self, action: str):
        """Unregister a task handler."""
        if action in self._task_handlers:
            del self._task_handlers[action]
            logger.info(f"Unregistered task handler for action: {action}")
    
    def delegate_task(
        self,
        to_agent_id: str,
        action: str,
        task_description: str,
        parameters: Dict = None,
        deadline: float = None,
        required_capabilities: List[str] = None,
        tee_authorization: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Delegate a task to another agent in the network.
        
        Args:
            to_agent_id: The target agent's ID
            action: The action to perform
            task_description: Human-readable description of the task
            parameters: Task parameters
            deadline: Unix timestamp for task deadline
            required_capabilities: Required capabilities for the target agent
            
        Returns:
            delegation_id: The ID of the created delegation request
            
        Raises:
            PermissionError: If delegation is not allowed by policy
            ValueError: If parameters are invalid
        """
        if parameters is None:
            parameters = {}
        
        # Create the delegation request
        delegation_request = DelegationProtocol.create_delegation_request(
            from_agent=self.identity,
            to_agent_id=to_agent_id,
            action=action,
            task_description=task_description,
            parameters=parameters,
            deadline=deadline,
            required_capabilities=required_capabilities,
            tee_authorization=tee_authorization
        )
        
        # Check if delegation is allowed by policy
        allowed, reason = self.policy_engine.evaluate_delegation_request(
            delegation_request,
            self.identity.agent_id,
            to_agent_id
        )
        
        if not allowed:
            logger.warning(f"Delegation denied: {reason}")
            raise PermissionError(f"Delegation not allowed: {reason}")
        
        # Store the delegation request
        with self._lock:
            self._delegations[delegation_request.delegation_id] = delegation_request
            
            # Add to delegation log for audit trail
            log_entry = {
                "timestamp": time.time(),
                "type": "delegation_created",
                "delegation_id": delegation_request.delegation_id,
                "from_agent": self.identity.agent_id,
                "to_agent": to_agent_id,
                "action": action,
                "task_description": task_description
            }
            self._delegation_log.append(log_entry)
        
        logger.info(f"Created delegation {delegation_request.delegation_id}: {action} to {to_agent_id}")

        # Returns the delegation_id; caller retrieves the DelegationRequest from
        # self._delegations[delegation_id], calls to_action_request(), and sends
        # the signed dict to the target agent's process_delegation_request().
        return delegation_request.delegation_id
    
    def process_delegation_request(
        self,
        signed_request: Dict,
        expected_gateway_public_key_hex: Optional[str] = None,
        expected_gateway_key_id: Optional[str] = None,
        expected_build_config_id: Optional[str] = None,
        require_tee_authorization: Optional[bool] = None,
    ) -> Dict:
        """
        Process an incoming delegation request from another agent.
        
        Args:
            signed_request: The signed action request received from another agent
            
        Returns:
            Signed action request containing the delegation result
            
        Raises:
            ValueError: If the request is invalid or not allowed
            PermissionError: If the delegation violates policy
        """
        try:
            # Extract the delegation request from the signed action request
            delegation_request = DelegationRequest.from_action_request(signed_request)
            
            logger.info(f"Received delegation request {delegation_request.delegation_id}: {delegation_request.action}")
            
            # Validate the request
            if delegation_request.is_expired():
                raise ValueError("Delegation request has expired")
            
            # Verify that the request is addressed to us
            if delegation_request.to_agent_id != self.identity.agent_id:
                raise ValueError(f"Delegation request not for this agent")
            
            # Verify Ed25519 signature, expiry, audience, and payload hash integrity
            trusted_require_tee_authorization = _trusted_tee_authorization_requirement(
                require_tee_authorization,
                expected_gateway_public_key_hex,
                expected_gateway_key_id,
                expected_build_config_id,
            )
            is_valid, error_msg, replay_key = DelegationProtocol.validate_delegation_request(
                signed_request,
                self.identity.agent_id,
                expected_gateway_public_key_hex or "",
                expected_gateway_key_id or "",
                expected_build_config_id or "",
                trusted_require_tee_authorization,
            )
            if not is_valid:
                raise ValueError(f"Invalid delegation request: {error_msg}")
            
            # Check if we're allowed to perform this task
            allowed, reason = self.policy_engine.evaluate_delegation_request(
                delegation_request,
                delegation_request.from_agent_id,
                self.identity.agent_id
            )
            
            if not allowed:
                logger.warning(f"Delegation not allowed by policy: {reason}")
                # Create a failed result
                result = DelegationProtocol.create_delegation_result(
                    delegation_request,
                    self.identity,
                    DelegationStatus.FAILED,
                    error=f"Not allowed by policy: {reason}"
                )
                return result.to_action_request(self.identity)
            
            # Check if we have a handler for this action
            handler = self._task_handlers.get(delegation_request.action)
            if not handler:
                logger.warning(f"No handler registered for action: {delegation_request.action}")
                result = DelegationProtocol.create_delegation_result(
                    delegation_request,
                    self.identity,
                    DelegationStatus.FAILED,
                    error=f"No handler available for action: {delegation_request.action}"
                )
                return result.to_action_request(self.identity)

            replay_integrity_key = _request_replay_integrity_key(self.identity)
            replay_allowed, replay_reason, replay_execution_token = DelegationProtocol.begin_delegation_request_execution(
                replay_key,
                _delegation_request_replay_expires_at(delegation_request),
                self.identity.agent_id,
                delegation_request.delegation_id,
                receipt_fingerprint(delegation_request.tee_authorization or {}),
                replay_integrity_key,
            )
            if not replay_allowed:
                logger.warning(replay_reason)
                result = DelegationProtocol.create_delegation_result(
                    delegation_request,
                    self.identity,
                    DelegationStatus.FAILED,
                    error=replay_reason,
                )
                return result.to_action_request(self.identity)
            
            # Mark delegation as in progress
            with self._lock:
                self._delegations[delegation_request.delegation_id] = delegation_request
                
                log_entry = {
                    "timestamp": time.time(),
                    "type": "delegation_received",
                    "delegation_id": delegation_request.delegation_id,
                    "from_agent": delegation_request.from_agent_id,
                    "to_agent": self.identity.agent_id,
                    "action": delegation_request.action,
                    "status": "in_progress"
                }
                self._delegation_log.append(log_entry)
            
            # Execute the task
            heartbeat_stop, heartbeat_thread = _start_request_replay_heartbeat(
                replay_key,
                replay_integrity_key,
                replay_execution_token,
            )

            try:
                logger.info(f"Executing task {delegation_request.action} for delegation {delegation_request.delegation_id}")
                task_result = handler(delegation_request.parameters)
                
                # Create successful result
                result = DelegationProtocol.create_delegation_result(
                    delegation_request,
                    self.identity,
                    DelegationStatus.COMPLETED,
                    result=task_result
                )
                DelegationProtocol.finalize_delegation_request_execution(
                    replay_key,
                    "COMPLETED",
                    replay_integrity_key,
                    execution_token=replay_execution_token,
                )
                
                status = DelegationStatus.COMPLETED
                
            except Exception as e:
                logger.error(f"Task execution failed: {e}")
                DelegationProtocol.finalize_delegation_request_execution(
                    replay_key,
                    "RETRYABLE_FAILURE",
                    replay_integrity_key,
                    error=str(e),
                    execution_token=replay_execution_token,
                )
                result = DelegationProtocol.create_delegation_result(
                    delegation_request,
                    self.identity,
                    DelegationStatus.FAILED,
                    error=str(e)
                )
                status = DelegationStatus.FAILED
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=1.0)
            
            # Store the result
            with self._lock:
                self._results[delegation_request.delegation_id] = result
                
                log_entry = {
                    "timestamp": time.time(),
                    "type": "delegation_completed",
                    "delegation_id": delegation_request.delegation_id,
                    "from_agent": delegation_request.from_agent_id,
                    "to_agent": self.identity.agent_id,
                    "action": delegation_request.action,
                    "status": status.value,
                    "has_error": bool(result.error)
                }
                self._delegation_log.append(log_entry)
            
            # Generate and save an execution receipt for audit trail
            try:
                # We'll create a mock "decision" for the receipt based on the outcome
                decision = {
                    "decision": "ALLOW" if result.status == DelegationStatus.COMPLETED else "DENY",
                    "action": delegation_request.action,
                    "agent_fingerprint": self.identity.agent_id,
                    "ts": time.time(),
                    "nonce_hash": delegation_request.nonce,  # Simplified
                    "proof_hash": "",  # Would be actual proof hash in real implementation
                    "policy_version": "1.0",
                    "denial_code": None if result.status == DelegationStatus.COMPLETED else "TASK_FAILED"
                }
                
                receipt = build_receipt(decision)
                # In a full implementation, we would save this receipt
                # save_receipt(receipt)
                
            except Exception as e:
                logger.warning(f"Failed to create execution receipt: {e}")
            
            # Return the signed result
            return result.to_action_request(self.identity)
            
        except Exception as e:
            logger.error(f"Error processing delegation request: {e}")
            # Return a signed error response
            error_result = DelegationResult(
                delegation_id="error",
                from_agent_id=self.identity.agent_id,
                to_agent_id="unknown",
                status=DelegationStatus.FAILED,
                error=str(e),
                nonce=str(uuid.uuid4()),
                issued_at=time.time()
            )
            return error_result.to_action_request(self.identity)
    
    def get_delegation_result(self, delegation_id: str) -> Optional[DelegationResult]:
        """
        Get the result of a delegation request.
        
        Args:
            delegation_id: The ID of the delegation request
            
        Returns:
            DelegationResult if available, None if not yet completed
        """
        with self._lock:
            return self._results.get(delegation_id)
    
    def get_pending_delegations(self) -> List[DelegationRequest]:
        """
        Get list of pending delegation requests (those we sent but haven't got results for).
        
        Returns:
            List of DelegationRequest instances
        """
        with self._lock:
            pending = []
            for deleg_id, request in self._delegations.items():
                if deleg_id not in self._results:
                    pending.append(request)
            return pending
    
    def get_delegation_log(self, limit: int = None) -> List[Dict]:
        """
        Get the delegation audit trail.
        
        Args:
            limit: Maximum number of entries to return (None for all)
            
        Returns:
            List of log entries (most recent first)
        """
        with self._lock:
            log = list(self._delegation_log)
            log.reverse()  # Most recent first
            if limit is not None:
                log = log[:limit]
            return log
    
    def get_agent_status(self) -> Dict:
        """
        Get current status of this agent in the delegation network.

        Returns:
            Dictionary with agent status information
        """
        with self._lock:
            # Read delegation_log directly here — get_delegation_log also acquires
            # self._lock, which would deadlock since Lock is non-reentrant.
            log = list(self._delegation_log)
            log.reverse()
            recent = log[:5]
            return {
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "did": self.identity.did,
                "public_key_hex": self.identity.public_key_hex,
                "active_delegations": len([
                    d for d in self._delegations.values()
                    if d.delegation_id not in self._results
                ]),
                "completed_delegations": len(self._results),
                "failed_delegations": len([
                    r for r in self._results.values()
                    if r.status == DelegationStatus.FAILED
                ]),
                "registered_handlers": list(self._task_handlers.keys()),
                "policy_info": self.policy_engine.policy.get_agent_info(self.identity.agent_id),
                "recent_activity": recent,
            }
    
    def shutdown(self):
        """Shutdown the agent delegation network gracefully."""
        logger.info(f"Shutting down Agent Delegation Network: {self.agent_name}")
        # In a full implementation, we would:
        # 1. Cancel any pending delegations
        # 2. Notify connected agents of shutdown
        # 3. Save final state
        # 4. Close network connections
        pass


# Convenience functions for easy usage
def create_agent(
    agent_name: str = None,
    policy_file: Optional[Path] = None,
    private_key_hex: Optional[str] = None,
) -> AgentDelegationNetwork:
    """
    Factory function to create an agent in the delegation network.

    Args:
        agent_name: Optional name for the agent
        policy_file: Optional path to delegation policy configuration
        private_key_hex: 64-char hex Ed25519 private key. If omitted, loads
                         from T3N_API_KEY env var (primary/coordinator agent).
                         Pass secrets.token_hex(32) for ephemeral worker agents.

    Returns:
        AgentDelegationNetwork instance
    """
    return AgentDelegationNetwork(agent_name=agent_name, policy_file=policy_file, private_key_hex=private_key_hex)


def quick_delegate(
    from_agent: AgentDelegationNetwork,
    to_agent_id: str,
    action: str,
    task_description: str,
    parameters: Dict = None
) -> str:
    """
    Convenience function for quick task delegation.
    
    Args:
        from_agent: The agent making the request
        to_agent_id: The target agent's ID
        action: The action to perform
        task_description: Human-readable description
        parameters: Task parameters
        
    Returns:
        delegation_id: The ID of the created delegation request
    """
    return from_agent.delegate_task(
        to_agent_id=to_agent_id,
        action=action,
        task_description=task_description,
        parameters=parameters
    )


# Example usage and patterns
class ADNPatterns:
    """Common patterns for using the Agent Delegation Network."""
    
    @staticmethod
    def master_worker_setup(num_workers: int = 3) -> Dict[str, AgentDelegationNetwork]:
        """
        Set up a master-worker pattern.
        
        Returns:
            Dictionary mapping agent roles to agent instances
        """
        agents = {}
        
        # Create master agent
        agents["master"] = create_agent("master-coordinator")
        
        # Create worker agents
        for i in range(num_workers):
            agents[f"worker-{i+1}"] = create_agent(f"worker-node-{i+1}")
        
        return agents
    
    @staticmethod
    def pipeline_setup(stage_names: List[str] = None) -> Dict[str, AgentDelegationNetwork]:
        """
        Set up a linear processing pipeline.
        
        Args:
            stage_names: Names for each stage in the pipeline
            
        Returns:
            Dictionary mapping stage names to agent instances
        """
        if stage_names is None:
            stage_names = ["ingest", "validate", "process", "aggregate", "report"]
        
        agents = {}
        for name in stage_names:
            agents[name] = create_agent(f"{name}-stage")
        
        return agents
