"""
Delegation Policy Engine for Terminal 3 Agent Delegation Network
Defines and enforces policies for agent delegation and task execution.
"""

import json
import os
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path

from src.agent_identity import AgentIdentity
from src.delegation_protocol import (
    DelegationRequest, 
    DelegationResult, 
    DelegationAction,
    DelegationStatus
)


class DelegationPolicy:
    """
    Policy engine for governing agent delegation and task execution.
    Similar to the governed_action_gate but for delegation-specific rules.
    """
    
    def __init__(self, policy_file: Optional[Path] = None):
        """
        Initialize the delegation policy engine.
        
        Args:
            policy_file: Optional path to delegation policy configuration
        """
        self.policy_file = policy_file or Path("config/delegation_policy.json")
        self._delegation_rules: Dict[str, Set[str]] = {}  # agent_id -> set of allowed actions
        self._agent_trust: Dict[str, Set[str]] = {}       # agent_id -> set of trusted agent_ids
        self._rate_limits: Dict[str, Dict] = {}           # agent_id -> rate limit info
        self._delegation_quotas: Dict[str, int] = {}      # agent_id -> daily delegation quota
        self._load_policy()
    
    def _load_policy(self):
        """Load policy configuration from file."""
        # Default policies - in a real implementation, these would come from config
        self._delegation_rules = {
            # Format: "agent_id": {"allowed_action_1", "allowed_action_2", ...}
            # For now, we'll allow delegating any action - policies can be customized
        }
        
        self._agent_trust = {}
        self._rate_limits = {}
        self._delegation_quotas = {}
        
        # Try to load from file if it exists
        if self.policy_file.exists():
            try:
                with open(self.policy_file, 'r') as f:
                    data = json.load(f)
                    self._delegation_rules = {
                        k: set(v) for k, v in data.get("delegation_rules", {}).items()
                    }
                    self._agent_trust = {
                        k: set(v) for k, v in data.get("agent_trust", {}).items()
                    }
                    self._rate_limits = data.get("rate_limits", {})
                    self._delegation_quotas = data.get("delegation_quotas", {})
            except Exception as e:
                print(f"Warning: Failed to load delegation policy from {self.policy_file}: {e}")
                print("Using default policies.")
    
    def save_policy(self):
        """Save current policy to file."""
        self.policy_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "delegation_rules": {
                k: list(v) for k, v in self._delegation_rules.items()
            },
            "agent_trust": {
                k: list(v) for k, v in self._agent_trust.items()
            },
            "rate_limits": self._rate_limits,
            "delegation_quotas": self._delegation_quotas
        }
        with open(self.policy_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def can_delegate(
        self,
        from_agent_id: str,
        to_agent_id: str,
        action: str
    ) -> Tuple[bool, str]:
        """
        Check if an agent is allowed to delegate a specific action to another agent.

        Args:
            from_agent_id: The agent_id (key fingerprint) of the delegating agent
            to_agent_id: The target agent's agent_id
            action: The action to delegate

        Returns:
            Tuple of (allowed, reason)
        """
        allowed_actions = self._delegation_rules.get(from_agent_id, set())

        # Default deny: explicit policy must be registered before any delegation is permitted.
        if not allowed_actions:
            return False, f"Delegation denied — no explicit policy registered for agent {from_agent_id} (default deny)"
        
        # Check if the action is in the allowed list
        if action in allowed_actions:
            # Trust check — must have an explicit trust relationship with the target (default deny).
            trusted_agents = self._agent_trust.get(from_agent_id, set())
            if not trusted_agents:
                return False, f"Delegation denied — no target-trust policy for agent {from_agent_id} (default deny)"
            if to_agent_id in trusted_agents:
                return True, f"Delegation of {action} to {to_agent_id} allowed"
            return False, f"Agent {from_agent_id} not trusted to delegate to {to_agent_id} for action {action}"
        
        return False, f"Action {action} not in delegation allowed list for agent {from_agent_id}"
    
    def can_perform_task(
        self,
        agent_id: str,
        action: str
    ) -> Tuple[bool, str]:
        """
        Check if an agent is allowed to perform a specific task action.

        Args:
            agent_id: The agent_id (key fingerprint) of the performing agent
            action: The action to perform

        Returns:
            Tuple of (allowed, reason)
        """
        allowed_actions = self._delegation_rules.get(agent_id, set())
        if not allowed_actions:
            return False, f"Action {action} denied — no policy registered for agent {agent_id} (default deny)"
        if action in allowed_actions:
            return True, f"Agent allowed to perform {action}"
        return False, f"Action {action} not in allowed list for agent {agent_id}"
    
    def add_delegation_rule(self, agent_id: str, action: str):
        """Add an action to an agent's allowed delegation list."""
        if agent_id not in self._delegation_rules:
            self._delegation_rules[agent_id] = set()
        self._delegation_rules[agent_id].add(action)
    
    def remove_delegation_rule(self, agent_id: str, action: str):
        """Remove an action from an agent's allowed delegation list."""
        if agent_id in self._delegation_rules:
            self._delegation_rules[agent_id].discard(action)
            if not self._delegation_rules[agent_id]:
                del self._delegation_rules[agent_id]
    
    def add_trust_relationship(self, from_agent_id: str, to_agent_id: str):
        """Establish a trust relationship between agents."""
        if from_agent_id not in self._agent_trust:
            self._agent_trust[from_agent_id] = set()
        self._agent_trust[from_agent_id].add(to_agent_id)
    
    def remove_trust_relationship(self, from_agent_id: str, to_agent_id: str):
        """Remove a trust relationship between agents."""
        if from_agent_id in self._agent_trust:
            self._agent_trust[from_agent_id].discard(to_agent_id)
            if not self._agent_trust[from_agent_id]:
                del self._agent_trust[from_agent_id]
    
    def is_trusted(self, from_agent_id: str, to_agent_id: str) -> bool:
        """Check if from_agent trusts to_agent."""
        trusted_agents = self._agent_trust.get(from_agent_id, set())
        return to_agent_id in trusted_agents
    
    def get_agent_info(self, agent_id: str) -> Dict:
        """Get information about an agent's policies and trust relationships."""
        return {
            "agent_id": agent_id,
            "allowed_actions": list(self._delegation_rules.get(agent_id, set())),
            "trusted_agents": list(self._agent_trust.get(agent_id, set())),
            "trusting_agents": [
                aid for aid, trusts in self._agent_trust.items() 
                if agent_id in trusts
            ],
            "rate_limits": self._rate_limits.get(agent_id, {}),
            "delegation_quota": self._delegation_quotas.get(agent_id, 0)
        }


class DelegationPolicyEngine:
    """
    Main interface for the delegation policy engine.
    """
    
    def __init__(self):
        self.policy = DelegationPolicy()
    
    def evaluate_delegation_request(
        self,
        request: 'DelegationRequest',
        from_agent_id: str,
        to_agent_id: str
    ) -> Tuple[bool, str]:
        """
        Evaluate whether a delegation request should be allowed.

        Args:
            request: The delegation request to evaluate
            from_agent_id: agent_id of the agent sending the request
            to_agent_id: agent_id of the agent that will receive and process it

        Returns:
            Tuple of (should_allow, reason)
        """
        can_delegate, reason = self.policy.can_delegate(
            from_agent_id,
            to_agent_id,
            request.action
        )
        if not can_delegate:
            return False, f"Delegation not allowed: {reason}"

        can_perform, reason = self.policy.can_perform_task(to_agent_id, request.action)
        if not can_perform:
            return False, f"Target agent not allowed to perform action: {reason}"

        return True, "Delegation request approved by policy"
    
    def evaluate_task_result(
        self,
        result: 'DelegationResult',
        performing_agent: AgentIdentity,
        requesting_agent: AgentIdentity
    ) -> Tuple[bool, str]:
        """
        Evaluate whether a task result should be accepted.
        
        Args:
            result: The delegation result to evaluate
            performing_agent: The agent that performed the task
            requesting_agent: The agent that requested the task
            
        Returns:
            Tuple of (should_accept, reason)
        """
        # Check if the performing agent is allowed to have done this task
        # We would need to know what action was requested - this would come from
        # the original delegation request stored somewhere
        
        # For now, we'll do basic validation
        if result.status not in [DelegationStatus.COMPLETED, DelegationStatus.FAILED]:
            return False, f"Invalid delegation status: {result.status}"
        
        if result.status == DelegationStatus.FAILED and not result.error:
            return False, "Failed delegation must include error message"
        
        return True, "Task result accepted"


# Convenience functions
def create_delegation_policy(policy_file: Optional[Path] = None) -> DelegationPolicy:
    """Create a delegation policy engine."""
    return DelegationPolicy(policy_file)


def check_delegation_allowed(
    from_agent_id: str,
    to_agent_id: str,
    action: str
) -> Tuple[bool, str]:
    """
    Check if delegation is allowed using the default policy.

    Args:
        from_agent_id: The requesting agent's agent_id
        to_agent_id: The target agent's agent_id
        action: The action to delegate

    Returns:
        Tuple of (allowed, reason)
    """
    policy = DelegationPolicy()
    return policy.can_delegate(from_agent_id, to_agent_id, action)


# Example policy configurations
class ExamplePolicies:
    """Example policy configurations for different use cases."""

    @staticmethod
    def open_network_policy() -> Dict:
        """Policy with explicit rules allowing all registered agents.
        
        NOTE: Policy engine is default-deny. Empty delegation_rules means DENY ALL.
        This example is a placeholder — populate delegation_rules and agent_trust
        before calling can_delegate() or all calls will be denied.
        See add_delegation_rule() and add_trust_relationship().
        """
        return {
            "delegation_rules": {},  # Empty = DENY ALL (default-deny). Populate explicitly.
            "agent_trust": {},       # Empty = DENY ALL target agents (default-deny; add_trust_relationship() required)
            "rate_limits": {},
            "delegation_quotas": {}
        }
    
    @staticmethod
    def hierarchical_policy() -> Dict:
        """Policy for a hierarchical organization."""
        return {
            "delegation_rules": {
                # Managers can delegate work tasks
                "manager-001": {"PROCESS_DATA", "GENERATE_REPORT", "VALIDATE_RESULTS"},
                "manager-002": {"PROCESS_DATA", "GENERATE_REPORT"},
                # Workers can only execute specific tasks
                "worker-001": {"DATA_ENTRY", "BASIC_CALCULATION"},
                "worker-002": {"DATA_ENTRY", "FORMAT_OUTPUT"},
                # Executives can only receive results
                "exec-001": set(),  # Can't delegate, only receive
            },
            "agent_trust": {
                # Managers trust their workers
                "manager-001": {"worker-001", "worker-002"},
                "manager-002": {"worker-001"},
                # Workers trust managers to validate their work
                "worker-001": {"manager-001", "manager-002"},
                "worker-002": {"manager-001"},
            },
            "rate_limits": {
                "manager-001": {"requests_per_minute": 10},
                "manager-002": {"requests_per_minute": 5},
            },
            "delegation_quotas": {
                "manager-001": 100,  # 100 delegations per day
                "manager-002": 50,
                "worker-001": 10,    # Workers can delegate less
                "worker-002": 10,
            }
        }
    
    @staticmethod
    def data_processing_pipeline_policy() -> Dict:
        """Policy for a data processing pipeline."""
        return {
            "delegation_rules": {
                "data_ingestor": {"VALIDATE_FORMAT", "ENRICH_DATA"},
                "data_validator": {"CLEAN_DATA", "CHECK_INTEGRITY"},
                "data_enricher": {"AGGREGATE_DATA", "CALCULATE_METRICS"},
                "data_aggregator": {"GENERATE_SUMMARY", "CREATE_VISUALIZATION"},
                "report_generator": {"FORMAT_REPORT", "DISTRIBUTE_REPORT"},
            },
            "agent_trust": {
                # Each stage trusts the next stage in the pipeline
                "data_ingestor": {"data_validator"},
                "data_validator": {"data_enricher"},
                "data_enricher": {"data_aggregator"},
                "data_aggregator": {"report_generator"},
                # Report generator doesn't delegate further
                "report_generator": set(),
            }
        }



