"""
Phase 11 — Agent Performance Bond

Before taking a task, an agent locks a performance bond in the T3N TEE.
The TEE enforces settlement rules after the task completes:
  - Excellent delivery (quality ≥ 0.9, on time) → full payout
  - Acceptable delivery (quality ≥ 0.7, on time) → proportional payout
  - Late delivery → 50% payout regardless of quality
  - Incomplete → slashed (0% payout)
  - Below threshold quality → penalized (25% payout)

This creates economic accountability in multi-agent systems using
hardware-enforced escrow — no trusted third party needed.

T3N TEE functions used:
  - lock-bond: locks a performance bond for a task
  - verify-and-settle: evaluates delivery and settles the bond
"""

import time
from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity


class PerformanceBond:
    """
    Manages TEE-enforced performance bonds for agent task accountability.
    """

    def __init__(self):
        self._bonds: Dict[str, Dict] = {}  # bond_id → bond metadata

    def lock_bond(
        self,
        agent: AgentIdentity,
        task_id: str,
        bond_amount: float,
        duration_seconds: int,
        tee_invoke_fn,
    ) -> Dict:
        """Agent locks a bond before starting a task."""
        deadline_epoch = int(time.time()) + duration_seconds
        payload = {
            "agent_did": agent.did,
            "task_id": task_id,
            "bond_amount": bond_amount,
            "deadline_epoch": deadline_epoch,
        }
        result = tee_invoke_fn("lock-bond", payload)
        bond_id = result.get("bond_id", "")
        self._bonds[bond_id] = {
            "agent_did": agent.did,
            "task_id": task_id,
            "bond_amount": bond_amount,
            "deadline_epoch": deadline_epoch,
            "locked_in_tee": result.get("locked_in_tee", False),
        }
        return result

    def settle_bond(
        self,
        bond_id: str,
        agent: AgentIdentity,
        completed: bool,
        quality_score: float,
        tee_invoke_fn,
    ) -> Dict:
        """Coordinator settles a bond after task completion."""
        bond = self._bonds.get(bond_id)
        if bond is None:
            raise ValueError(f"Bond {bond_id} not found")

        payload = {
            "bond_id": bond_id,
            "agent_did": agent.did,
            "task_id": bond["task_id"],
            "bond_amount": bond["bond_amount"],
            "deadline_epoch": bond["deadline_epoch"],
            "current_epoch": int(time.time()),
            "completed": completed,
            "quality_score": quality_score,
        }
        return tee_invoke_fn("verify-and-settle", payload)

    def run_demo(self, agents: List[AgentIdentity], tee_invoke_fn) -> Dict:
        """
        Demo: agents lock bonds → coordinator settles after "completion".
        Shows full settlement, partial (late), and slashed scenarios.
        """
        scenarios = [
            (agents[0], "TASK-001", 100.0, 3600, True, 0.95),   # full payout
            (agents[1], "TASK-002", 50.0, 3600, True, 0.75),    # partial payout
            (agents[0], "TASK-003", 80.0, 3600, False, 0.0),    # slashed
        ]

        results = []
        for agent, task_id, amount, duration, completed, quality in scenarios:
            lock = self.lock_bond(agent, task_id, amount, duration, tee_invoke_fn)
            bond_id = lock.get("bond_id", "")
            settle = self.settle_bond(bond_id, agent, completed, quality, tee_invoke_fn)
            results.append({
                "task_id": task_id,
                "bond_amount": amount,
                "settlement": settle.get("settlement"),
                "payout_pct": settle.get("payout_pct"),
                "payout_amount": settle.get("payout_amount"),
                "reason": settle.get("reason"),
                "settled_in_tee": settle.get("settled_in_tee"),
            })

        return {
            "phase": "performance_bond",
            "bonds_settled": len(results),
            "settlements": results,
        }
