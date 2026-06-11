"""
Phase 3 — Agent Reputation Ledger

Agents build verifiable reputation scores via the TEE. After each completed task,
the coordinator records performance. The TEE computes a weighted score:
  - Quality: 70% weight
  - Timeliness: 30% weight

Reputation determines task assignment priority in future delegation rounds.

T3N TEE functions used:
  - record-completion: records a task outcome and returns the reputation delta
  - get-reputation: computes an agent's overall score from their history
"""

from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity
from openrouter.client import ask


class ReputationLedger:
    """
    Maintains agent performance history and computes TEE-verified reputation scores.
    """

    def __init__(self):
        self._history: Dict[str, List[Dict]] = {}  # did → list of task records

    def record_task(
        self,
        agent: AgentIdentity,
        task_id: str,
        quality_score: float,
        on_time: bool,
        tee_invoke_fn,
    ) -> Dict:
        """Record a completed task and get TEE-verified reputation delta."""
        payload = {
            "agent_did": agent.did,
            "task_id": task_id,
            "quality_score": quality_score,
            "on_time": on_time,
        }
        result = tee_invoke_fn("record-completion", payload)

        entry = {
            "task_id": task_id,
            "quality_score": quality_score,
            "on_time": on_time,
            "reputation_delta": result.get("reputation_delta", 0.0),
            "recorded_in_tee": result.get("recorded_in_tee", False),
        }
        self._history.setdefault(agent.did, []).append(entry)
        return result

    def get_reputation(self, agent: AgentIdentity, tee_invoke_fn) -> Dict:
        """Get TEE-computed reputation for an agent based on their recorded history."""
        history = self._history.get(agent.did, [])
        if not history:
            return {"agent_did": agent.did, "reputation_score": 0.0, "tier": "UNRATED", "tasks_evaluated": 0}

        payload = {
            "agent_did": agent.did,
            "history": [{"quality_score": e["quality_score"], "on_time": e["on_time"]} for e in history],
        }
        return tee_invoke_fn("get-reputation", payload)

    def rank_agents(self, agents: List[AgentIdentity], tee_invoke_fn) -> List[Dict]:
        """Return agents ranked by TEE-computed reputation score (highest first)."""
        scores = []
        for agent in agents:
            rep = self.get_reputation(agent, tee_invoke_fn)
            scores.append({
                "agent_did": agent.did,
                "agent_name": agent.agent_name,
                "reputation_score": rep.get("reputation_score", 0.0),
                "tier": rep.get("tier", "UNRATED"),
                "tasks_evaluated": rep.get("tasks_evaluated", 0),
            })
        return sorted(scores, key=lambda x: x["reputation_score"], reverse=True)

    def generate_assessment(self, agent: AgentIdentity, rep: Dict) -> str:
        """Use OpenRouter to generate a natural-language quality assessment."""
        return ask(
            f"Write a 2-sentence quality assessment for an AI agent. "
            f"Reputation score: {rep.get('reputation_score', 0):.2f}/1.0. "
            f"Tier: {rep.get('tier', 'UNRATED')}. "
            f"Tasks evaluated: {rep.get('tasks_evaluated', 0)}.",
            system="You write concise agent performance assessments for multi-agent systems."
        )

    def run_demo(self, agents: List[AgentIdentity], task_records: List[Dict], tee_invoke_fn) -> Dict:
        """
        Full ledger demo: record tasks for all agents, then compute rankings.
        task_records: list of {agent_idx, task_id, quality_score, on_time}
        """
        completions = []
        for rec in task_records:
            agent = agents[rec["agent_idx"]]
            result = self.record_task(agent, rec["task_id"], rec["quality_score"], rec["on_time"], tee_invoke_fn)
            completions.append({
                "agent_did": agent.did,
                "task_id": rec["task_id"],
                "reputation_delta": result.get("reputation_delta"),
                "recorded_in_tee": result.get("recorded_in_tee"),
            })

        rankings = self.rank_agents(agents, tee_invoke_fn)
        top = rankings[0] if rankings else {}
        assessment = self.generate_assessment(
            agents[0], {"reputation_score": top.get("reputation_score", 0), "tier": top.get("tier", "?"), "tasks_evaluated": top.get("tasks_evaluated", 0)}
        ) if rankings else ""

        return {
            "phase": "reputation_ledger",
            "tasks_recorded": len(completions),
            "rankings": rankings,
            "top_agent_did": top.get("agent_did"),
            "top_tier": top.get("tier"),
            "assessment": assessment[:100] + "..." if len(assessment) > 100 else assessment,
        }
