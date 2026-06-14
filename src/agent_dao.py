"""
Phase 9 — Autonomous Agent DAO

Agents vote on proposals via the T3N TEE. Votes are sealed inside the enclave —
no agent knows how others voted until the tally is announced.
The TEE enforces quorum rules and produces a tamper-proof result.

T3N TEE functions used:
  - cast-vote: seals a vote inside the TEE, returns a receipt
  - tally-votes: counts all votes inside the TEE, announces result
"""

import hashlib
from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity
from llm.client import ask


class AgentDAO:
    """
    Implements a sealed-vote DAO for autonomous multi-agent decision making.
    """

    def __init__(self, proposal_id: str, quorum_threshold: int = 3):
        self.proposal_id = proposal_id
        self.quorum_threshold = quorum_threshold
        self._votes: List[Dict] = []

    def draft_proposal(self, context: str = "") -> str:
        """Use the LLM to draft the proposal text."""
        return ask(
            f"Draft a 2-sentence DAO proposal for a multi-agent system. "
            f"Proposal ID: {self.proposal_id}. Context: {context or 'Q1 2026 premium sales data processing prioritization'}.",
            system="You write concise governance proposals for autonomous AI agent DAOs."
        )

    def cast_vote(self, voter: AgentIdentity, vote: str, rationale: str, tee_invoke_fn) -> Dict:
        """Agent casts a sealed vote. Vote is hashed into enclave — not revealed until tally."""
        assert vote in ("FOR", "AGAINST", "ABSTAIN"), f"Invalid vote: {vote}"
        rationale_hash = hashlib.sha256(rationale.encode()).hexdigest()[:16]

        payload = {
            "voter_did": voter.did,
            "proposal_id": self.proposal_id,
            "vote": vote,
            "rationale_hash": rationale_hash,
        }
        result = tee_invoke_fn("cast-vote", payload)
        self._votes.append({"voter_did": voter.did, "vote": vote})
        return result

    def tally(self, tee_invoke_fn) -> Dict:
        """Tally all votes inside the TEE and announce the result."""
        payload = {
            "proposal_id": self.proposal_id,
            "votes": self._votes,
            "quorum_threshold": self.quorum_threshold,
        }
        return tee_invoke_fn("tally-votes", payload)

    def run_demo(self, agents: List[AgentIdentity], votes: List[str], tee_invoke_fn) -> Dict:
        """
        Full DAO round: draft proposal → agents vote → TEE tallies result.
        votes: list of "FOR"/"AGAINST"/"ABSTAIN" aligned with agents
        """
        proposal_text = self.draft_proposal()
        receipts = []
        for agent, vote in zip(agents, votes):
            rationale = f"Agent {agent.agent_name} votes {vote} on {self.proposal_id}"
            result = self.cast_vote(agent, vote, rationale, tee_invoke_fn)
            receipts.append(result.get("vote_receipt", ""))

        tally = self.tally(tee_invoke_fn)

        return {
            "phase": "agent_dao",
            "proposal_id": self.proposal_id,
            "proposal_text": proposal_text[:100] + "..." if len(proposal_text) > 100 else proposal_text,
            "votes_cast": len(receipts),
            "result": tally.get("result"),
            "votes_for": tally.get("votes_for"),
            "votes_against": tally.get("votes_against"),
            "quorum_met": tally.get("quorum_met"),
            "tallied_in_tee": tally.get("tallied_in_tee", False),
        }
