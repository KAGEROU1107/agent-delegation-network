"""
Phase 10 — Verifiable AI Decision Audit

AI agents log every decision they make with a rationale hash and confidence score.
The TEE creates an immutable audit entry for each decision.
An auditor agent periodically invokes audit-decisions to detect anomalies
(low-confidence decisions, outlier patterns) and produce a tamper-proof attestation.

T3N TEE functions used:
  - log-decision: creates a TEE-attested audit entry for a decision
  - audit-decisions: scans all entries for anomalies, returns risk score
"""

import hashlib
from typing import Dict, List
from src.agent_identity import AgentIdentity
from llm.client import ask


class DecisionAuditAgent:
    """
    Logs agent decisions to the TEE and runs audits to detect anomalies.
    """

    def __init__(self, auditor: AgentIdentity):
        self.auditor = auditor
        self._entries: List[Dict] = []

    def log_decision(
        self,
        agent: AgentIdentity,
        decision_id: str,
        action: str,
        rationale: str,
        confidence: float,
        tee_invoke_fn,
    ) -> Dict:
        """Log a decision with its rationale hash to the TEE."""
        rationale_hash = hashlib.sha256(rationale.encode()).hexdigest()[:20]
        payload = {
            "agent_did": agent.did,
            "decision_id": decision_id,
            "action": action,
            "rationale_hash": rationale_hash,
            "confidence": confidence,
        }
        result = tee_invoke_fn("log-decision", payload)
        self._entries.append({
            "agent_did": agent.did,
            "action": action,
            "confidence": confidence,
            "entry_hash": result.get("entry_hash", ""),
        })
        return result

    def run_audit(self, tee_invoke_fn) -> Dict:
        """Auditor scans all entries inside the TEE for anomalies."""
        payload = {
            "auditor_did": self.auditor.did,
            "entries": [{"agent_did": e["agent_did"], "action": e["action"], "confidence": e["confidence"]}
                        for e in self._entries],
        }
        return tee_invoke_fn("audit-decisions", payload)

    def generate_report(self, audit_result: Dict) -> str:
        """Use the LLM to generate a human-readable audit report."""
        return ask(
            f"Write a 2-sentence audit summary. "
            f"Total decisions: {audit_result.get('total_decisions', 0)}. "
            f"Anomalies: {audit_result.get('anomalies_detected', 0)}. "
            f"Risk score: {audit_result.get('risk_score', 0):.2f}.",
            system="You write concise security audit summaries for AI agent systems."
        )

    def run_demo(self, agents: List[AgentIdentity], tee_invoke_fn) -> Dict:
        """
        Demo: agents log decisions → auditor runs TEE audit → report generated.
        Includes one low-confidence decision (confidence=0.3) to trigger anomaly detection.
        """
        decisions = [
            (agents[0], "D001", "route_to_premium_processor", "High revenue segment detected", 0.95),
            (agents[1], "D002", "apply_quality_filter", "Data quality score below threshold", 0.88),
            (agents[0], "D003", "escalate_to_human", "Edge case outside training distribution", 0.30),
            (agents[1], "D004", "proceed_with_delegation", "All checks passed", 0.92),
        ]

        log_results = []
        for agent, did, action, rationale, conf in decisions:
            result = self.log_decision(agent, did, action, rationale, conf, tee_invoke_fn)
            log_results.append({"decision_id": did, "entry_hash": result.get("entry_hash"), "logged_in_tee": result.get("logged_in_tee")})

        audit = self.run_audit(tee_invoke_fn)
        report = self.generate_report(audit)

        return {
            "phase": "decision_audit",
            "decisions_logged": len(log_results),
            "anomalies_detected": audit.get("anomalies_detected"),
            "risk_score": audit.get("risk_score"),
            "attestation": audit.get("attestation"),
            "audited_in_tee": audit.get("audited_in_tee"),
            "report": report[:120] + "..." if len(report) > 120 else report,
        }
