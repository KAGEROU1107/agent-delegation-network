"""
Phase 7 — Agentic KYC Pipeline

A multi-step KYC (Know Your Customer) process where different agents handle
each verification step. Data hashes flow through the TEE — no raw PII leaves
the enclave. The coordinator assembles the full picture without seeing
the underlying sensitive data.

Steps: identity → address → financial → compliance

T3N TEE functions used:
  - kyc-submit-step: records a completed KYC step with data hash
  - kyc-get-status: returns current approval status and missing steps
"""

import hashlib
from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity


KYC_STEPS = ["identity", "address", "financial", "compliance"]


class KYCPipeline:
    """
    Coordinates a multi-agent KYC pipeline where each agent handles one step.
    PII stays hashed — only verification status flows out of the TEE.
    """

    def __init__(self, applicant_id: str):
        self.applicant_id = applicant_id
        self._completed_steps: List[str] = []

    def _hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()[:20]

    def submit_step(
        self,
        agent: AgentIdentity,
        step: str,
        raw_data: str,
        tee_invoke_fn,
    ) -> Dict:
        """
        Agent submits a KYC step. Raw data is hashed before going to the TEE.
        The enclave records the step completion without seeing the underlying PII.
        """
        if step not in KYC_STEPS:
            raise ValueError(f"Unknown KYC step: {step}. Must be one of {KYC_STEPS}")

        data_hash = self._hash_data(raw_data)
        payload = {
            "agent_did": agent.did,
            "applicant_id": self.applicant_id,
            "step": step,
            "data_hash": data_hash,
        }
        result = tee_invoke_fn("kyc-submit-step", payload)
        self._completed_steps.append(step)
        return result

    def get_status(self, tee_invoke_fn) -> Dict:
        """Check KYC status inside the TEE."""
        payload = {
            "applicant_id": self.applicant_id,
            "steps_completed": self._completed_steps,
        }
        return tee_invoke_fn("kyc-get-status", payload)

    def run_demo(self, agents: List[AgentIdentity], tee_invoke_fn) -> Dict:
        """
        Full KYC pipeline: 4 agents handle 4 steps → final status check.
        Each agent only knows about its own step — TEE aggregates the full picture.
        """
        # Assign agents to steps (cycle if fewer agents than steps)
        step_results = []
        for i, step in enumerate(KYC_STEPS):
            agent = agents[i % len(agents)]
            # Synthetic data that would be real PII in production
            synthetic_data = f"applicant:{self.applicant_id}:step:{step}:verified"
            result = self.submit_step(agent, step, synthetic_data, tee_invoke_fn)
            step_results.append({
                "step": step,
                "agent_did": agent.did,
                "step_receipt": result.get("step_receipt"),
                "progress_pct": result.get("progress_pct"),
                "recorded_in_tee": result.get("recorded_in_tee"),
            })

        status = self.get_status(tee_invoke_fn)

        return {
            "phase": "kyc_pipeline",
            "applicant_id": self.applicant_id,
            "steps_submitted": len(step_results),
            "status": status.get("status"),
            "steps_completed": status.get("steps_completed"),
            "steps_required": status.get("steps_required"),
            "missing_steps": status.get("missing_steps", []),
            "verified_in_tee": status.get("verified_in_tee", False),
        }
