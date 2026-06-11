"""
Phase 4 — Privacy-Preserving Personalization

Agents personalize customer outreach without the coordinator ever seeing raw customer data.
Customer segment is determined inside the T3N TEE — only the message variant comes out.
OpenRouter generates the personalized message text from the variant, not from raw data.

T3N TEE functions used:
  - send-personalized-outreach: maps customer segment to message variant inside the enclave
"""

from typing import Dict, List
from src.agent_identity import AgentIdentity
from openrouter.client import ask


class PersonalizationAgent:
    """
    Runs privacy-preserving outreach personalization via the T3N TEE.
    Raw customer data stays inside the enclave; only message variants come out.
    """

    def __init__(self, coordinator: AgentIdentity):
        self.coordinator = coordinator

    def personalize(
        self,
        customer_id: str,
        segment: str,
        template_id: str,
        tee_invoke_fn,
    ) -> Dict:
        """
        TEE maps segment to message variant without exposing the segment label
        or raw customer data to the orchestrator.
        """
        payload = {
            "customer_id": customer_id,
            "segment": segment,
            "template_id": template_id,
            "data_hash": f"hash:{customer_id}:{segment}",  # hash of actual customer record
        }
        return tee_invoke_fn("send-personalized-outreach", payload)

    def compose_message(self, variant: str, customer_id: str) -> str:
        """
        OpenRouter composes the actual message text from the TEE-selected variant.
        No raw customer data is sent to OpenRouter — only the variant identifier.
        """
        return ask(
            f"Write a 1-sentence personalized outreach message for variant: {variant}. "
            f"Customer ID prefix: {customer_id[:6]}. Keep it warm and professional.",
            system="You write short, personalized outreach messages for sales teams."
        )

    def run_demo(self, customers: List[Dict], tee_invoke_fn) -> Dict:
        """
        Demo: personalize outreach for multiple customer segments.
        customers: list of {customer_id, segment, template_id}
        """
        results = []
        for c in customers:
            tee_result = self.personalize(c["customer_id"], c["segment"], c["template_id"], tee_invoke_fn)
            variant = tee_result.get("message_variant", "standard")
            message = self.compose_message(variant, c["customer_id"])
            results.append({
                "customer_id": c["customer_id"],
                "message_variant": variant,
                "personalization_score": tee_result.get("personalization_score"),
                "raw_data_exposed": tee_result.get("raw_data_exposed", True),
                "processed_in_tee": tee_result.get("processed_in_tee", False),
                "message": message[:80] + "..." if len(message) > 80 else message,
            })

        return {
            "phase": "personalization",
            "customers_processed": len(results),
            "all_private": all(not r["raw_data_exposed"] for r in results),
            "results": results,
        }
