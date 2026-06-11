"""
Phase 6 — Cross-Tenant Verified Computation

Two conceptual tenants share a computation via the T3N TEE.
Each tenant's data stays separate — the TEE processes both datasets
inside the enclave and returns aggregated results without either tenant
seeing the other's raw records.

This demonstrates T3N's multi-party compute capability: parties that
don't trust each other can jointly produce verified output.

T3N TEE functions used:
  - process-data: processes each tenant's records independently
  - validate-quality: validates the combined output
"""

from typing import Dict, List
from src.agent_identity import AgentIdentity


class CrossTenantCollab:
    """
    Coordinates a multi-party computation where two tenants share a TEE contract.
    Each tenant sends their own records; the TEE processes both independently.
    """

    def __init__(self, coordinator: AgentIdentity):
        self.coordinator = coordinator

    def process_tenant_data(
        self,
        tenant_name: str,
        records: List[float],
        tee_invoke_fn,
    ) -> Dict:
        """Process a single tenant's records inside the TEE."""
        payload = {
            "data_source": f"{tenant_name}_private_records",
            "time_period": "Q1-2026",
            "filters": [f"tenant:{tenant_name}"],
            "records": records,
        }
        return tee_invoke_fn("process-data", payload)

    def aggregate_results(self, results: List[Dict]) -> Dict:
        """
        Aggregate TEE-verified outputs from multiple tenants.
        Neither tenant sees the other's raw data — only the combined aggregate.
        """
        total_records = sum(r.get("records_processed", 0) for r in results)
        total_revenue = sum(r.get("total_revenue", 0.0) for r in results)
        combined_avg = total_revenue / total_records if total_records > 0 else 0.0
        all_processed = all(r.get("processed_in_tee", False) for r in results)
        return {
            "total_records": total_records,
            "combined_revenue": round(total_revenue, 2),
            "combined_avg": round(combined_avg, 2),
            "all_processed_in_tee": all_processed,
        }

    def run_demo(self, tee_invoke_fn) -> Dict:
        """
        Demo: two tenants contribute records → TEE processes each → aggregate output.
        Tenant A and Tenant B never see each other's records.
        """
        # Synthetic record sets — in production these would be the tenants' private data
        tenant_a_records = [412.50, 289.00, 531.75, 198.25, 644.00, 321.50, 488.00, 275.25]
        tenant_b_records = [563.75, 392.00, 445.50, 312.25, 589.00, 234.75, 678.50, 356.00]

        result_a = self.process_tenant_data("tenant_alpha", tenant_a_records, tee_invoke_fn)
        result_b = self.process_tenant_data("tenant_beta", tenant_b_records, tee_invoke_fn)

        aggregate = self.aggregate_results([result_a, result_b])

        # Validate the combined output
        validate_payload = {
            "records_processed": aggregate["total_records"],
            "avg_value": aggregate["combined_avg"],
            "total_revenue": aggregate["combined_revenue"],
            "trend": result_a.get("trend", "stable"),
        }
        validation = tee_invoke_fn("validate-quality", validate_payload)

        return {
            "phase": "cross_tenant_collab",
            "tenant_alpha_records": len(tenant_a_records),
            "tenant_beta_records": len(tenant_b_records),
            "tenant_alpha_revenue": result_a.get("total_revenue"),
            "tenant_beta_revenue": result_b.get("total_revenue"),
            "combined_records": aggregate["total_records"],
            "combined_revenue": aggregate["combined_revenue"],
            "combined_avg": aggregate["combined_avg"],
            "quality_score": validation.get("quality_score"),
            "all_processed_in_tee": aggregate["all_processed_in_tee"],
        }
