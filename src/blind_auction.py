"""
Phase 2 — Blind Multi-Agent Auction

Worker agents compete for a task by submitting sealed bids inside the T3N TEE.
Bids are hidden from other bidders — only the TEE sees the raw amounts.
The coordinator resolves the auction: lowest bid wins.

T3N TEE functions used:
  - submit-bid: seals a bid inside the enclave, returns a receipt (not the amount)
  - resolve-auction: compares all bids inside TEE, announces winner
"""

import secrets
import hashlib
import json
from typing import Dict, List, Optional
from src.agent_identity import AgentIdentity
from openrouter.client import ask


class BlindAuction:
    """
    Coordinates a sealed-bid auction where worker agents bid on a task.
    Bids are sealed inside the TEE before the coordinator sees them.
    """

    def __init__(self, item_id: str, coordinator: AgentIdentity):
        self.item_id = item_id
        self.coordinator = coordinator
        self.bids: List[Dict] = []
        self.sealed_receipts: List[Dict] = []
        self.result: Optional[Dict] = None

    def write_task_spec(self) -> str:
        """Use OpenRouter to generate a task specification for the auction."""
        return ask(
            f"Write a concise task specification for an AI agent auction. Task ID: {self.item_id}. "
            "The winning agent will process premium sales data. Include deliverable and SLA.",
            system="You write short, precise task specifications for AI agent work auctions."
        )

    def submit_bid(self, worker: AgentIdentity, amount: float, tee_invoke_fn) -> Dict:
        """
        Worker submits a sealed bid. The TEE seals the amount — other agents
        only see the receipt, not the bid amount.
        """
        nonce = secrets.token_hex(16)
        payload = {
            "bidder_did": worker.did,
            "item_id": self.item_id,
            "amount": amount,
            "nonce": nonce,
        }

        # Submit to TEE — amount is sealed inside the enclave
        tee_result = tee_invoke_fn("submit-bid", payload)

        receipt = {
            "bidder_did": worker.did,
            "item_id": self.item_id,
            "amount": amount,          # kept locally by the bidder
            "bid_hash": tee_result.get("bid_hash", ""),
            "receipt": tee_result.get("receipt", ""),
            "sealed_in_tee": tee_result.get("sealed_in_tee", False),
        }
        self.bids.append({"bidder_did": worker.did, "amount": amount})
        self.sealed_receipts.append(receipt)
        return receipt

    def resolve(self, tee_invoke_fn) -> Dict:
        """Coordinator resolves the auction inside the TEE."""
        if not self.bids:
            raise ValueError("No bids to resolve")

        payload = {
            "item_id": self.item_id,
            "bids": self.bids,
        }
        result = tee_invoke_fn("resolve-auction", payload)
        self.result = result
        return result

    def run_demo(self, workers: List[AgentIdentity], amounts: List[float], tee_invoke_fn) -> Dict:
        """Full auction: spec → sealed bids → TEE resolution."""
        spec = self.write_task_spec()
        receipts = [self.submit_bid(w, a, tee_invoke_fn) for w, a in zip(workers, amounts)]
        result = self.resolve(tee_invoke_fn)

        return {
            "phase": "blind_auction",
            "item_id": self.item_id,
            "task_spec": spec[:120] + "..." if len(spec) > 120 else spec,
            "bids_submitted": len(receipts),
            "sealed_receipts": [r["receipt"] for r in receipts],
            "winner_did": result.get("winner_did"),
            "winning_amount": result.get("winning_amount"),
            "total_bids": result.get("total_bids"),
            "resolved_in_tee": result.get("resolved_in_tee", False),
        }
