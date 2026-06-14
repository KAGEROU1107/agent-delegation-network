"""
Generic LLM client — lightweight wrapper for grunt-work LLM calls.

Used by Python ADN agents for reasoning tasks that don't need to run inside the TEE:
  - Writing task specifications for auctions
  - Generating rationale hashes for decision audit
  - Producing KYC data summaries
  - Drafting DAO proposals

Configure via environment variables:
  LLM_API_KEY   — API key for your LLM provider (required for live calls)
  LLM_BASE_URL  — Base URL of an OpenAI-compatible API endpoint
  LLM_MODEL     — Model name (default: gpt-4o-mini)
  LLM_PROVIDER  — Informational label (e.g. "openai", "groq", "local")

When LLM_API_KEY is not set the client falls back to a deterministic stub so
the demo runs without any LLM credentials.
"""

import json
import os
import urllib.request
import urllib.error
from typing import Optional


DEFAULT_BASE_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"


class LLMClient:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY", "")
        self.model = model or os.getenv("LLM_MODEL", DEFAULT_MODEL)
        self.base_url = base_url or os.getenv("LLM_BASE_URL", DEFAULT_BASE_URL)
        self._available = bool(self.api_key)

    def complete(self, prompt: str, system: str = "You are a concise AI agent assistant.", max_tokens: int = 256) -> str:
        """
        Call the configured LLM endpoint with a single prompt. Returns the response text.
        Falls back to a deterministic stub if LLM_API_KEY is not configured.
        """
        if not self._available:
            return self._stub(prompt)

        payload = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }).encode()

        req = urllib.request.Request(
            self.base_url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                return data["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            # Quota exceeded or key invalid → graceful fallback so demo still runs
            if e.code in (403, 429):
                return self._stub(prompt)
            raise RuntimeError(f"LLM API HTTP {e.code}: {body}") from e

    def _stub(self, prompt: str) -> str:
        """Deterministic stub used when LLM_API_KEY is not set."""
        keywords = prompt.lower()
        if "auction" in keywords or "bid" in keywords:
            return "Task specification: Analyze Q1 2026 premium sales data. Deliverable: segmented revenue report with regional breakdown. SLA: 2 hours."
        if "reputation" in keywords or "quality" in keywords:
            return "Quality assessment: Agent completed task within SLA, output met validation criteria, no anomalies detected."
        if "kyc" in keywords or "compliance" in keywords:
            return "KYC summary: All four verification steps passed. Applicant identity confirmed, address verified, financials within threshold, compliance check clean."
        if "proposal" in keywords or "vote" in keywords or "dao" in keywords:
            return "Proposal: Prioritize high-value segment tasks in Q2. Rationale: Q1 data shows 28% higher revenue per premium record."
        if "decision" in keywords or "rationale" in keywords:
            return "Decision rationale: Selected optimal agent based on reputation score 0.92, previous task completion rate 100%, bid within budget."
        if "personali" in keywords or "outreach" in keywords:
            return "Personalization strategy: high_value segment receives premium_offer variant with 15% discount; at_risk segment receives retention_offer."
        return "Agent task completed. Output meets specification requirements."


# Module-level singleton — import and use directly
_client: Optional[LLMClient] = None


def get_client() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client


def ask(prompt: str, system: str = "You are a concise AI agent assistant.", max_tokens: int = 256) -> str:
    """Convenience function — call without instantiating a client."""
    return get_client().complete(prompt, system=system, max_tokens=max_tokens)
