import json
import os
import urllib.error
import urllib.request
from typing import Any


DEFAULT_BASE_URL = "https://staging.terminal3.io"


def get_t3n_api_key() -> str:
    """Return the Terminal 3 token without logging or normalizing it."""
    return os.getenv("T3N_API_KEY", "").strip() or os.getenv("TERMINAL3_API_KEY", "").strip()


def get_configured_did() -> str:
    return os.getenv("DID", "").strip() or os.getenv("T3N_DID", "").strip()


def get_did(api_key: str | None = None, base_url: str | None = None) -> dict[str, Any]:
    """
    Call Terminal 3's documented token API.

    Docs: GET /v1/did with x-api-token header.
    This function never prints or returns the raw token.
    """
    token = (api_key or get_t3n_api_key()).strip()
    if not token:
        return {
            "ok": False,
            "status": None,
            "did": None,
            "error": "T3N_API_KEY_MISSING",
        }

    url = (base_url or os.getenv("T3N_BASE_URL", DEFAULT_BASE_URL)).rstrip("/") + "/v1/did"
    request = urllib.request.Request(url, method="GET", headers={"x-api-token": token})

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body) if body else {}
            did = data.get("data", {}).get("did")
            return {
                "ok": True,
                "status": response.status,
                "did": did,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": False,
            "status": exc.code,
            "did": None,
            "error": _extract_error(body) or exc.reason,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": None,
            "did": None,
            "error": exc.__class__.__name__,
        }


def validate_configured_identity() -> dict[str, Any]:
    configured_did = get_configured_did()
    result = get_did()
    result["configured_did"] = configured_did or None
    result["did_matches"] = bool(configured_did and result.get("did") == configured_did)
    return result


def _extract_error(body: str) -> str | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None

    errors = parsed.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            return first.get("code") or first.get("message")
    return None
