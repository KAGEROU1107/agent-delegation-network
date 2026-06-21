"""Gateway-linked TEE authorization receipt helpers.

The current T3N generic-input world returns a delegation authorization decision,
but it does not directly dispatch Python workers. These helpers bind that
decision-shaped output into the Python worker path with a signed gateway receipt.
"""

from copy import deepcopy
from typing import Any, Dict, Optional

from src.terminal3_agent_auth_adapter import _canonical, _sha256, verify_action_request

RECEIPT_VERSION = "adn.tee_authorization/1"
RECEIPT_ACTION = "TEE_AUTHORIZATION"


def tee_authorization_request_hash(
    to_agent_id: str,
    action: str,
    parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """Hash the worker request fields covered by the gateway receipt."""
    return _sha256(_canonical({
        "to_agent_id": to_agent_id,
        "action": action,
        "parameters": parameters or {},
    }))


def _receipt_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    keys = [
        "v",
        "delegation_id",
        "tee_delegation_id",
        "status",
        "to_agent_id",
        "action",
        "request_hash",
        "credential_fingerprint",
    ]
    return {key: receipt.get(key) for key in keys}


def receipt_fingerprint(receipt: Dict[str, Any]) -> str:
    """Stable fingerprint of the receipt body, excluding gateway proof fields."""
    return _sha256(_canonical(_receipt_body(receipt)))


def build_tee_authorization_receipt(
    gateway_identity,
    tee_result: Dict[str, Any],
    action: str,
    parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a signed gateway receipt from a TEE delegate-task authorization result."""
    delegation_id = tee_result.get("delegation_id")
    to_agent_id = tee_result.get("routed_to")
    if not delegation_id or not to_agent_id:
        raise ValueError("TEE authorization requires delegation_id and routed_to")

    body = {
        "v": RECEIPT_VERSION,
        "delegation_id": delegation_id,
        "tee_delegation_id": delegation_id,
        "status": tee_result.get("status"),
        "to_agent_id": to_agent_id,
        "action": action,
        "request_hash": tee_authorization_request_hash(to_agent_id, action, parameters),
        "credential_fingerprint": tee_result.get("credential_fingerprint"),
    }
    proof = gateway_identity.sign_action(RECEIPT_ACTION, delegation_id, data=body)
    return {
        **body,
        "gateway_public_key_hex": proof["public_key_hex"],
        "gateway_proof": proof,
    }


def verify_tee_authorization_receipt(
    receipt: Dict[str, Any],
    expected_gateway_pubkey_hex: str,
    expected_delegation_id: str,
    expected_to_agent_id: str,
    expected_action: str,
    expected_parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate that a signed receipt authorizes exactly this worker request."""
    if not isinstance(receipt, dict):
        raise RuntimeError("TEE authorization receipt missing")

    body = _receipt_body(receipt)
    if body["v"] != RECEIPT_VERSION:
        raise RuntimeError("TEE authorization receipt version invalid")
    if body["status"] != "ROUTED":
        raise RuntimeError("TEE authorization receipt status is not ROUTED")
    if body["delegation_id"] != expected_delegation_id:
        raise RuntimeError("TEE authorization delegation_id mismatch")
    if body["tee_delegation_id"] != expected_delegation_id:
        raise RuntimeError("TEE authorization TEE delegation_id mismatch")
    if body["to_agent_id"] != expected_to_agent_id:
        raise RuntimeError("TEE authorization target mismatch")
    if body["action"] != expected_action:
        raise RuntimeError("TEE authorization action mismatch")
    if not body["credential_fingerprint"]:
        raise RuntimeError("TEE authorization credential fingerprint missing")

    if expected_parameters is not None:
        expected_hash = tee_authorization_request_hash(
            expected_to_agent_id,
            expected_action,
            expected_parameters,
        )
        if body["request_hash"] != expected_hash:
            raise RuntimeError("TEE authorization request_hash mismatch")

    proof = receipt.get("gateway_proof")
    if not isinstance(proof, dict):
        raise RuntimeError("TEE authorization gateway proof missing")
    if receipt.get("gateway_public_key_hex") != expected_gateway_pubkey_hex:
        raise RuntimeError("TEE authorization gateway key mismatch")
    if proof.get("public_key_hex") != expected_gateway_pubkey_hex:
        raise RuntimeError("TEE authorization proof signer mismatch")

    ok, err = verify_action_request(proof, RECEIPT_ACTION)
    if not ok:
        raise RuntimeError("TEE authorization proof invalid: " + str(err))
    if proof.get("data_hash") != _sha256(_canonical(body)):
        raise RuntimeError("TEE authorization body does not match signed hash")

    return deepcopy(receipt)
