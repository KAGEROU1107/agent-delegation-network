import json
import hashlib
import uuid
import os
from pathlib import Path

def _scan_for_secrets(data: str) -> bool:
    patterns = [
        "TERMINAL3_API_KEY",
        "T3N_API_KEY",
        "ILMUCHAT_API_KEY",
        "sk-",
        "sk-or-",
        "0xdd99"
    ]
    for pattern in patterns:
        if pattern in data:
            return True
    for env_name in ("T3N_API_KEY", "TERMINAL3_API_KEY"):
        env_key = os.getenv(env_name, "")
        if len(env_key) > 8 and env_key[:8] in data:
            return True
    return False

def build_receipt(decision: dict) -> dict:
    receipt = {
        "receipt_id": "effv3-receipt-" + uuid.uuid4().hex[:12],
        "decision": decision.get("decision"),
        "ts": decision.get("ts"),
        "action": decision.get("action"),
        "agent_fingerprint": decision.get("agent_fingerprint"),
        "denial_code": decision.get("denial_code"),
        "nonce_hash": decision.get("nonce_hash"),
        "proof_hash": decision.get("proof_hash"),
        "policy_version": decision.get("policy_version"),
        "spec_version": "1.0",
        "raw_secret_included": False,
        "authority": "UNTRUSTED_ADVISORY"
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
    receipt["receipt_hash"] = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    return receipt

def save_receipt(receipt: dict, directory: Path = None) -> Path:
    if directory is None:
        directory = Path("demo/sample_sanitized_receipts")
    directory.mkdir(parents=True, exist_ok=True)
    file_path = directory / f"{receipt['receipt_id']}.json"
    serialized = json.dumps(receipt, indent=2)
    if _scan_for_secrets(serialized):
        raise ValueError("SECRET_EXPOSURE_DETECTED: save aborted")
    with file_path.open('w') as f:
        f.write(serialized)
    return file_path

def verify_receipt(receipt: dict) -> bool:
    if "receipt_hash" not in receipt:
        return False
    stored_hash = receipt.pop("receipt_hash")
    canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
    computed_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    receipt["receipt_hash"] = stored_hash
    return stored_hash == computed_hash
