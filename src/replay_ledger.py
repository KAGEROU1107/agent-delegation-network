import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


REQUEST_KIND = "request"
RESULT_KIND = "result"
REQUEST_STATE_RUNNING = "RUNNING"
REQUEST_STATE_COMPLETED = "COMPLETED"
REQUEST_STATE_RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
REQUEST_STATE_FINAL_FAILURE = "FINAL_FAILURE"
RESULT_STATE_CONSUMED = "CONSUMED"
RUNNING_LEASE_SECONDS = 5 * 60
RESULT_REPLAY_TTL_SECONDS = 15 * 60
MAX_REQUEST_ATTEMPTS = 2
_CONNECT_RETRY_ATTEMPTS = 8
_CONNECT_RETRY_DELAY_SECONDS = 0.05
_INTEGRITY_DOMAIN_PREFIX = "adn.replay-ledger.integrity"


def _best_effort_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _ledger_dir() -> Path:
    configured = os.environ.get("ADN_REPLAY_LEDGER_DIR", "").strip()
    if configured:
        base = Path(configured)
    else:
        base = Path(tempfile.gettempdir()) / "adn_replay_ledger"
    base.mkdir(parents=True, exist_ok=True)
    _best_effort_chmod(base, 0o700)
    return base


def _ledger_db_path() -> Path:
    return _ledger_dir() / "replay_ledger.sqlite3"


def _connect() -> sqlite3.Connection:
    db_path = _ledger_db_path()
    last_error: Optional[sqlite3.OperationalError] = None
    for attempt in range(_CONNECT_RETRY_ATTEMPTS):
        conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_entries (
                    replay_key TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    first_seen_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    owner_agent_id TEXT,
                    delegation_id TEXT,
                    payload_fingerprint TEXT,
                    integrity_mac TEXT,
                    last_error TEXT,
                    execution_token TEXT
                )
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(replay_entries)").fetchall()
            }
            if "execution_token" not in columns:
                conn.execute("ALTER TABLE replay_entries ADD COLUMN execution_token TEXT")
            _best_effort_chmod(db_path, 0o600)
            return conn
        except sqlite3.OperationalError as exc:
            conn.close()
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            last_error = exc
            time.sleep(_CONNECT_RETRY_DELAY_SECONDS * (attempt + 1))
    if last_error is not None:
        raise last_error
    raise RuntimeError("Unable to open replay ledger")


def _stable_record_payload(record: Dict[str, Any]) -> str:
    body = {
        "replay_key": record.get("replay_key"),
        "kind": record.get("kind"),
        "state": record.get("state"),
        "attempt_count": record.get("attempt_count"),
        "max_attempts": record.get("max_attempts"),
        "first_seen_at": record.get("first_seen_at"),
        "updated_at": record.get("updated_at"),
        "expires_at": record.get("expires_at"),
        "owner_agent_id": record.get("owner_agent_id"),
        "delegation_id": record.get("delegation_id"),
        "payload_fingerprint": record.get("payload_fingerprint"),
        "last_error": record.get("last_error"),
        "execution_token": record.get("execution_token"),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _compute_integrity_mac(record: Dict[str, Any], integrity_secret_hex: Optional[str]) -> Optional[str]:
    if not integrity_secret_hex:
        return None
    secret = bytes.fromhex(integrity_secret_hex)
    return hmac.new(secret, _stable_record_payload(record).encode("utf-8"), hashlib.sha256).hexdigest()


def derive_integrity_key(secret_hex: Optional[str], domain: str) -> Optional[str]:
    if not secret_hex:
        return None
    secret = bytes.fromhex(secret_hex)
    label = f"{_INTEGRITY_DOMAIN_PREFIX}.{domain}".encode("utf-8")
    return hmac.new(secret, label, hashlib.sha256).hexdigest()


def _configured_integrity_secret_hex() -> Optional[str]:
    raw_env_secret = os.environ.get("ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX", "").strip()
    key_file = os.environ.get("ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE", "").strip()
    runtime_mode = os.environ.get("ADN_RUNTIME_MODE", "").strip().lower()
    if runtime_mode == "live" and raw_env_secret:
        raise RuntimeError("ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX is not accepted in live mode")
    if key_file:
        return Path(key_file).read_text(encoding="utf-8").strip().removeprefix("0x").lower()
    return raw_env_secret.removeprefix("0x").lower() or None


def configured_integrity_key(domain: str) -> Optional[str]:
    return derive_integrity_key(
        _configured_integrity_secret_hex(),
        domain,
    )


def _verify_integrity(record: sqlite3.Row, integrity_secret_hex: Optional[str]) -> None:
    if not integrity_secret_hex:
        return
    expected = _compute_integrity_mac(dict(record), integrity_secret_hex)
    actual = record["integrity_mac"]
    if not actual or not hmac.compare_digest(actual, expected or ""):
        raise RuntimeError("Replay ledger integrity check failed")


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _write_record(
    conn: sqlite3.Connection,
    replay_key: str,
    kind: str,
    state: str,
    attempt_count: int,
    max_attempts: int,
    first_seen_at: float,
    updated_at: float,
    expires_at: float,
    owner_agent_id: str,
    delegation_id: str,
    payload_fingerprint: str,
    integrity_secret_hex: Optional[str],
    last_error: Optional[str] = None,
    execution_token: Optional[str] = None,
) -> None:
    record = {
        "replay_key": replay_key,
        "kind": kind,
        "state": state,
        "attempt_count": attempt_count,
        "max_attempts": max_attempts,
        "first_seen_at": first_seen_at,
        "updated_at": updated_at,
        "expires_at": expires_at,
        "owner_agent_id": owner_agent_id,
        "delegation_id": delegation_id,
        "payload_fingerprint": payload_fingerprint,
        "last_error": last_error,
        "execution_token": execution_token,
    }
    record["integrity_mac"] = _compute_integrity_mac(record, integrity_secret_hex)
    conn.execute(
        """
        INSERT INTO replay_entries (
            replay_key, kind, state, attempt_count, max_attempts, first_seen_at,
            updated_at, expires_at, owner_agent_id, delegation_id, payload_fingerprint,
            integrity_mac, last_error, execution_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(replay_key) DO UPDATE SET
            kind=excluded.kind,
            state=excluded.state,
            attempt_count=excluded.attempt_count,
            max_attempts=excluded.max_attempts,
            first_seen_at=excluded.first_seen_at,
            updated_at=excluded.updated_at,
            expires_at=excluded.expires_at,
            owner_agent_id=excluded.owner_agent_id,
            delegation_id=excluded.delegation_id,
            payload_fingerprint=excluded.payload_fingerprint,
            integrity_mac=excluded.integrity_mac,
            last_error=excluded.last_error,
            execution_token=excluded.execution_token
        """,
        (
            replay_key,
            kind,
            state,
            attempt_count,
            max_attempts,
            first_seen_at,
            updated_at,
            expires_at,
            owner_agent_id,
            delegation_id,
            payload_fingerprint,
            record["integrity_mac"],
            last_error,
            execution_token,
        ),
    )


def begin_request_execution(
    replay_key: str,
    replay_expires_at: float,
    owner_agent_id: str,
    delegation_id: str,
    payload_fingerprint: str,
    integrity_secret_hex: Optional[str],
) -> Tuple[bool, str, Optional[str]]:
    if not replay_key:
        return False, "Delegation request replay key missing", None

    now_ts = time.time()
    execution_token = secrets.token_hex(16)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM replay_entries WHERE expires_at <= ?", (now_ts,))
        row = conn.execute(
            "SELECT * FROM replay_entries WHERE replay_key = ?",
            (replay_key,),
        ).fetchone()

        if row is None:
            _write_record(
                conn,
                replay_key=replay_key,
                kind=REQUEST_KIND,
                state=REQUEST_STATE_RUNNING,
                attempt_count=1,
                max_attempts=MAX_REQUEST_ATTEMPTS,
                first_seen_at=now_ts,
                updated_at=now_ts,
                expires_at=replay_expires_at,
                owner_agent_id=owner_agent_id,
                delegation_id=delegation_id,
                payload_fingerprint=payload_fingerprint,
                integrity_secret_hex=integrity_secret_hex,
                execution_token=execution_token,
            )
            conn.commit()
            return True, "", execution_token

        _verify_integrity(row, integrity_secret_hex)
        existing = _row_to_dict(row)
        state = existing["state"]
        attempt_count = int(existing["attempt_count"])
        max_attempts = int(existing["max_attempts"])
        first_seen_at = float(existing["first_seen_at"])
        updated_at = float(existing["updated_at"])
        expires_at = min(float(existing["expires_at"]), replay_expires_at)

        if state == REQUEST_STATE_COMPLETED:
            conn.commit()
            return False, "Delegation request replay detected", None
        if state == REQUEST_STATE_FINAL_FAILURE:
            conn.commit()
            return False, "Delegation request reached final failure", None
        if state == REQUEST_STATE_RUNNING and (now_ts - updated_at) < RUNNING_LEASE_SECONDS:
            conn.commit()
            return False, "Delegation request already running", None
        if attempt_count >= max_attempts:
            _write_record(
                conn,
                replay_key=replay_key,
                kind=REQUEST_KIND,
                state=REQUEST_STATE_FINAL_FAILURE,
                attempt_count=attempt_count,
                max_attempts=max_attempts,
                first_seen_at=first_seen_at,
                updated_at=now_ts,
                expires_at=expires_at,
                owner_agent_id=owner_agent_id,
                delegation_id=delegation_id,
                payload_fingerprint=payload_fingerprint,
                integrity_secret_hex=integrity_secret_hex,
                last_error="Delegation request retry limit exceeded",
                execution_token=None,
            )
            conn.commit()
            return False, "Delegation request retry limit exceeded", None

        _write_record(
            conn,
            replay_key=replay_key,
            kind=REQUEST_KIND,
            state=REQUEST_STATE_RUNNING,
            attempt_count=attempt_count + 1,
            max_attempts=max_attempts,
            first_seen_at=first_seen_at,
            updated_at=now_ts,
            expires_at=expires_at,
            owner_agent_id=owner_agent_id,
            delegation_id=delegation_id,
            payload_fingerprint=payload_fingerprint,
            integrity_secret_hex=integrity_secret_hex,
            execution_token=execution_token,
        )
        conn.commit()
        return True, "", execution_token
    finally:
        conn.close()


def heartbeat_request_execution(
    replay_key: str,
    integrity_secret_hex: Optional[str],
    execution_token: Optional[str],
) -> bool:
    if not replay_key:
        return False
    now_ts = time.time()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM replay_entries WHERE replay_key = ?",
            (replay_key,),
        ).fetchone()
        if row is None:
            conn.commit()
            return False
        _verify_integrity(row, integrity_secret_hex)
        existing = _row_to_dict(row)
        if existing["state"] != REQUEST_STATE_RUNNING:
            conn.commit()
            return False
        existing_token = existing.get("execution_token")
        if existing_token and existing_token != execution_token:
            conn.commit()
            return False
        _write_record(
            conn,
            replay_key=replay_key,
            kind=REQUEST_KIND,
            state=REQUEST_STATE_RUNNING,
            attempt_count=int(existing["attempt_count"]),
            max_attempts=int(existing["max_attempts"]),
            first_seen_at=float(existing["first_seen_at"]),
            updated_at=now_ts,
            expires_at=float(existing["expires_at"]),
            owner_agent_id=existing.get("owner_agent_id") or "",
            delegation_id=existing.get("delegation_id") or "",
            payload_fingerprint=existing.get("payload_fingerprint") or "",
            integrity_secret_hex=integrity_secret_hex,
            last_error=existing.get("last_error"),
            execution_token=existing.get("execution_token"),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def finalize_request_execution(
    replay_key: str,
    final_state: str,
    integrity_secret_hex: Optional[str],
    last_error: Optional[str] = None,
    execution_token: Optional[str] = None,
) -> bool:
    if not replay_key:
        return False
    now_ts = time.time()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM replay_entries WHERE replay_key = ?",
            (replay_key,),
        ).fetchone()
        if row is None:
            conn.commit()
            return False
        _verify_integrity(row, integrity_secret_hex)
        existing = _row_to_dict(row)
        existing_token = existing.get("execution_token")
        if existing_token and existing_token != execution_token:
            conn.commit()
            return False
        next_state = final_state
        if final_state == REQUEST_STATE_RETRYABLE_FAILURE and int(existing["attempt_count"]) >= int(existing["max_attempts"]):
            next_state = REQUEST_STATE_FINAL_FAILURE
            last_error = last_error or "Delegation request retry limit exceeded"
        _write_record(
            conn,
            replay_key=replay_key,
            kind=REQUEST_KIND,
            state=next_state,
            attempt_count=int(existing["attempt_count"]),
            max_attempts=int(existing["max_attempts"]),
            first_seen_at=float(existing["first_seen_at"]),
            updated_at=now_ts,
            expires_at=float(existing["expires_at"]),
            owner_agent_id=existing.get("owner_agent_id") or "",
            delegation_id=existing.get("delegation_id") or "",
            payload_fingerprint=existing.get("payload_fingerprint") or "",
            integrity_secret_hex=integrity_secret_hex,
            last_error=last_error,
            execution_token=None,
        )
        conn.commit()
        return True
    finally:
        conn.close()


def consume_result_replay(
    replay_key: str,
    owner_agent_id: str,
    delegation_id: str,
    payload_fingerprint: str,
    expires_at: Optional[float] = None,
    integrity_secret_hex: Optional[str] = None,
) -> Tuple[bool, str]:
    if not replay_key:
        return False, "result replay key missing"
    if not integrity_secret_hex:
        return False, "result replay integrity key missing"

    now_ts = time.time()
    effective_expires_at = float(expires_at or (now_ts + RESULT_REPLAY_TTL_SECONDS))
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM replay_entries WHERE expires_at <= ?", (now_ts,))
        row = conn.execute(
            "SELECT * FROM replay_entries WHERE replay_key = ?",
            (replay_key,),
        ).fetchone()
        if row is not None:
            _verify_integrity(row, integrity_secret_hex)
            conn.commit()
            return False, "result replay already consumed"

        _write_record(
            conn,
            replay_key=replay_key,
            kind=RESULT_KIND,
            state=RESULT_STATE_CONSUMED,
            attempt_count=1,
            max_attempts=1,
            first_seen_at=now_ts,
            updated_at=now_ts,
            expires_at=effective_expires_at,
            owner_agent_id=owner_agent_id,
            delegation_id=delegation_id,
            payload_fingerprint=payload_fingerprint,
            integrity_secret_hex=integrity_secret_hex,
        )
        conn.commit()
        return True, ""
    finally:
        conn.close()
