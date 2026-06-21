import threading
import time
from collections import deque

from src.terminal3_agent_auth_adapter import verify_action_request, _canonical, _sha256

MAX_SEEN_NONCES = 4096
SEEN_NONCE_TTL_SECONDS = 15 * 60
_seen = set()
_seen_order = deque()
_seen_lock = threading.Lock()


def _prune_seen_nonces_locked(now):
    cutoff = now - SEEN_NONCE_TTL_SECONDS
    while _seen_order and _seen_order[0][1] <= cutoff:
        nonce, _created_at = _seen_order.popleft()
        _seen.discard(nonce)
    while len(_seen_order) > MAX_SEEN_NONCES:
        nonce, _created_at = _seen_order.popleft()
        _seen.discard(nonce)


def _consume_result_nonce(nonce):
    now = time.monotonic()
    with _seen_lock:
        _prune_seen_nonces_locked(now)
        if not nonce or nonce in _seen:
            raise RuntimeError('result nonce missing or already consumed')
        _seen.add(nonce)
        _seen_order.append((nonce, now))
        _prune_seen_nonces_locked(now)

def verify_worker_result(proof, expected_worker_id, expected_worker_pubkey_hex, expected_delegation_id, coordinator_id):
    ok, err = verify_action_request(proof, 'TASK_RESULT')
    if not ok:
        raise RuntimeError('worker result signature invalid: ' + str(err))
    if proof.get('public_key_hex') != expected_worker_pubkey_hex:
        raise RuntimeError('worker key does not match expected worker')
    if proof.get('agent_id') != expected_worker_id:
        raise RuntimeError('worker result signer is not the expected worker')
    rd = proof.get('result_data') or {}
    if proof.get('data_hash') != _sha256(_canonical(rd)):
        raise RuntimeError('worker result_data does not match signed data_hash')
    if proof.get('nonce') != rd.get('nonce'):
        raise RuntimeError('result nonce inconsistent with signed envelope')
    if rd.get('from_agent_id') != expected_worker_id:
        raise RuntimeError('result from_agent_id mismatch')
    if rd.get('to_agent_id') != coordinator_id:
        raise RuntimeError('result audience is not the coordinator')
    if rd.get('delegation_id') != expected_delegation_id:
        raise RuntimeError('result delegation_id mismatch')
    if rd.get('status') != 'COMPLETED':
        raise RuntimeError('result status not COMPLETED')
    _consume_result_nonce(rd.get('nonce'))
    return rd
