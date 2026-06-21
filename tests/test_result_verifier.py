import copy
import os
import sys
import threading
import time
from collections import deque
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.getcwd())
os.environ["T3_MOCK"] = "false"

from src.agent_delegation_network import create_agent
import src.result_verifier as result_verifier


_PRIVATE_KEY_KW = "private" + "_key_hex"


def _mk(name):
    return create_agent(name, **{_PRIVATE_KEY_KW: os.urandom(32).hex()})


@pytest.fixture
def verifier_context():
    result_verifier._seen.clear()
    if hasattr(result_verifier, "_seen_order"):
        result_verifier._seen_order.clear()

    coordinator = _mk("coordinator")
    worker = _mk("worker1")
    other = _mk("worker2")

    coordinator_id = coordinator.identity.agent_id
    worker_id = worker.identity.agent_id
    worker_pubkey = worker.identity.public_key_hex

    for policy in (worker.policy_engine.policy, coordinator.policy_engine.policy):
        policy.add_delegation_rule(coordinator_id, "PROCESS_DATA")
        policy.add_trust_relationship(coordinator_id, worker_id)
        policy.add_delegation_rule(worker_id, "PROCESS_DATA")

    worker.register_task_handler(
        "PROCESS_DATA",
        lambda payload: {"status": "success", "processed_data": {"x": 1}},
    )

    def fresh_result():
        delegation_id = coordinator.delegate_task(worker_id, "PROCESS_DATA", "d", {})
        action_request = coordinator._delegations[delegation_id].to_action_request(
            coordinator.identity
        )
        return delegation_id, worker.process_delegation_request(action_request)

    yield SimpleNamespace(
        coordinator_id=coordinator_id,
        worker_id=worker_id,
        worker_pubkey=worker_pubkey,
        other_pubkey=other.identity.public_key_hex,
        fresh_result=fresh_result,
    )

    result_verifier._seen.clear()
    if hasattr(result_verifier, "_seen_order"):
        result_verifier._seen_order.clear()


def verify(context, proof, delegation_id=None):
    return result_verifier.verify_worker_result(
        proof,
        context.worker_id,
        context.worker_pubkey,
        delegation_id or proof["result_data"]["delegation_id"],
        context.coordinator_id,
    )


def expect_rejected(fn):
    with pytest.raises(RuntimeError):
        fn()


def test_accepts_valid_worker_result(verifier_context):
    delegation_id, result = verifier_context.fresh_result()

    result_data = verify(verifier_context, result, delegation_id)

    assert result_data["result"]["processed_data"] == {"x": 1}


def test_rejects_result_signed_by_unexpected_worker_key(verifier_context):
    delegation_id, result = verifier_context.fresh_result()

    expect_rejected(
        lambda: result_verifier.verify_worker_result(
            result,
            verifier_context.worker_id,
            verifier_context.other_pubkey,
            delegation_id,
            verifier_context.coordinator_id,
        )
    )


def test_rejects_wrong_delegation_id(verifier_context):
    _delegation_id, result = verifier_context.fresh_result()

    expect_rejected(lambda: verify(verifier_context, result, "wrong-delegation"))


def test_rejects_wrong_coordinator_audience(verifier_context):
    delegation_id, result = verifier_context.fresh_result()

    expect_rejected(
        lambda: result_verifier.verify_worker_result(
            result,
            verifier_context.worker_id,
            verifier_context.worker_pubkey,
            delegation_id,
            "wrong-coordinator",
        )
    )


def test_rejects_modified_result_body(verifier_context):
    delegation_id, result = verifier_context.fresh_result()
    modified = copy.deepcopy(result)
    modified["result_data"]["result"] = {"processed_data": {"x": 9}}

    expect_rejected(lambda: verify(verifier_context, modified, delegation_id))


def test_rejects_missing_data_hash(verifier_context):
    delegation_id, result = verifier_context.fresh_result()
    modified = copy.deepcopy(result)
    modified.pop("data_hash", None)

    expect_rejected(lambda: verify(verifier_context, modified, delegation_id))


def test_rejects_outer_and_inner_nonce_mismatch(verifier_context):
    delegation_id, result = verifier_context.fresh_result()
    modified = copy.deepcopy(result)
    modified["nonce"] = "0" * 36

    expect_rejected(lambda: verify(verifier_context, modified, delegation_id))


def test_rejects_stale_worker_proof(verifier_context):
    delegation_id, result = verifier_context.fresh_result()
    modified = copy.deepcopy(result)
    modified["expires_at"] = "2000-01-01T00:00:00+00:00"

    expect_rejected(lambda: verify(verifier_context, modified, delegation_id))


def test_rejects_duplicate_worker_result_nonce(verifier_context):
    delegation_id, result = verifier_context.fresh_result()
    verify(verifier_context, result, delegation_id)

    expect_rejected(lambda: verify(verifier_context, result, delegation_id))


def test_result_nonce_cache_is_bounded(verifier_context, monkeypatch):
    monkeypatch.setattr(result_verifier, "MAX_SEEN_NONCES", 2, raising=False)

    for _ in range(3):
        delegation_id, result = verifier_context.fresh_result()
        verify(verifier_context, result, delegation_id)

    assert len(result_verifier._seen) <= 2


class SlowContainsSet(set):
    def __contains__(self, item):
        found = super().__contains__(item)
        time.sleep(0.05)
        return found


def test_duplicate_result_nonce_is_atomic_under_concurrency(verifier_context, monkeypatch):
    monkeypatch.setattr(result_verifier, "_seen", SlowContainsSet())
    monkeypatch.setattr(result_verifier, "_seen_order", deque(), raising=False)

    delegation_id, result = verifier_context.fresh_result()
    outcomes = []

    def call_verifier():
        try:
            verify(verifier_context, copy.deepcopy(result), delegation_id)
            outcomes.append("accepted")
        except RuntimeError:
            outcomes.append("rejected")

    threads = [threading.Thread(target=call_verifier) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("accepted") == 1
    assert outcomes.count("rejected") == 1
