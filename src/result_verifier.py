from src.terminal3_agent_auth_adapter import verify_action_request, _canonical, _sha256

_seen = set()

def verify_worker_result(proof, expected_worker_id, expected_delegation_id, coordinator_id):
    ok, err = verify_action_request(proof, 'TASK_RESULT')
    if not ok:
        raise RuntimeError('worker result signature invalid: ' + str(err))
    if proof.get('agent_id') != expected_worker_id:
        raise RuntimeError('worker result signer is not the expected worker')
    rd = proof.get('result_data') or {}
    if proof.get('data_hash') != _sha256(_canonical(rd)):
        raise RuntimeError('worker result_data does not match signed data_hash')
    if rd.get('from_agent_id') != expected_worker_id:
        raise RuntimeError('result from_agent_id mismatch')
    if rd.get('to_agent_id') != coordinator_id:
        raise RuntimeError('result audience is not the coordinator')
    if rd.get('delegation_id') != expected_delegation_id:
        raise RuntimeError('result delegation_id mismatch')
    if rd.get('status') != 'COMPLETED':
        raise RuntimeError('result status not COMPLETED')
    rn = rd.get('nonce')
    if not rn or rn in _seen:
        raise RuntimeError('result nonce missing or already consumed')
    _seen.add(rn)
    return rd