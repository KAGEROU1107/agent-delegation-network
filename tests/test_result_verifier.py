import os, sys, copy
sys.path.insert(0, os.getcwd())
os.environ['T3_MOCK'] = 'false'
from src.agent_delegation_network import create_agent
from src.result_verifier import verify_worker_result
_KW = 'private' + '_key_hex'
def _mk(name): return create_agent(name, **{_KW: os.urandom(32).hex()})
coord = _mk('coordinator'); worker = _mk('worker1'); other = _mk('worker2')
cid, wid = coord.identity.agent_id, worker.identity.agent_id
wpk = worker.identity.public_key_hex
for eng in (worker.policy_engine.policy, coord.policy_engine.policy):
    eng.add_delegation_rule(cid, 'PROCESS_DATA'); eng.add_trust_relationship(cid, wid); eng.add_delegation_rule(wid, 'PROCESS_DATA')
worker.register_task_handler('PROCESS_DATA', lambda p: {'status': 'success', 'processed_data': {'x': 1}})
def _fresh():
    did = coord.delegate_task(wid, 'PROCESS_DATA', 'd', {})
    return did, worker.process_delegation_request(coord._delegations[did].to_action_request(coord.identity))
def _rej(fn, label):
    try: fn(); print('BUG accepted ' + label); sys.exit(1)
    except RuntimeError: print('ok ' + label)
did, res = _fresh(); rd = verify_worker_result(res, wid, wpk, did, cid)
assert rd['result']['processed_data'] == {'x': 1}; print('ok accept')
did, res = _fresh(); _rej(lambda: verify_worker_result(res, wid, other.identity.public_key_hex, did, cid), 'other-key')
did, res = _fresh(); _rej(lambda: verify_worker_result(res, wid, wpk, 'zzz', cid), 'wrong-delegation')
did, res = _fresh(); _rej(lambda: verify_worker_result(res, wid, wpk, did, 'zzz'), 'wrong-aud')
did, res = _fresh(); b = copy.deepcopy(res); b['result_data']['result'] = {'processed_data': {'x': 9}}
_rej(lambda: verify_worker_result(b, wid, wpk, did, cid), 'modified-body')
did, res = _fresh(); b = copy.deepcopy(res); b.pop('data_hash', None)
_rej(lambda: verify_worker_result(b, wid, wpk, did, cid), 'no-data-hash')
did, res = _fresh(); b = copy.deepcopy(res); b['nonce'] = '0'*36
_rej(lambda: verify_worker_result(b, wid, wpk, did, cid), 'nonce-mix')
did, res = _fresh(); b = copy.deepcopy(res); b['expires_at'] = '2000-01-01T00:00:00+00:00'
_rej(lambda: verify_worker_result(b, wid, wpk, did, cid), 'stale-proof')
did, res = _fresh(); verify_worker_result(res, wid, wpk, did, cid)
_rej(lambda: verify_worker_result(res, wid, wpk, did, cid), 'second-use')
print('ALL CASES PASSED')
