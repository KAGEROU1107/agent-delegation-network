/**
 * Python ADN subprocess runner.
 *
 * Live execution now uses a strict three-step handoff:
 *   1. Prepare Python worker identities and return their stable IDs.
 *   2. Obtain real T3N delegate-task authorization for those exact IDs.
 *   3. Execute Python work only with the prepared identities and typed T3N results.
 *
 * Security: no secret or path material is interpolated into command strings.
 * All values flow through the subprocess environment only.
 */

import { spawn } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";
import { randomBytes } from "crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ADN_ROOT = join(__dirname, "../../");

export interface AdnDelegationResult {
  success: boolean;
  tenantDid: string;
  coordinatorDid: string;
  recordsProcessed: number;
  totalRevenue: number;
  avgValue: number;
  qualityScore: number;
  qualityPassed: boolean;
  uniqueIdentities: number;
}

export interface PreparedAdnIdentity {
  agentId: string;
  did: string;
  publicKeyHex: string;
  privateKeyHex: string;
}

export interface PreparedAdnExecution {
  tenantDid: string;
  coordinator: PreparedAdnIdentity;
  worker1: PreparedAdnIdentity;
  worker2: PreparedAdnIdentity;
  validator: PreparedAdnIdentity;
  gateway: PreparedAdnIdentity;
}

export interface TeeAuthorizationResult {
  delegation_id: string;
  status: string;
  routed_to: string;
  credential_fingerprint: string;
  credential_enforced: boolean;
  build_config_id: string;
}

export interface TeeAuthorizationBundle {
  processData?: TeeAuthorizationResult;
  validateQuality?: TeeAuthorizationResult;
  buildConfigId?: string;
}

export interface RunAdnDeps {
  spawnImpl?: typeof spawn;
  pythonExecutable?: string;
}

const RUNNER_SCRIPT = `
import sys, os, json, secrets, logging, csv, statistics
from pathlib import Path

ADN_ROOT = os.environ['ADN_ROOT']
tenant_did = os.environ['DID']
mode = os.environ.get('ADN_RUN_MODE', 'execute')

sys.path.insert(0, ADN_ROOT)
logging.disable(9999)

from src.agent_delegation_network import create_agent
from src.result_verifier import verify_worker_result
from src.tee_authorization import build_tee_authorization_receipt


def make_identity(name, private_key_hex=None):
    private_key_hex = private_key_hex or secrets.token_hex(32)
    agent = create_agent(name, private_key_hex=private_key_hex)
    packet = {
        'agentId': agent.identity.agent_id,
        'did': agent.identity.did,
        'publicKeyHex': agent.identity.public_key_hex,
        'privateKeyHex': private_key_hex,
    }
    return agent, packet


def restore_identity(name, identity_bundle):
    packet = identity_bundle.get(name) or {}
    private_key_hex = packet.get('privateKeyHex')
    if not private_key_hex:
        raise RuntimeError(f'{name} private key bundle missing')
    agent = create_agent(name, private_key_hex=private_key_hex)
    if agent.identity.agent_id != packet.get('agentId'):
        raise RuntimeError(f'{name} agentId mismatch')
    if agent.identity.public_key_hex != packet.get('publicKeyHex'):
        raise RuntimeError(f'{name} publicKeyHex mismatch')
    return agent


def load_amounts():
    data_dir = Path(ADN_ROOT) / 'data'
    csv_files = list(data_dir.glob('sales_*.csv'))
    csv_path = csv_files[0] if csv_files else None
    amounts = []
    if csv_path:
        with csv_path.open() as handle:
            for row in csv.DictReader(handle):
                if row.get('sale_amount'):
                    amounts.append(float(row['sale_amount']))
    return csv_path, amounts


def require_authorization_result(name, tee_bundle, expected_worker_id, expected_build_config_id):
    result = tee_bundle.get(name)
    if not result:
        raise RuntimeError(f'{name} TEE authorization bundle is required')
    if result.get('status') != 'ROUTED':
        raise RuntimeError(f'{name} TEE authorization status must be ROUTED')
    if result.get('routed_to') != expected_worker_id:
        raise RuntimeError(f'{name} routed_to mismatch')
    if result.get('credential_enforced') is not True:
        raise RuntimeError(f'{name} credential_enforced must be true')
    if not result.get('credential_fingerprint'):
        raise RuntimeError(f'{name} credential fingerprint missing')
    if not result.get('build_config_id'):
        raise RuntimeError(f'{name} build_config_id missing')
    if result.get('build_config_id') != expected_build_config_id:
        raise RuntimeError(f'{name} build_config_id mismatch')
    return result


if mode == 'prepare':
    coordinator, coordinator_packet = make_identity('coordinator')
    worker1, worker1_packet = make_identity('worker1')
    worker2, worker2_packet = make_identity('worker2')
    validator, validator_packet = make_identity('validator')
    gateway, gateway_packet = make_identity('gateway')
    print(json.dumps({
        'tenantDid': tenant_did,
        'coordinator': coordinator_packet,
        'worker1': worker1_packet,
        'worker2': worker2_packet,
        'validator': validator_packet,
        'gateway': gateway_packet,
    }))
    raise SystemExit(0)

identity_bundle = json.loads(os.environ['ADN_IDENTITY_BUNDLE_JSON'])
tee_bundle = json.loads(os.environ['TEE_AUTHORIZATION_BUNDLE_JSON'])
trusted_gateway_public_key_hex = os.environ.get('ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX', '')
expected_build_config_id = tee_bundle.get('buildConfigId') or ''

if identity_bundle.get('tenantDid') != tenant_did:
    raise RuntimeError('Prepared tenant DID mismatch')
if not trusted_gateway_public_key_hex:
    raise RuntimeError('Trusted gateway public key is required')
if not expected_build_config_id:
    raise RuntimeError('TEE authorization buildConfigId is required')

coordinator = restore_identity('coordinator', identity_bundle)
worker1 = restore_identity('worker1', identity_bundle)
worker2 = restore_identity('worker2', identity_bundle)
validator = restore_identity('validator', identity_bundle)
gateway = restore_identity('gateway', identity_bundle)

if gateway.identity.public_key_hex != trusted_gateway_public_key_hex:
    raise RuntimeError('Trusted gateway public key mismatch')

unique_ids = len({
    coordinator.identity.agent_id,
    worker1.identity.agent_id,
    worker2.identity.agent_id,
    validator.identity.agent_id,
})

csv_path, amounts = load_amounts()

coord_id = coordinator.identity.agent_id
w1_id = worker1.identity.agent_id
val_id = validator.identity.agent_id

coordinator.policy_engine.policy.add_delegation_rule(coord_id, 'PROCESS_DATA')
coordinator.policy_engine.policy.add_delegation_rule(coord_id, 'VALIDATE_QUALITY')
coordinator.policy_engine.policy.add_trust_relationship(coord_id, w1_id)
coordinator.policy_engine.policy.add_trust_relationship(coord_id, val_id)
coordinator.policy_engine.policy.add_delegation_rule(w1_id, 'PROCESS_DATA')
coordinator.policy_engine.policy.add_delegation_rule(val_id, 'VALIDATE_QUALITY')

worker1.policy_engine.policy.add_delegation_rule(coord_id, 'PROCESS_DATA')
worker1.policy_engine.policy.add_trust_relationship(coord_id, w1_id)
worker1.policy_engine.policy.add_delegation_rule(w1_id, 'PROCESS_DATA')
validator.policy_engine.policy.add_delegation_rule(coord_id, 'VALIDATE_QUALITY')
validator.policy_engine.policy.add_trust_relationship(coord_id, val_id)
validator.policy_engine.policy.add_delegation_rule(val_id, 'VALIDATE_QUALITY')


def process_handler(payload):
    total = round(sum(amounts), 2) if amounts else 0
    avg = round(statistics.mean(amounts), 2) if amounts else 0
    trend = 'UPWARD' if len(amounts) >= 2 and amounts[-1] > amounts[0] else 'STABLE'
    return {'status': 'success', 'processed_data': {
        'records_processed': len(amounts),
        'total_revenue': total,
        'avg_value': avg,
        'min_value': round(min(amounts), 2) if amounts else 0,
        'max_value': round(max(amounts), 2) if amounts else 0,
        'trend': trend,
        'csv_file': csv_path.name if csv_path else 'none',
    }}


def validate_handler(payload):
    data = payload.get('data', {})
    score = 1.0
    if not data.get('records_processed'):
        score -= 0.4
    if not data.get('avg_value'):
        score -= 0.3
    if not data.get('csv_file'):
        score -= 0.1
    score = max(0.0, round(score, 2))
    return {'status': 'success', 'quality_score': score, 'passed': score >= 0.8, 'issues': []}


worker1.register_task_handler('PROCESS_DATA', process_handler)
validator.register_task_handler('VALIDATE_QUALITY', validate_handler)

params1 = {'data_source': 'csv', 'time_period': 'Q1-2026', 'filters': []}
process_auth_result = require_authorization_result('processData', tee_bundle, w1_id, expected_build_config_id)
auth1 = build_tee_authorization_receipt(
    gateway_identity=gateway.identity,
    tee_result=process_auth_result,
    action='PROCESS_DATA',
    parameters=params1,
)
did1 = coordinator.delegate_task(w1_id, 'PROCESS_DATA', 'process sales data', params1, tee_authorization=auth1)
req1 = coordinator._delegations[did1]
sig1 = req1.to_action_request(coordinator.identity)
res1 = worker1.process_delegation_request(
    sig1,
    expected_gateway_public_key_hex=trusted_gateway_public_key_hex,
    expected_build_config_id=expected_build_config_id,
)
rd1 = verify_worker_result(
    res1,
    w1_id,
    worker1.identity.public_key_hex,
    did1,
    coord_id,
    expected_tee_authorization=auth1,
    expected_gateway_public_key_hex=trusted_gateway_public_key_hex,
    expected_action='PROCESS_DATA',
    expected_parameters=params1,
    expected_build_config_id=expected_build_config_id,
)
processed_data = (rd1.get('result') or {}).get('processed_data', {})
if not processed_data:
    raise RuntimeError(
        'worker1 returned no processed_data - status: ' +
        str(res1['result_data'].get('status')) +
        ' error: ' + str(res1['result_data'].get('error'))
    )

params2 = {'data': processed_data}
validate_auth_result = require_authorization_result('validateQuality', tee_bundle, val_id, expected_build_config_id)
auth2 = build_tee_authorization_receipt(
    gateway_identity=gateway.identity,
    tee_result=validate_auth_result,
    action='VALIDATE_QUALITY',
    parameters=params2,
)
did2 = coordinator.delegate_task(val_id, 'VALIDATE_QUALITY', 'validate data quality', params2, tee_authorization=auth2)
req2 = coordinator._delegations[did2]
sig2 = req2.to_action_request(coordinator.identity)
res2 = validator.process_delegation_request(
    sig2,
    expected_gateway_public_key_hex=trusted_gateway_public_key_hex,
    expected_build_config_id=expected_build_config_id,
)
rd2 = verify_worker_result(
    res2,
    val_id,
    validator.identity.public_key_hex,
    did2,
    coord_id,
    expected_tee_authorization=auth2,
    expected_gateway_public_key_hex=trusted_gateway_public_key_hex,
    expected_action='VALIDATE_QUALITY',
    expected_parameters=params2,
    expected_build_config_id=expected_build_config_id,
)
validated_data = rd2.get('result') or {}

print(json.dumps({
    'success': res1['result_data']['status'] == 'COMPLETED' and res2['result_data']['status'] == 'COMPLETED',
    'tenantDid': tenant_did,
    'coordinatorDid': coordinator.identity.did,
    'uniqueIdentities': unique_ids,
    'recordsProcessed': processed_data.get('records_processed', 0),
    'totalRevenue': processed_data.get('total_revenue', 0),
    'avgValue': processed_data.get('avg_value', 0),
    'qualityScore': validated_data.get('quality_score', 0),
    'qualityPassed': bool(validated_data.get('passed', False)),
}))
`;

function runPythonJson<T>(env: Record<string, string>, deps: RunAdnDeps = {}): Promise<T> {
  const tmpFile = join(tmpdir(), `adn_run_${randomBytes(8).toString("hex")}.py`);
  const spawnImpl = deps.spawnImpl ?? spawn;
  const pythonExecutable = deps.pythonExecutable ?? "python3";

  return new Promise((resolve, reject) => {
    writeFileSync(tmpFile, RUNNER_SCRIPT, "utf-8");

    const proc = spawnImpl(pythonExecutable, [tmpFile], {
      env: {
        ...process.env,
        ADN_ROOT,
        T3_MOCK: "false",
        ...env,
      },
    });

    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    proc.on("close", (code) => {
      try {
        unlinkSync(tmpFile);
      } catch {
        // Best-effort cleanup only.
      }
      if (code !== 0) {
        reject(new Error(`ADN process failed (exit ${code}):\n${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout.trim()) as T);
      } catch {
        reject(new Error(`ADN output parse error:\n${stdout}\n${stderr}`));
      }
    });
  });
}

export function prepareAdnExecution(
  tenantDid: string,
  deps: RunAdnDeps = {}
): Promise<PreparedAdnExecution> {
  return runPythonJson<PreparedAdnExecution>(
    {
      DID: tenantDid,
      ADN_RUN_MODE: "prepare",
    },
    deps,
  );
}

export function runAdnWithRealDid(
  apiKey: string,
  tenantDid: string,
  preparedExecution: PreparedAdnExecution,
  teeAuthorizationBundle: TeeAuthorizationBundle,
  deps: RunAdnDeps = {},
): Promise<AdnDelegationResult> {
  return runPythonJson<AdnDelegationResult>(
    {
      DID: tenantDid,
      T3N_API_KEY: apiKey,
      ADN_RUN_MODE: "execute",
      ADN_IDENTITY_BUNDLE_JSON: JSON.stringify(preparedExecution),
      ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX: preparedExecution.gateway.publicKeyHex,
      TEE_AUTHORIZATION_BUNDLE_JSON: JSON.stringify(teeAuthorizationBundle),
    },
    deps,
  );
}
