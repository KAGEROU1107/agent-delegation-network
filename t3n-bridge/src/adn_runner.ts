/**
 * Python ADN subprocess runner.
 *
 * Live execution uses a strict three-step handoff:
 *   1. Prepare Python worker identities and return their stable IDs.
 *   2. Obtain real T3N delegate-task authorization for those exact IDs.
 *   3. Execute Python work only with the prepared identities, typed T3N results,
 *      and a separately provisioned gateway signing key.
 *
 * Security: the bridge no longer sends private keys or authorization bundles
 * through child stdout or environment JSON blobs. Sensitive material is written
 * to short-lived temp files and cleaned up after the subprocess exits.
 */

import { spawn } from "child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";
import { randomBytes } from "crypto";
import {
  getRuntimeMode,
  requireHexEnv,
  requireReplayLedgerDir,
  resolveReplayKeyProvider,
} from "./runtime_config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ADN_ROOT = join(__dirname, "../../");

export interface AdnDelegationResult {
  success: boolean;
  replayMode: "durable-live" | "durable-test" | "non-durable-demo";
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
}

export interface GatewayKeyBundle {
  gatewayKeyId: string;
  publicKeyHex: string;
  privateKeyHex: string;
}

export interface TeeAuthorizationResult {
  delegation_id: string;
  status: string;
  routed_to: string;
  credential_fingerprint: string;
  credential_enforced: boolean;
  build_config_id: string;
  authorization_expires_at: string;
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
from src.runtime_security import resolve_runtime_mode
from src.tee_authorization import build_tee_authorization_receipt

runtime_mode = resolve_runtime_mode()


def write_output(payload):
    output_path = os.environ.get('ADN_OUTPUT_PATH', '')
    if not output_path:
        raise RuntimeError('ADN_OUTPUT_PATH is required')
    Path(output_path).write_text(json.dumps(payload), encoding='utf-8')
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass


def load_json_file(env_name):
    input_path = os.environ.get(env_name, '')
    if not input_path:
        raise RuntimeError(f'{env_name} is required')
    return json.loads(Path(input_path).read_text(encoding='utf-8'))


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


def restore_identity(name, packet):
    private_key_hex = (packet or {}).get('privateKeyHex')
    if not private_key_hex:
        raise RuntimeError(f'{name} private key bundle missing')
    agent = create_agent(name, private_key_hex=private_key_hex)
    if agent.identity.agent_id != packet.get('agentId'):
        raise RuntimeError(f'{name} agentId mismatch')
    if agent.identity.public_key_hex != packet.get('publicKeyHex'):
        raise RuntimeError(f'{name} publicKeyHex mismatch')
    return agent


def restore_gateway_identity(gateway_bundle):
    private_key_hex = (gateway_bundle or {}).get('privateKeyHex')
    if not private_key_hex:
        raise RuntimeError('gateway private key bundle missing')
    gateway = create_agent('gateway', private_key_hex=private_key_hex)
    if gateway.identity.public_key_hex != gateway_bundle.get('publicKeyHex'):
        raise RuntimeError('Trusted gateway public key mismatch')
    return gateway


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
    if not result.get('authorization_expires_at'):
        raise RuntimeError(f'{name} authorization_expires_at missing')
    return result


if mode == 'prepare':
    coordinator, coordinator_packet = make_identity('coordinator')
    worker1, worker1_packet = make_identity('worker1')
    worker2, worker2_packet = make_identity('worker2')
    validator, validator_packet = make_identity('validator')
    write_output({
        'tenantDid': tenant_did,
        'coordinator': coordinator_packet,
        'worker1': worker1_packet,
        'worker2': worker2_packet,
        'validator': validator_packet,
    })
    print(json.dumps({'status': 'prepared'}))
    raise SystemExit(0)

if mode == 'prepare_gateway':
    gateway, gateway_packet = make_identity('gateway')
    gateway_key_id = os.environ.get('ADN_GATEWAY_KEY_ID', '') or f"gateway-{gateway.identity.agent_id}"
    write_output({
        'gatewayKeyId': gateway_key_id,
        'publicKeyHex': gateway_packet['publicKeyHex'],
        'privateKeyHex': gateway_packet['privateKeyHex'],
    })
    print(json.dumps({'status': 'prepared_gateway'}))
    raise SystemExit(0)

identity_bundle = load_json_file('ADN_IDENTITY_BUNDLE_PATH')
tee_bundle = load_json_file('TEE_AUTHORIZATION_BUNDLE_PATH')

# Phase 2: prefer pre-signed receipts (private key isolated in executor)
_pre_signed_path = os.environ.get('ADN_PRE_SIGNED_RECEIPTS_PATH', '')
if _pre_signed_path:
    pre_signed_bundle = load_json_file('ADN_PRE_SIGNED_RECEIPTS_PATH')
    gateway_key_bundle = None
else:
    gateway_key_bundle = load_json_file('ADN_GATEWAY_KEY_BUNDLE_PATH')
    pre_signed_bundle = None

if identity_bundle.get('tenantDid') != tenant_did:
    raise RuntimeError('Prepared tenant DID mismatch')

if pre_signed_bundle is not None:
    trusted_gateway_public_key_hex = pre_signed_bundle.get('publicKeyHex', '')
    trusted_gateway_key_id = pre_signed_bundle.get('gatewayKeyId', '')
else:
    trusted_gateway_public_key_hex = gateway_key_bundle.get('publicKeyHex', '')
    trusted_gateway_key_id = gateway_key_bundle.get('gatewayKeyId', '')
expected_build_config_id = tee_bundle.get('buildConfigId') or ''

if not trusted_gateway_public_key_hex:
    raise RuntimeError('Trusted gateway public key is required')
if not trusted_gateway_key_id:
    raise RuntimeError('Trusted gateway key id is required')
if not expected_build_config_id:
    raise RuntimeError('TEE authorization buildConfigId is required')

coordinator = restore_identity('coordinator', identity_bundle.get('coordinator'))
worker1 = restore_identity('worker1', identity_bundle.get('worker1'))
worker2 = restore_identity('worker2', identity_bundle.get('worker2'))
validator = restore_identity('validator', identity_bundle.get('validator'))
# Phase 2: no private key in Python when pre-signed receipts are provided
gateway = None if pre_signed_bundle is not None else restore_gateway_identity({
    'publicKeyHex': trusted_gateway_public_key_hex,
    'privateKeyHex': gateway_key_bundle.get('privateKeyHex'),
})

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

phase = os.environ.get('ADN_EXECUTION_PHASE', 'full')

if phase == 'process':
    params1 = {'data_source': 'csv', 'time_period': 'Q1-2026', 'filters': []}
    process_auth_result = require_authorization_result('processData', tee_bundle, w1_id, expected_build_config_id)
    auth1 = pre_signed_bundle.get('processDataReceipt')
    if not auth1:
        raise RuntimeError('processDataReceipt missing from pre-signed bundle')
    did1 = coordinator.delegate_task(w1_id, 'PROCESS_DATA', 'process sales data', params1, tee_authorization=auth1)
    req1 = coordinator._delegations[did1]
    sig1 = req1.to_action_request(coordinator.identity)
    res1 = worker1.process_delegation_request(
        sig1,
        expected_gateway_public_key_hex=trusted_gateway_public_key_hex,
        expected_gateway_key_id=trusted_gateway_key_id,
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
        expected_gateway_key_id=trusted_gateway_key_id,
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
    print(json.dumps({
        'phase': 'process',
        'process_succeeded': res1['result_data']['status'] == 'COMPLETED',
        'processed_data': processed_data,
    }))

elif phase == 'validate':
    processed_data_path_env = os.environ.get('ADN_PROCESSED_DATA_PATH', '')
    if not processed_data_path_env:
        raise RuntimeError('ADN_PROCESSED_DATA_PATH is required for phase=validate')
    processed_data_obj = json.loads(Path(processed_data_path_env).read_text(encoding='utf-8'))
    processed_data = processed_data_obj.get('processed_data', {})
    process_succeeded = processed_data_obj.get('process_succeeded', False)
    params2 = {'data': processed_data}
    validate_auth_result = require_authorization_result('validateQuality', tee_bundle, val_id, expected_build_config_id)
    auth2 = pre_signed_bundle.get('validateQualityReceipt')
    if not auth2:
        raise RuntimeError('validateQualityReceipt missing from pre-signed bundle')
    did2 = coordinator.delegate_task(val_id, 'VALIDATE_QUALITY', 'validate data quality', params2, tee_authorization=auth2)
    req2 = coordinator._delegations[did2]
    sig2 = req2.to_action_request(coordinator.identity)
    res2 = validator.process_delegation_request(
        sig2,
        expected_gateway_public_key_hex=trusted_gateway_public_key_hex,
        expected_gateway_key_id=trusted_gateway_key_id,
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
        expected_gateway_key_id=trusted_gateway_key_id,
        expected_action='VALIDATE_QUALITY',
        expected_parameters=params2,
        expected_build_config_id=expected_build_config_id,
    )
    validated_data = rd2.get('result') or {}
    print(json.dumps({
        'success': process_succeeded and res2['result_data']['status'] == 'COMPLETED',
        'replayMode': 'non-durable-demo' if runtime_mode == 'demo' else ('durable-test' if runtime_mode == 'test' else 'durable-live'),
        'tenantDid': tenant_did,
        'coordinatorDid': coordinator.identity.did,
        'uniqueIdentities': unique_ids,
        'recordsProcessed': processed_data.get('records_processed', 0),
        'totalRevenue': processed_data.get('total_revenue', 0),
        'avgValue': processed_data.get('avg_value', 0),
        'qualityScore': validated_data.get('quality_score', 0),
        'qualityPassed': bool(validated_data.get('passed', False)),
    }))

else:
    # Legacy full path: gateway key signs in Python (used by runAdnWithRealDid)
    params1 = {'data_source': 'csv', 'time_period': 'Q1-2026', 'filters': []}
    process_auth_result = require_authorization_result('processData', tee_bundle, w1_id, expected_build_config_id)
    if pre_signed_bundle is not None:
        auth1 = pre_signed_bundle.get('processDataReceipt')
        if not auth1:
            raise RuntimeError('processDataReceipt missing from pre-signed bundle')
    else:
        auth1 = build_tee_authorization_receipt(
            gateway_identity=gateway.identity,
            gateway_key_id=trusted_gateway_key_id,
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
        expected_gateway_key_id=trusted_gateway_key_id,
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
        expected_gateway_key_id=trusted_gateway_key_id,
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
    if pre_signed_bundle is not None:
        auth2 = pre_signed_bundle.get('validateQualityReceipt')
        if not auth2:
            raise RuntimeError('validateQualityReceipt missing from pre-signed bundle')
    else:
        auth2 = build_tee_authorization_receipt(
            gateway_identity=gateway.identity,
            gateway_key_id=trusted_gateway_key_id,
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
        expected_gateway_key_id=trusted_gateway_key_id,
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
        expected_gateway_key_id=trusted_gateway_key_id,
        expected_action='VALIDATE_QUALITY',
        expected_parameters=params2,
        expected_build_config_id=expected_build_config_id,
    )
    validated_data = rd2.get('result') or {}
    print(json.dumps({
        'success': res1['result_data']['status'] == 'COMPLETED' and res2['result_data']['status'] == 'COMPLETED',
        'replayMode': 'non-durable-demo' if runtime_mode == 'demo' else ('durable-test' if runtime_mode == 'test' else 'durable-live'),
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

function createSecureTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}_`));
  chmodSync(dir, 0o700);
  return dir;
}

function tempPath(tempDir: string, prefix: string, suffix: string): string {
  return join(tempDir, `${prefix}_${randomBytes(8).toString("hex")}.${suffix}`);
}

function writeJsonTemp(tempDir: string, prefix: string, payload: unknown): string {
  const outputPath = tempPath(tempDir, prefix, "json");
  writeFileSync(outputPath, JSON.stringify(payload), { encoding: "utf-8", mode: 0o600 });
  return outputPath;
}

function writeSecretTemp(tempDir: string, prefix: string, secret: string): string {
  const outputPath = tempPath(tempDir, prefix, "key");
  writeFileSync(outputPath, secret, { encoding: "utf-8", mode: 0o600 });
  return outputPath;
}

function readJsonFile<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf-8")) as T;
}

function cleanupTempFiles(paths: string[], dirs: string[] = []): void {
  for (const path of paths) {
    try {
      unlinkSync(path);
    } catch {
      // Best-effort cleanup only.
    }
  }
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup only.
    }
  }
}

export function requireConfiguredGatewayKeyBundleFromEnv(): GatewayKeyBundle {
  const privateKeyHex = requireHexEnv("ADN_GATEWAY_PRIVATE_KEY_HEX");
  const publicKeyHex = requireHexEnv("ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX");
  const gatewayKeyId = process.env.ADN_GATEWAY_KEY_ID?.trim() || `gateway-${publicKeyHex.slice(0, 12)}`;
  return {
    gatewayKeyId,
    publicKeyHex,
    privateKeyHex,
  };
}

function runPythonProcess(env: Record<string, string>, deps: RunAdnDeps = {}): Promise<{ stdout: string; stderr: string }> {
  const tempDir = createSecureTempDir("adn_run");
  const scriptPath = tempPath(tempDir, "adn_run", "py");
  const spawnImpl = deps.spawnImpl ?? spawn;
  const pythonExecutable = deps.pythonExecutable ?? "python3";

  return new Promise((resolve, reject) => {
    writeFileSync(scriptPath, RUNNER_SCRIPT, { encoding: "utf-8", mode: 0o600 });
    const childEnv: Record<string, string> = { ...process.env, ADN_ROOT, T3_MOCK: "false", ...env } as Record<string, string>;
    childEnv.ADN_REPLAY_LEDGER_DIR = env.ADN_REPLAY_LEDGER_DIR ?? join(tempDir, "replay-ledger");
    delete childEnv.T3N_API_KEY;
    delete childEnv.ADN_GATEWAY_PRIVATE_KEY_HEX;
    delete childEnv.ADN_TRUSTED_GATEWAY_PUBLIC_KEY_HEX;
    delete childEnv.ADN_REPLAY_LEDGER_INTEGRITY_KEY_HEX;
    if (env.ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE) {
      childEnv.ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE = env.ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE;
    } else {
      delete childEnv.ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE;
    }

    const proc = spawnImpl(pythonExecutable, [scriptPath], {
      env: childEnv,
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
      cleanupTempFiles([scriptPath], [tempDir]);
      if (code !== 0) {
        reject(new Error(`ADN process failed (exit ${code}):\n${stderr}`));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

export async function prepareAdnExecution(
  tenantDid: string,
  deps: RunAdnDeps = {}
): Promise<PreparedAdnExecution> {
  const tempDir = createSecureTempDir("adn_prepare");
  const outputPath = tempPath(tempDir, "adn_prepare", "json");
  try {
    await runPythonProcess(
      {
        DID: tenantDid,
        ADN_RUN_MODE: "prepare",
        ADN_OUTPUT_PATH: outputPath,
        ADN_REPLAY_LEDGER_DIR: join(tempDir, "replay-ledger"),
      },
      deps,
    );
    return readJsonFile<PreparedAdnExecution>(outputPath);
  } finally {
    cleanupTempFiles([outputPath], [tempDir]);
  }
}

export async function prepareGatewayKeyBundle(
  deps: RunAdnDeps = {}
): Promise<GatewayKeyBundle> {
  const tempDir = createSecureTempDir("adn_gateway");
  const outputPath = tempPath(tempDir, "adn_gateway", "json");
  try {
    await runPythonProcess(
      {
        DID: "did:t3n:gateway-local",
        ADN_RUN_MODE: "prepare_gateway",
        ADN_OUTPUT_PATH: outputPath,
        ADN_REPLAY_LEDGER_DIR: join(tempDir, "replay-ledger"),
      },
      deps,
    );
    return readJsonFile<GatewayKeyBundle>(outputPath);
  } finally {
    cleanupTempFiles([outputPath], [tempDir]);
  }
}

export async function runAdnWithRealDid(
  tenantDid: string,
  preparedExecution: PreparedAdnExecution,
  teeAuthorizationBundle: TeeAuthorizationBundle,
  gatewayKeyBundle: GatewayKeyBundle,
  deps: RunAdnDeps = {},
): Promise<AdnDelegationResult> {
  const tempDir = createSecureTempDir("adn_execute");
  const runtimeMode = getRuntimeMode();
  const replayLedgerDir = requireReplayLedgerDir(runtimeMode, tempDir);
  const replayKeyProvider = resolveReplayKeyProvider(runtimeMode);
  const identityBundlePath = writeJsonTemp(tempDir, "adn_identity_bundle", preparedExecution);
  const teeAuthorizationPath = writeJsonTemp(tempDir, "adn_tee_bundle", teeAuthorizationBundle);
  const gatewayKeyBundlePath = writeJsonTemp(tempDir, "adn_gateway_bundle", gatewayKeyBundle);
  const replayIntegrityKeyPath = writeSecretTemp(tempDir, "adn_replay_integrity", replayKeyProvider.keyHex);

  try {
    const { stdout, stderr } = await runPythonProcess(
      {
        DID: tenantDid,
        ADN_RUN_MODE: "execute",
        ADN_IDENTITY_BUNDLE_PATH: identityBundlePath,
        TEE_AUTHORIZATION_BUNDLE_PATH: teeAuthorizationPath,
        ADN_GATEWAY_KEY_BUNDLE_PATH: gatewayKeyBundlePath,
        ADN_RUNTIME_MODE: runtimeMode,
        ADN_REPLAY_LEDGER_DIR: replayLedgerDir,
        ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE: replayIntegrityKeyPath,
        ADN_REPLAY_LEDGER_KEY_REF: replayKeyProvider.keyRef,
      },
      deps,
    );
    try {
      return JSON.parse(stdout.trim()) as AdnDelegationResult;
    } catch {
      throw new Error(`ADN output parse error:\n${stdout}\n${stderr}`);
    }
  } finally {
    cleanupTempFiles([identityBundlePath, teeAuthorizationPath, gatewayKeyBundlePath, replayIntegrityKeyPath], [tempDir]);
  }
}


// ─── Phase 2: Pre-signed gateway bundle ─────────────────────────────────────

/**
 * Pre-signed bundle written by the TypeScript executor and passed to Python
 * via ADN_PRE_SIGNED_RECEIPTS_PATH.  Python only verifies — it never signs.
 */
export interface PreSignedReceiptsBundle {
  publicKeyHex: string;
  gatewayKeyId: string;
  processDataReceipt: Record<string, unknown>;
  validateQualityReceipt: Record<string, unknown>;
}

/**
 * Phase 2 execution path — two-pass design.
 *
 * Pass 1 (phase=process): Python runs worker1, outputs processed_data JSON.
 * Pass 2 (phase=validate): TypeScript signs the VALIDATE_QUALITY receipt with
 *   the REAL processed_data, then Python runs the validator with that receipt.
 *
 * This eliminates the placeholder `{ data: {} }` receipt that previously caused
 * a TEE receipt-hash mismatch at runtime.
 *
 * spawnGatewayExecutor() must have already been called and scrubbed
 * ADN_GATEWAY_PRIVATE_KEY_HEX from this process's env.
 */
export async function runAdnWithSignedGateway(
  tenantDid: string,
  preparedExecution: PreparedAdnExecution,
  teeAuthorizationBundle: TeeAuthorizationBundle,
  client: import("./gateway_client.js").GatewaySigningClient,
  deps: RunAdnDeps = {},
): Promise<AdnDelegationResult> {
  const pubInfo = await client.getPublicInfo();

  const processAuthResult = teeAuthorizationBundle.processData as unknown as Record<string, unknown>;
  const validateAuthResult = teeAuthorizationBundle.validateQuality as unknown as Record<string, unknown>;

  const params1: Record<string, unknown> = {
    data_source: "csv",
    time_period: "Q1-2026",
    filters: [],
  };

  // ── Pass 1 setup ─────────────────────────────────────────────────────────────
  const processDataReceipt = await client.signReceipt(processAuthResult, "PROCESS_DATA", params1);

  const tempDir = createSecureTempDir("adn_execute_signed");
  const runtimeMode = getRuntimeMode();
  const replayLedgerDir = requireReplayLedgerDir(runtimeMode, tempDir);
  const replayKeyProvider = resolveReplayKeyProvider(runtimeMode);
  const identityBundlePath = writeJsonTemp(tempDir, "adn_identity_bundle", preparedExecution);
  const teeAuthorizationPath = writeJsonTemp(tempDir, "adn_tee_bundle", teeAuthorizationBundle);
  const replayIntegrityKeyPath = writeSecretTemp(tempDir, "adn_replay_integrity", replayKeyProvider.keyHex);

  const tempFiles = [identityBundlePath, teeAuthorizationPath, replayIntegrityKeyPath];

  try {
    const processPreSignedBundle = {
      publicKeyHex: pubInfo.publicKeyHex,
      gatewayKeyId: pubInfo.gatewayKeyId,
      processDataReceipt,
    };
    const processPreSignedPath = writeJsonTemp(tempDir, "adn_process_pre_signed", processPreSignedBundle);
    tempFiles.push(processPreSignedPath);

    // ── Pass 1: run worker1, capture processed_data ───────────────────────────
    const { stdout: processStdout, stderr: processStderr } = await runPythonProcess(
      {
        DID: tenantDid,
        ADN_RUN_MODE: "execute",
        ADN_EXECUTION_PHASE: "process",
        ADN_IDENTITY_BUNDLE_PATH: identityBundlePath,
        TEE_AUTHORIZATION_BUNDLE_PATH: teeAuthorizationPath,
        ADN_PRE_SIGNED_RECEIPTS_PATH: processPreSignedPath,
        ADN_RUNTIME_MODE: runtimeMode,
        ADN_REPLAY_LEDGER_DIR: replayLedgerDir,
        ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE: replayIntegrityKeyPath,
        ADN_REPLAY_LEDGER_KEY_REF: replayKeyProvider.keyRef,
      },
      deps,
    );

    let processPhaseResult: { process_succeeded: boolean; processed_data: Record<string, unknown> };
    try {
      processPhaseResult = JSON.parse(processStdout.trim());
    } catch {
      throw new Error(`ADN phase=process output parse error:\n${processStdout}\n${processStderr}`);
    }

    const processedData = processPhaseResult.processed_data;
    const processSucceeded = processPhaseResult.process_succeeded;

    // ── Sign VALIDATE_QUALITY receipt with REAL processed_data ────────────────
    const params2: Record<string, unknown> = { data: processedData };
    const validateQualityReceipt = await client.signReceipt(validateAuthResult, "VALIDATE_QUALITY", params2);

    // ── Pass 2 setup ─────────────────────────────────────────────────────────
    const validatePreSignedBundle = {
      publicKeyHex: pubInfo.publicKeyHex,
      gatewayKeyId: pubInfo.gatewayKeyId,
      validateQualityReceipt,
    };
    const validatePreSignedPath = writeJsonTemp(tempDir, "adn_validate_pre_signed", validatePreSignedBundle);
    const processedDataPath = writeJsonTemp(tempDir, "adn_processed_data", {
      processed_data: processedData,
      process_succeeded: processSucceeded,
    });
    tempFiles.push(validatePreSignedPath, processedDataPath);

    // ── Pass 2: run validator with bound receipt ───────────────────────────────
    const { stdout, stderr } = await runPythonProcess(
      {
        DID: tenantDid,
        ADN_RUN_MODE: "execute",
        ADN_EXECUTION_PHASE: "validate",
        ADN_IDENTITY_BUNDLE_PATH: identityBundlePath,
        TEE_AUTHORIZATION_BUNDLE_PATH: teeAuthorizationPath,
        ADN_PRE_SIGNED_RECEIPTS_PATH: validatePreSignedPath,
        ADN_PROCESSED_DATA_PATH: processedDataPath,
        ADN_RUNTIME_MODE: runtimeMode,
        ADN_REPLAY_LEDGER_DIR: replayLedgerDir,
        ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE: replayIntegrityKeyPath,
        ADN_REPLAY_LEDGER_KEY_REF: replayKeyProvider.keyRef,
      },
      deps,
    );

    try {
      return JSON.parse(stdout.trim()) as AdnDelegationResult;
    } catch {
      throw new Error(`ADN phase=validate output parse error:\n${stdout}\n${stderr}`);
    }
  } finally {
    cleanupTempFiles(tempFiles, [tempDir]);
  }
}
