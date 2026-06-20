/**
 * Python ADN subprocess runner.
 *
 * The TypeScript bridge handles Terminal 3 ADK auth (T3nClient, TenantClient).
 * Once a real authenticated DID is obtained, it is injected into the Python
 * Agent Delegation Network as the coordinator's identity.
 *
 * Architecture:
 *   TypeScript  ──[auth]──>  T3N testnet
 *   TypeScript  ──[spawn]──>  Python ADN (DID injected from authenticated session)
 *   Python ADN  ──[sign]──>   Ed25519 signed delegation requests
 *   TypeScript  ──[invoke]──>  T3N TEE contract for data processing
 */

import { spawn } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

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

/**
 * Run the Python Agent Delegation Network with the real authenticated DID.
 * The DID comes from T3N auth — NOT hardcoded.
 */
export async function runAdnWithRealDid(
  apiKey: string,
  tenantDid: string
): Promise<AdnDelegationResult> {
  return new Promise((resolve, reject) => {
    const script = `
import sys, os, json, secrets, logging
sys.path.insert(0, r'${ADN_ROOT.replace(/\\/g, '\\\\')}')
os.environ['DID'] = '${tenantDid}'
os.environ['T3_MOCK'] = 'false'
logging.disable(9999)

from src.agent_delegation_network import create_agent

coordinator = create_agent('coordinator')
worker1     = create_agent('worker1',   private_key_hex=secrets.token_hex(32))
worker2     = create_agent('worker2',   private_key_hex=secrets.token_hex(32))
validator   = create_agent('validator', private_key_hex=secrets.token_hex(32))

unique_ids = len({
    coordinator.identity.agent_id,
    worker1.identity.agent_id,
    worker2.identity.agent_id,
    validator.identity.agent_id,
})

import csv, statistics, time
from pathlib import Path

data_dir = Path(r'${ADN_ROOT.replace(/\\/g, '\\\\')}') / 'data'
csv_files = list(data_dir.glob('sales_*.csv'))
csv_path = csv_files[0] if csv_files else None
records, amounts = [], []
if csv_path:
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            if row.get('sale_amount'):
                amounts.append(float(row['sale_amount']))

from src.delegation_protocol import DelegationProtocol, DelegationStatus

coord_id = coordinator.identity.agent_id
w1_id    = worker1.identity.agent_id
w2_id    = worker2.identity.agent_id
val_id   = validator.identity.agent_id

coordinator.policy_engine.policy.add_delegation_rule(coord_id, 'PROCESS_DATA')
coordinator.policy_engine.policy.add_delegation_rule(coord_id, 'VALIDATE_QUALITY')
coordinator.policy_engine.policy.add_trust_relationship(coord_id, w1_id)
coordinator.policy_engine.policy.add_trust_relationship(coord_id, val_id)
coordinator.policy_engine.policy.add_trust_relationship(coord_id, coord_id)
worker1.policy_engine.policy.add_delegation_rule(w1_id, 'PROCESS_DATA')
worker1.policy_engine.policy.add_trust_relationship(w1_id, coord_id)
validator.policy_engine.policy.add_delegation_rule(val_id, 'VALIDATE_QUALITY')
validator.policy_engine.policy.add_trust_relationship(val_id, coord_id)

avg = round(statistics.mean(amounts), 2) if amounts else 0.0
total = round(sum(amounts), 2)
mid = len(amounts) // 2
trend = 'increasing' if mid and statistics.mean(amounts[mid:]) > statistics.mean(amounts[:mid]) else 'stable'

def process_handler(p):
    return {'status': 'success', 'processed_data': {
        'records_processed': len(amounts), 'total_revenue': total,
        'avg_value': avg, 'min_value': round(min(amounts), 2) if amounts else 0,
        'max_value': round(max(amounts), 2) if amounts else 0,
        'trend': trend, 'csv_file': csv_path.name if csv_path else 'none',
    }}

def validate_handler(p):
    data = p.get('data', {})
    score = 1.0
    if not data.get('records_processed'): score -= 0.4
    if not data.get('avg_value'):         score -= 0.3
    if not data.get('csv_file'):          score -= 0.1
    score = max(0.0, round(score, 2))
    return {'status': 'success', 'quality_score': score, 'passed': score >= 0.8, 'issues': []}

worker1.register_task_handler('PROCESS_DATA',    process_handler)
validator.register_task_handler('VALIDATE_QUALITY', validate_handler)

did1 = coordinator.delegate_task(w1_id, 'PROCESS_DATA', 'process sales data', {'data_source': 'csv', 'time_period': 'Q1-2026', 'filters': []})
req1 = coordinator._delegations[did1]
sig1 = req1.to_action_request(coordinator.identity)
res1 = worker1.process_delegation_request(sig1)
pd = res1['result_data'].get('result', {}).get('processed_data', {})

did2 = coordinator.delegate_task(val_id, 'VALIDATE_QUALITY', 'validate data quality', {'data': pd})
req2 = coordinator._delegations[did2]
sig2 = req2.to_action_request(coordinator.identity)
res2 = validator.process_delegation_request(sig2)
vd = res2['result_data'].get('result', {})

print(json.dumps({
    'success': res1['result_data']['status'] == 'COMPLETED' and res2['result_data']['status'] == 'COMPLETED',
    'tenantDid': '${tenantDid}',
    'coordinatorDid': coordinator.identity.did,
    'uniqueIdentities': unique_ids,
    'recordsProcessed': pd.get('records_processed', 0),
    'totalRevenue': pd.get('total_revenue', 0),
    'avgValue': pd.get('avg_value', 0),
    'qualityScore': vd.get('quality_score', 0),
    'qualityPassed': bool(vd.get('passed', False)),
}))
`;

    const proc = spawn("python3", ["-c", script], {
      env: { ...process.env, T3N_API_KEY: apiKey, DID: tenantDid, T3_MOCK: "false" },
    });

    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

    proc.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`ADN process failed (exit ${code}):\n${stderr}`));
        return;
      }
      try {
        const result = JSON.parse(stdout.trim());
        resolve(result as AdnDelegationResult);
      } catch {
        reject(new Error(`ADN output parse error:\n${stdout}\n${stderr}`));
      }
    });
  });
}

