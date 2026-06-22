import assert from "assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, "../..");
const pythonExecutable = process.platform === "win32" ? "python" : "python3";
const testDir = mkdtempSync(join(tmpdir(), "adn-replay-restart-"));
const replayLedgerDir = join(testDir, "ledger");
const keyFile = join(testDir, "replay-hmac.key");
const fixturePath = join(testDir, "fixture.json");
const scriptPath = join(testDir, "replay_restart_fixture.py");

writeFileSync(keyFile, "55".repeat(32), { encoding: "utf-8", mode: 0o600 });

const pythonScript = String.raw`
import json
import os
import sys

root = os.environ["ADN_ROOT"]
sys.path.insert(0, root)

from src.agent_delegation_network import create_agent
from src.result_verifier import verify_worker_result
from src.tee_authorization import build_tee_authorization_receipt

BUILD_CONFIG_ID = "adn-build-restart"
GATEWAY_KEY_ID = "gateway-restart"
AUTHORIZATION_EXPIRES_AT = "2999-01-01T00:00:00+00:00"
COORDINATOR_KEY = "01" * 32
WORKER_KEY = "02" * 32
GATEWAY_KEY = "03" * 32


def make_context():
    coordinator = create_agent("coordinator", private_key_hex=COORDINATOR_KEY)
    worker = create_agent("worker", private_key_hex=WORKER_KEY)
    gateway = create_agent("gateway", private_key_hex=GATEWAY_KEY)
    coordinator_id = coordinator.identity.agent_id
    worker_id = worker.identity.agent_id
    for policy in (worker.policy_engine.policy, coordinator.policy_engine.policy):
        policy.add_delegation_rule(coordinator_id, "PROCESS_DATA")
        policy.add_trust_relationship(coordinator_id, worker_id)
        policy.add_delegation_rule(worker_id, "PROCESS_DATA")
    worker.register_task_handler(
        "PROCESS_DATA",
        lambda _payload: {"status": "success", "processed_data": {"restart": True}},
    )
    return coordinator, worker, gateway


def make_receipt(worker, gateway):
    return build_tee_authorization_receipt(
        gateway_identity=gateway.identity,
        gateway_key_id=GATEWAY_KEY_ID,
        tee_result={
            "delegation_id": "tee-del-replay-restart",
            "status": "ROUTED",
            "routed_to": worker.identity.agent_id,
            "credential_fingerprint": "cred-replay-restart",
            "credential_enforced": True,
            "build_config_id": BUILD_CONFIG_ID,
            "authorization_expires_at": AUTHORIZATION_EXPIRES_AT,
        },
        action="PROCESS_DATA",
        parameters={},
    )


def process_request(worker, signed_request, gateway, expect_success):
    result = worker.process_delegation_request(
        signed_request,
        expected_gateway_public_key_hex=gateway.identity.public_key_hex,
        expected_gateway_key_id=GATEWAY_KEY_ID,
        expected_build_config_id=BUILD_CONFIG_ID,
    )
    if expect_success and result["result_data"]["status"] != "COMPLETED":
        raise RuntimeError(result["result_data"].get("error", "request failed"))
    return result


def verify_result(result, coordinator, worker, receipt):
    return verify_worker_result(
        result,
        worker.identity.agent_id,
        worker.identity.public_key_hex,
        result["result_data"]["delegation_id"],
        coordinator.identity.agent_id,
        expected_tee_authorization=receipt,
        expected_gateway_public_key_hex=receipt["gateway_public_key_hex"],
        expected_gateway_key_id=GATEWAY_KEY_ID,
        expected_action="PROCESS_DATA",
        expected_parameters={},
        expected_build_config_id=BUILD_CONFIG_ID,
    )


mode = sys.argv[1]
fixture_path = sys.argv[2]
coordinator, worker, gateway = make_context()
receipt = make_receipt(worker, gateway)

if mode == "create":
    delegation_id = coordinator.delegate_task(
        worker.identity.agent_id,
        "PROCESS_DATA",
        "restart replay fixture",
        {},
        tee_authorization=receipt,
    )
    signed_request = coordinator._delegations[delegation_id].to_action_request(coordinator.identity)
    result = process_request(worker, signed_request, gateway, expect_success=True)
    verify_result(result, coordinator, worker, receipt)
    with open(fixture_path, "w", encoding="utf-8") as handle:
        json.dump({
            "signed_request": signed_request,
            "result": result,
            "receipt": receipt,
            "coordinator_id": coordinator.identity.agent_id,
            "worker_id": worker.identity.agent_id,
            "worker_public_key_hex": worker.identity.public_key_hex,
        }, handle, sort_keys=True, separators=(",", ":"))
    print(json.dumps({"created": True, "requestStatus": result["result_data"]["status"]}))
elif mode == "replay":
    with open(fixture_path, encoding="utf-8") as handle:
        fixture = json.load(handle)
    replayed = process_request(worker, fixture["signed_request"], gateway, expect_success=False)
    request_error = replayed["result_data"].get("error", "")
    result_error = ""
    try:
        verify_result(fixture["result"], coordinator, worker, fixture["receipt"])
    except RuntimeError as exc:
        result_error = str(exc)
    output = {
        "requestReplayRejected": replayed["result_data"]["status"] == "FAILED" and "replay" in request_error.lower(),
        "resultReplayRejected": "replay" in result_error.lower() or "consumed" in result_error.lower(),
        "requestError": request_error,
        "resultError": result_error,
        "ledgerPersistedAcrossRestart": True,
        "build_config_id": BUILD_CONFIG_ID,
    }
    print(json.dumps(output, sort_keys=True))
    if not output["requestReplayRejected"] or not output["resultReplayRejected"]:
        raise SystemExit(2)
else:
    raise SystemExit(f"unknown mode: {mode}")
`;

function runFixture(mode) {
  const result = spawnSync(pythonExecutable, [scriptPath, mode, fixturePath], {
    cwd: rootDir,
    env: {
      ...process.env,
      ADN_ROOT: rootDir,
      ADN_RUNTIME_MODE: "live",
      ADN_REPLAY_LEDGER_DIR: replayLedgerDir,
      ADN_REPLAY_LEDGER_INTEGRITY_KEY_FILE: keyFile,
    },
    encoding: "utf-8",
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
}

try {
  writeFileSync(scriptPath, pythonScript, { encoding: "utf-8", mode: 0o600 });
  const created = runFixture("create");
  assert.equal(created.created, true);
  assert.equal(created.requestStatus, "COMPLETED");
  const replayed = runFixture("replay");
  assert.equal(replayed.requestReplayRejected, true);
  assert.equal(replayed.resultReplayRejected, true);
  assert.equal(replayed.ledgerPersistedAcrossRestart, true);
  assert.equal(replayed.build_config_id, "adn-build-restart");
  assert.ok(existsSync(join(replayLedgerDir, "replay_ledger.sqlite3")));
} finally {
  rmSync(testDir, { recursive: true, force: true });
}
