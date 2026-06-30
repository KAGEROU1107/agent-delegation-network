#!/usr/bin/env python3
"""
ADN Worker Executor — isolated process that owns worker private keys.
Bridge spawns this and communicates via authenticated TCP loopback RPC.
Private keys never leave this process.
"""
import os, sys, json, secrets, socket, threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CAPABILITY_TOKEN = os.environ.get("WORKER_CAPABILITY_TOKEN", "")
if not CAPABILITY_TOKEN:
    print("[worker_executor] WORKER_CAPABILITY_TOKEN not set", file=sys.stderr)
    sys.exit(1)

_sessions: dict = {}

def _auth(data: dict) -> bool:
    token = data.get("token", "")
    if isinstance(token, str):
        token = token.encode()
    return secrets.compare_digest(token, CAPABILITY_TOKEN.encode())

def handle_rpc(data: dict) -> dict:
    if not _auth(data):
        return {"error": "unauthorized"}

    method = data.get("method")

    if method == "create_session":
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_hex = pub_bytes.hex()
        sid = secrets.token_hex(16)
        agent_id = f"worker-{secrets.token_hex(8)}"
        did = f"did:key:z{pub_hex[:32]}"
        _sessions[sid] = {"priv": priv, "did": did, "agentId": agent_id, "publicKeyHex": pub_hex}
        return {"session_id": sid, "agentId": agent_id, "did": did, "publicKeyHex": pub_hex}

    elif method == "sign_result":
        sid = data.get("session_id", "")
        if sid not in _sessions:
            return {"error": "unknown_session"}
        payload = data.get("payload", "")
        if isinstance(payload, str):
            payload_bytes = payload.encode()
        else:
            payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = _sessions[sid]["priv"].sign(payload_bytes)
        return {"signature": sig.hex(), "session_id": sid}

    elif method == "get_public_key":
        sid = data.get("session_id", "")
        if sid not in _sessions:
            return {"error": "unknown_session"}
        s = _sessions[sid]
        return {"publicKeyHex": s["publicKeyHex"], "did": s["did"], "agentId": s["agentId"]}

    elif method == "close_session":
        sid = data.get("session_id", "")
        _sessions.pop(sid, None)
        return {"closed": sid}

    return {"error": "unknown_method"}

def _handle_client(conn: socket.socket):
    try:
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            try:
                data = json.loads(buf.decode())
                result = handle_rpc(data)
                conn.sendall(json.dumps(result).encode() + b"\n")
                buf = b""
            except json.JSONDecodeError:
                continue
    finally:
        conn.close()

def serve():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(10)
    sys.stdout.write(f"WORKER_EXECUTOR_READY:tcp:{port}\n")
    sys.stdout.flush()
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    serve()
