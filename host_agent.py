"""
ADN Live Narrator — Claude-powered shell agent.
Reads demo output line by line, sends key moments to Claude API,
speaks the generated narration via TTS.

Terminal 1 (record this):
    cd t3n-bridge
    node --loader ts-node/esm src/index.ts 2>&1 | tee ../demo_output.txt

Terminal 2 (narrator, can be minimized):
    cd agent-delegation-network
    Get-Content demo_output.txt -Wait | python3 host_agent.py
"""

import sys
import re
import threading
import queue
import anthropic
import pyttsx3

# ── TTS ───────────────────────────────────────────────────────────────────────
_engine = pyttsx3.init()
_engine.setProperty("rate", 160)
_engine.setProperty("volume", 1.0)
_tts_q = queue.Queue()

def _tts_worker():
    while True:
        text = _tts_q.get()
        if text is None:
            break
        _engine.say(text)
        _engine.runAndWait()
        _tts_q.task_done()

threading.Thread(target=_tts_worker, daemon=True).start()

def speak(text):
    print(f"\n[NARRATOR] {text}\n")
    sys.stdout.flush()
    _tts_q.put(text)

def wait_done():
    _tts_q.join()

# ── Claude narrator ───────────────────────────────────────────────────────────
client = anthropic.Anthropic()

SYSTEM = """You are the live video narrator for an Agent Delegation Network demo running against
the Terminal 3 blockchain testnet. You narrate each phase as it happens — clear, confident,
technical but not dense. You are the VOICE of this demo.

Rules:
- 2-4 sentences max per narration. Short and punchy.
- No filler words. No "okay" or "so". Just explain what happened and why it matters.
- When you see REJECTED lines, emphasize these are REAL HTTP 400s from the live T3N server.
- When you see _in_tee: true fields, call them TEE attestation fields — proof the computation ran in the enclave.
- Speak in present tense as events happen.
- Do NOT say "I" — you are a narrator, not a participant.
- Output ONLY the narration text. No markdown, no labels, no quotes."""

def narrate(event_label, raw_lines):
    """Call Claude to narrate a specific moment."""
    prompt = f"EVENT: {event_label}\n\nRAW OUTPUT:\n{raw_lines}\n\nNarrate this moment."
    try:
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=120,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()
        speak(text)
    except Exception as e:
        print(f"[NARRATOR ERROR] {e}")

# ── State ─────────────────────────────────────────────────────────────────────
state = {
    "phase": None,
    "wit_count": 0,
    "neg_lines": [],
    "intro_done": False,
}

WIT_NAMES = [
    "delegate-task", "submit-bid", "resolve-auction", "record-completion",
    "get-reputation", "send-personalized-outreach", "issue-time-grant",
    "check-grant", "kyc-submit-step", "kyc-get-status", "store-secret",
    "invoke-with-secret", "cast-vote", "tally-votes", "log-decision",
    "audit-decisions", "lock-bond", "verify-and-settle",
]

def handle(line):
    s = state

    # Commit binding
    if "88b7b88" in line and not s["intro_done"]:
        s["intro_done"] = True
        narrate("Demo start / commit binding", line)
        return

    # Phase 1
    if "[Phase 1]" in line:
        s["phase"] = 1
        narrate("Phase 1 starting — T3N authentication", line)
        return

    if "Authenticated DID" in line:
        narrate("Live DID received from T3N handshake API", line)
        return

    # Phase 0
    if "[Phase 0]" in line:
        s["phase"] = 0
        s["neg_lines"] = []
        narrate("Phase 0 starting — Agent Auth SDK credential lifecycle", line)
        return

    if "credential built" in line:
        narrate("Delegation credential built — vc_id is fresh random bytes this run", line)
        return

    if "pre-revocation call:" in line:
        narrate("Pre-revocation delegated call result", line)
        return

    if "revocation: SUCCESS" in line:
        narrate("Credential revoked — 35 second sleep starting for TTL expiry", line)
        return

    if "post-revocation call:" in line:
        narrate("Post-expiry delegated call result — TEE clock check fired", line)
        return

    if "missing agent_sig" in line or "short nonce" in line or "no envelope at all" in line:
        s["neg_lines"].append(line.strip())
        if len(s["neg_lines"]) == 3:
            narrate("C-01 negative envelope tests — all three results from live T3N server",
                    "\n".join(s["neg_lines"]))
        return

    # Phase 2
    if "[Phase 2]" in line:
        s["phase"] = 2
        narrate("Phase 2 starting — Python multi-agent delegation network", line)
        return

    if "Session DID injected correctly" in line:
        narrate("Phase 2 complete — DID binding confirmed", line)
        return

    # Phase 3
    if "[Phase 3]" in line:
        s["phase"] = 3
        narrate("Phase 3 starting — Rust/WASM TEE contract v3.8.1", line)
        return

    if "processed_in_tee: true" in line:
        narrate("TEE computation complete — attestation field confirmed", line)
        return

    if "validated_in_tee: true" in line:
        narrate("Quality validation complete inside TEE", line)
        return

    if "correctly rejected empty records" in line:
        narrate("TEE rejected empty records input — contract-layer validation", line)
        return

    # Phase 4
    if "[Phase 4]" in line:
        s["phase"] = 4
        s["wit_count"] = 0
        narrate("Phase 4 starting — all 20 WIT exports against live T3N TEE", line)
        return

    if "waiting 65s" in line or "fuel window reset" in line:
        narrate("Fuel window reset — testnet throttle limit, 65 second wait", line)
        return

    if s["phase"] == 4 and "[+]" in line:
        for fn in WIT_NAMES:
            if f"[+] {fn}:" in line:
                s["wit_count"] += 1
                narrate(
                    f"WIT function {s['wit_count']} of 18: {fn}",
                    f"Function: {fn}\nOutput: {line.strip()}"
                )
                return

    if "All 20 WIT exports invoked" in line:
        narrate("All 20 WIT exports complete", line)
        return

    # Summary
    if "BUILT + SIGNED + ENFORCED" in line:
        narrate("Agent Auth summary line — enforced means all assertions passed", line)
        return

    if "20/20 WIT functions" in line:
        narrate("Final summary — 20 of 20 WIT functions, live T3N testnet run", line)
        return

    if "FATAL:" in line:
        speak("Hard failure detected. Check the terminal output.")
        return


def main():
    speak("Agent Delegation Network narrator online. Waiting for demo output.")
    for raw in sys.stdin:
        line = raw.rstrip()
        if line:
            handle(line)

if __name__ == "__main__":
    main()