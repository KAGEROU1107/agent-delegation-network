# ADN Live Narrator Agent
# Uses claude CLI to generate narration + PowerShell built-in TTS to speak it.
#
# Terminal 1 (record this):
#   cd t3n-bridge
#   node --loader ts-node/esm src/index.ts 2>&1 | tee ../demo_output.txt
#
# Terminal 2 (run this, can minimize):
#   cd agent-delegation-network
#   .\narrator.ps1

Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.Rate = 1

$SYSTEM = "You are the live video narrator for an Agent Delegation Network demo against the Terminal 3 blockchain testnet. Narrate each event in 2-3 sentences max. Be clear and technical. No filler words. No markdown. REJECTED lines = real HTTP 400 from live T3N server. Fields ending _in_tee: true = TEE attestation proof. Output ONLY narration text."

function Narrate($event, $raw) {
    $prompt = "EVENT: $event`nRAW: $raw`nNarrate this now."
    $text = ($prompt | claude --print --system $SYSTEM 2>$null)
    if ($text) {
        Write-Host "`n>> $text`n" -ForegroundColor Cyan
        $synth.SpeakAsync($text) | Out-Null
    }
}

function Say($text) {
    Write-Host "`n>> $text`n" -ForegroundColor Green
    $synth.SpeakAsync($text) | Out-Null
}

$outFile = Join-Path $PSScriptRoot "demo_output.txt"
if (Test-Path $outFile) { Clear-Content $outFile }

Say "Narrator online. Waiting for demo."

$phase = $null; $negLines = @(); $witCount = 0; $introDone = $false

Get-Content $outFile -Wait | ForEach-Object {
    $line = $_.Trim()
    if (-not $line) { return }
    Write-Host $line -ForegroundColor DarkGray

    if ($line -match "88b7b88" -and -not $introDone) {
        $introDone = $true
        Narrate "Demo start and commit binding" $line

    } elseif ($line -match "\[Phase 1\]") {
        $phase = 1; Narrate "Phase 1 T3N authentication starting" $line

    } elseif ($line -match "Authenticated DID") {
        Narrate "Live DID received from T3N handshake API" $line

    } elseif ($line -match "\[Phase 0\]") {
        $phase = 0; $negLines = @()
        Narrate "Phase 0 Agent Auth SDK credential lifecycle" $line

    } elseif ($line -match "credential built") {
        Narrate "Delegation credential built with fresh random vc_id this run" $line

    } elseif ($line -match "pre-revocation call:") {
        Narrate "Pre-revocation delegated call result" $line

    } elseif ($line -match "revocation: SUCCESS") {
        Narrate "Credential revoked. 35 second sleep starting for TTL expiry." $line

    } elseif ($line -match "post-revocation call:") {
        Narrate "Post-expiry call result. TEE clock check fired inside enclave." $line

    } elseif ($line -match "missing agent_sig|short nonce|no envelope at all") {
        $negLines += $line
        if ($negLines.Count -eq 3) {
            Narrate "C-01 negative envelope tests — all three results from live T3N server" ($negLines -join " | ")
        }

    } elseif ($line -match "\[Phase 2\]") {
        $phase = 2; Narrate "Phase 2 Python multi-agent delegation network" $line

    } elseif ($line -match "Session DID injected correctly") {
        Narrate "Phase 2 complete. DID binding confirmed." $line

    } elseif ($line -match "\[Phase 3\]") {
        $phase = 3; Narrate "Phase 3 Rust WASM TEE contract v3.8.1" $line

    } elseif ($line -match "processed_in_tee: true") {
        Narrate "TEE computation complete. Attestation field confirmed." $line

    } elseif ($line -match "validated_in_tee: true") {
        Narrate "Quality validation complete inside TEE enclave." $line

    } elseif ($line -match "correctly rejected empty records") {
        Narrate "TEE rejected empty input. Contract-layer validation." $line

    } elseif ($line -match "\[Phase 4\]") {
        $phase = 4; $witCount = 0
        Narrate "Phase 4 starting. All 20 WIT exports against live Terminal 3 TEE." $line

    } elseif ($line -match "waiting 65s|fuel window reset") {
        Say "Fuel window reset. Testnet throttle — 65 second wait."

    } elseif ($phase -eq 4 -and $line -match "\[\+\] ([\w-]+):") {
        $fn = $Matches[1]; $witCount++
        Narrate "WIT function $witCount of 18: $fn" "Function: $fn | Output: $line"

    } elseif ($line -match "All 20 WIT exports invoked") {
        Narrate "All 20 WIT exports invoked on live Terminal 3 TEE." $line

    } elseif ($line -match "BUILT \+ SIGNED \+ ENFORCED") {
        Narrate "Agent Auth enforced. All assertions passed." $line

    } elseif ($line -match "20/20 WIT functions") {
        Narrate "Final summary. 20 of 20 WIT functions on live Terminal 3 testnet." $line

    } elseif ($line -match "FATAL:") {
        Say "Hard failure detected. Check the terminal."
    }
}