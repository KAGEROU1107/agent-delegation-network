# ADN Install Script — Windows (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=== ADN Install Script ===" -ForegroundColor Cyan

# Check Node.js >= 18
try {
    $nodeVersion = (node -e "process.stdout.write(process.versions.node.split('.')[0])") -as [int]
    if ($nodeVersion -lt 18) {
        Write-Host "ERROR: Node.js v18+ required (found v$nodeVersion)" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Node.js $(node -v) OK" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Node.js not found. Install from https://nodejs.org (v18+)" -ForegroundColor Red
    exit 1
}

# Check Python 3
try {
    $pyVersion = python --version 2>&1
    Write-Host "[+] $pyVersion OK" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}

# Install Node deps
Write-Host "[+] Installing Node.js dependencies..."
Push-Location t3n-bridge
npm install
Pop-Location

# Install Python deps
Write-Host "[+] Installing Python dependencies..."
pip install -r requirements.txt

# Copy .env if not present
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[+] Created .env from .env.example — fill in your T3N_API_KEY" -ForegroundColor Yellow
} else {
    Write-Host "[+] .env already exists — skipping" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit .env and set T3N_API_KEY to your Terminal 3 testnet key"
Write-Host "  2. cd t3n-bridge"
Write-Host "  3. node --loader ts-node/esm src/index.ts"
