#!/usr/bin/env bash
set -e

echo "=== ADN Install Script ==="

if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js not found. Install from https://nodejs.org (v18+)"
  exit 1
fi
NODE_VERSION=$(node -e "process.stdout.write(process.versions.node.split('.')[0])")
if [ "$NODE_VERSION" -lt 18 ]; then
  echo "ERROR: Node.js v18+ required (found v$NODE_VERSION)"
  exit 1
fi
echo "[+] Node.js $(node -v) OK"

if ! command -v python3 &>/dev/null; then
  echo "ERROR: Python 3 not found. Install from https://python.org"
  exit 1
fi
echo "[+] $(python3 --version) OK"

echo "[+] Installing Node.js dependencies..."
cd t3n-bridge && npm install && cd ..

echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[+] Created .env from .env.example — fill in your T3N_API_KEY"
else
  echo "[+] .env already exists — skipping"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit .env and set T3N_API_KEY to your Terminal 3 testnet key"
echo "  2. cd t3n-bridge"
echo "  3. node --loader ts-node/esm src/index.ts"
