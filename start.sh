#!/usr/bin/env bash
set -e

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        LeakLens — Credential Exposure Scanner        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""

# ─── Check Node.js ────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "  [ERROR] Node.js is not installed. Install from https://nodejs.org"
  exit 1
fi
echo "  [OK] Node.js $(node -v) found"

# ─── Check PowerShell Core ────────────────────────────────────────────────────
if ! command -v pwsh &>/dev/null; then
  echo "  [ERROR] PowerShell Core (pwsh) is not installed."
  echo "  Install from https://github.com/PowerShell/PowerShell"
  exit 1
fi
echo "  [OK] $(pwsh --version) found"

# ─── Install dependencies if needed ──────────────────────────────────────────
if [ ! -d "backend/node_modules" ]; then
  echo ""
  echo "  [*] Installing backend dependencies..."
  (cd backend && npm install --silent)
  echo "  [OK] Dependencies installed"
else
  echo "  [OK] Dependencies already installed"
fi

# ─── Create reports directory ─────────────────────────────────────────────────
mkdir -p reports

# ─── Start backend ────────────────────────────────────────────────────────────
echo ""
echo "  [*] Starting LeakLens backend on http://localhost:3000"
echo ""

(cd backend && node server.js) &
BACKEND_PID=$!

sleep 1

# ─── Open browser ─────────────────────────────────────────────────────────────
if command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:3000" &>/dev/null &
elif command -v open &>/dev/null; then
  open "http://localhost:3000"
fi

echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  LeakLens is running at http://localhost:3000       │"
echo "  │  Press Ctrl+C to stop.                              │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""

# Wait for backend
wait $BACKEND_PID
