#!/usr/bin/env bash
set -e

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        LeakLens — Credential Exposure Scanner        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""

# ─── Check Python ─────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
  echo "  [ERROR] Python 3 is not installed."
  echo "  Install from https://www.python.org or via your package manager."
  exit 1
fi

PYTHON=$(command -v python3 || command -v python)
echo "  [OK] $($PYTHON --version) found"

# ─── Install dependencies ─────────────────────────────────────────────────────
echo ""
echo "  [*] Installing dependencies (flask, smbprotocol)..."
$PYTHON -m pip install -r requirements.txt -q
echo "  [OK] Dependencies ready"

# ─── Create reports directory ─────────────────────────────────────────────────
mkdir -p reports

# ─── Start server ─────────────────────────────────────────────────────────────
echo ""
echo "  [*] Starting LeakLens at http://localhost:3000"
echo "      Press Ctrl+C to stop."
echo ""

# Open browser after server starts
(sleep 1.5 && (
  if command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:3000" &>/dev/null
  elif command -v open &>/dev/null; then
    open "http://localhost:3000"
  fi
)) &

$PYTHON leaklens.py
