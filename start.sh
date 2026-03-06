#!/usr/bin/env bash

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        LeakLens — Credential Exposure Scanner        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""

# ─── Locate Python ────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "  [ERROR] Python is not installed or not in PATH."
    echo "  Install from https://www.python.org or via your package manager:"
    echo "    Ubuntu/Debian:  sudo apt install python3"
    echo "    macOS:          brew install python"
    echo ""
    exit 1
fi

# ─── Check Python version (require 3.11+) ────────────────────────────────────
PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    echo "  [ERROR] Python 3.11 or higher is required. Found: $PY_VER"
    echo ""
    exit 1
fi
echo "  [OK] Python $($PYTHON --version) found"

# ─── Install core dependencies ────────────────────────────────────────────────
echo ""
echo "  [*] Installing core dependencies..."
if ! $PYTHON -m pip install -r requirements.txt --no-warn-script-location -q; then
    echo ""
    echo "  [ERROR] Failed to install core dependencies."
    echo "  Try running manually: pip install -r requirements.txt"
    echo ""
    exit 1
fi
echo "  [OK] Core dependencies ready"

# ─── Check smbclient binary (needed for share enumeration on Linux/macOS) ─────
echo ""
if command -v smbclient &>/dev/null; then
    echo "  [OK] smbclient found — share enumeration available"
else
    echo "  [WARN] smbclient binary not found."
    echo "  SMB share enumeration (Discover Shares button) will be unavailable."
    echo "  Scanning a known UNC path (e.g. //server/share) still works without it."
    echo ""
    echo "  To enable share enumeration, install samba-client:"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "    brew install samba"
    else
        echo "    sudo apt install smbclient    # Debian/Ubuntu"
        echo "    sudo dnf install samba-client  # Fedora/RHEL"
    fi
    echo ""
fi

# ─── Create reports directory ─────────────────────────────────────────────────
mkdir -p reports

# ─── Open browser after server starts ────────────────────────────────────────
(sleep 1.5 && {
    if command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost:3000" &>/dev/null
    elif command -v open &>/dev/null; then
        open "http://localhost:3000"
    fi
}) &

# ─── Start server ─────────────────────────────────────────────────────────────
echo "  [*] Starting LeakLens at http://localhost:3000"
echo "      Press Ctrl+C to stop."
echo ""
$PYTHON leaklens.py
