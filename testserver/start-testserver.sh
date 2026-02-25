#!/usr/bin/env bash
set -e

echo ""
echo "  ========================================================="
echo "   LeakLens - Test File Server"
echo "   Samba share with intentionally unsafe files for testing"
echo "  ========================================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Detect runtime ----------------------------------------------------------
RUNTIME=""
if command -v docker &>/dev/null; then RUNTIME="docker"
elif command -v podman &>/dev/null; then RUNTIME="podman"
fi

if [ -z "$RUNTIME" ]; then
  echo "  [ERROR] Neither Docker nor Podman found."
  echo "  Install Docker: https://docs.docker.com/get-docker/"
  echo "  or Podman:      https://podman.io/getting-started/installation"
  exit 1
fi

echo "  [OK] Using $RUNTIME"

# --- Build -------------------------------------------------------------------
echo ""
echo "  [*] Building test server image..."
$RUNTIME build -t leaklens-testserver "$SCRIPT_DIR/testserver"
echo "  [OK] Image built"

# --- Remove existing ---------------------------------------------------------
$RUNTIME rm -f leaklens-testserver 2>/dev/null || true

# --- Start -------------------------------------------------------------------
echo ""
echo "  [*] Starting test file server..."
$RUNTIME run -d \
  --name leaklens-testserver \
  -p 4445:4445 \
  leaklens-testserver

echo ""
echo "  ---------------------------------------------------------"
echo "   Test server running on port 4445!"
echo ""
echo "   Mount the share, then point LeakLens at the mount path:"
echo ""
echo "   Linux:"
echo "     sudo mount -t cifs //127.0.0.1/testshare /mnt/testshare \\"
echo "       -o port=4445,guest,vers=2.0"
echo "     Then scan: /mnt/testshare"
echo ""
echo "   macOS:"
echo "     open 'smb://127.0.0.1:4445/testshare'"
echo "     Then scan the mounted path under /Volumes/"
echo ""
echo "   Run ./stop-testserver.sh to shut it down."
echo "  ---------------------------------------------------------"
echo ""
