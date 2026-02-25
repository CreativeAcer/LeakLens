#!/usr/bin/env bash

RUNTIME=""
if command -v docker &>/dev/null; then RUNTIME="docker"
elif command -v podman &>/dev/null; then RUNTIME="podman"
fi

if [ -z "$RUNTIME" ]; then
  echo "  [ERROR] Neither Docker nor Podman found."
  exit 1
fi

echo "  [*] Stopping test server..."
$RUNTIME rm -f leaklens-testserver
echo "  [OK] Done."
