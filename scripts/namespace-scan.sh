#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "[AIVF CCS namespace scan]"
LEGACY_PATTERN='cor''rectover'
if grep -RIni --exclude-dir=.git --exclude='namespace-scan.sh' -- "$LEGACY_PATTERN" . >/tmp/aivf-ccs-legacy-namespace-hits.txt; then
  echo "FAIL: legacy project namespace/name found in public repository"
  cat /tmp/aivf-ccs-legacy-namespace-hits.txt
  exit 1
fi
echo "PASS: no legacy project namespace/name remains in public repository"
