#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${TMPDIR:-/tmp}/aivf-ccs-oss-test-venv"

rm -rf "$VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" -q install --upgrade pip
"$VENV/bin/pip" -q install "$ROOT/aivf-ccs-verifier" -r "$ROOT/public-verifier/requirements.txt"

cleanup() { rm -rf "$VENV"; }
trap cleanup EXIT

echo "[1/3] Python CCS conformance + persistence"
PYTHONPATH="$ROOT/aivf-ccs-verifier/src" "$VENV/bin/python" "$ROOT/aivf-ccs-verifier/tests/test_conformance.py"
PYTHONPATH="$ROOT/aivf-ccs-verifier/src" "$VENV/bin/python" "$ROOT/aivf-ccs-verifier/tests/test_persistence.py"

echo "[2/3] Node SDK"
(cd "$ROOT/aivf-ccs-sdk" && npm test)

echo "[3/3] Public verifier unit tests"
"$VENV/bin/python" "$ROOT/public-verifier/tests/test_verifier.py"

echo "ALL OSS TESTS PASSED"


echo "[boundary] OSS/commercial separation"
"$ROOT/scripts/oss-boundary-scan.sh"


echo "[namespace] AIVF CCS naming"
"$ROOT/scripts/namespace-scan.sh"
