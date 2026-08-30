#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/4] Python conformance"
PYTHONPATH="$ROOT/aivf-ccs-verifier/src" python3 "$ROOT/aivf-ccs-verifier/tests/test_conformance.py"

echo "[2/4] Persistence"
PYTHONPATH="$ROOT/aivf-ccs-verifier/src" python3 "$ROOT/aivf-ccs-verifier/tests/test_persistence.py"

echo "[3/4] Node in-process SDK"
(cd "$ROOT/aivf-ccs-sdk" && npm test)

echo "[4/4] Cross-language Python verifier <-> Node SDK"
TMP="$(mktemp -d)"
PORT=50951
cleanup() {
  kill "${PID:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

PYTHONPATH="$ROOT/aivf-ccs-verifier/src" \
python3 -m aivf_ccs_verifier.cli \
  --transport tcp --host 127.0.0.1 --port "$PORT" \
  --health-host 127.0.0.1 --health-port 50952 \
  --db "$TMP/evidence.db" --key-file "$TMP/ed25519.seed" \
  --issuer urn:test:verifier --audience urn:test:executor &
PID=$!

python3 - <<'PY'
import time, urllib.request
for _ in range(40):
    try:
        urllib.request.urlopen("http://127.0.0.1:50952/healthz",timeout=.2).read()
        break
    except Exception:
        time.sleep(.1)
else:
    raise SystemExit("verifier did not become healthy")
PY

(cd "$ROOT/aivf-ccs-sdk" && CCS_TEST_PORT="$PORT" node test/test_remote.mjs)
echo "ALL TESTS PASSED"
