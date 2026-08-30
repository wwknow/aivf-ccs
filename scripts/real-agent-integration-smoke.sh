#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
PORT="${AIVF_TEST_CCS_PORT:-50961}"
HEALTH_PORT="${AIVF_TEST_CCS_HEALTH_PORT:-50962}"

cleanup() {
  kill "${PID:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

PYTHONPATH="$ROOT/aivf-ccs-verifier/src" \
python3 -m aivf_ccs_verifier.cli \
  --transport tcp \
  --host 127.0.0.1 \
  --port "$PORT" \
  --health-host 127.0.0.1 \
  --health-port "$HEALTH_PORT" \
  --db "$TMP/evidence.db" \
  --key-file "$TMP/ed25519.seed" \
  --issuer urn:wwknow:aivf:verifier:integration-test \
  --audience urn:wwknow:aivf:executor:integration-test \
  --key-id aivf-ed25519-test &
PID=$!

python3 - "$HEALTH_PORT" <<'PY'
import sys,time,urllib.request
port=sys.argv[1]
url=f"http://127.0.0.1:{port}/healthz"
for _ in range(60):
    try:
        urllib.request.urlopen(url,timeout=.2).read()
        break
    except Exception:
        time.sleep(.1)
else:
    raise SystemExit("temporary AIVF CCS verifier did not become healthy")
PY

OUT="$TMP/agent.out"
CCS_HOST=127.0.0.1 \
CCS_PORT="$PORT" \
AIVF_PUBLIC_VERIFY_URL="" \
AIVF_HTTP_MODE=stub \
node "$ROOT/examples/real-agent-integration/agent.mjs" --demo \
  | tee "$OUT"

grep -q 'SAFE_HTTP: verdict=allow tool_executed=true' "$OUT"
grep -q 'RCE: verdict=deny tool_executed=false' "$OUT"
grep -q 'SSRF: verdict=deny tool_executed=false' "$OUT"
grep -q 'CREDENTIAL: verdict=deny tool_executed=false' "$OUT"
grep -q 'AIVF_REAL_AGENT_SUMMARY=' "$OUT"

echo "PASS: real agent integration smoke"
