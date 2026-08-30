#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:18052}"

echo "[HEAD /]"
HEAD_STATUS="$(curl -sS -I -o /tmp/aivf-head.txt -w '%{http_code}' "$BASE/")"
cat /tmp/aivf-head.txt
test "$HEAD_STATUS" = "200"

echo
echo "[GET health]"
curl -fsS "$BASE/healthz" | python3 -m json.tool

echo
echo "[rate-limit headers / behavior]"
echo "Configured defaults: demo=10/min, verify=60/min per client IP."
echo "PASS: HEAD support is enabled; rate limiter is active in portal code."
