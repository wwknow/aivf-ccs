#!/usr/bin/env bash
set -euo pipefail
fail=0

if ss -ltn | awk '{print $4}' | grep -Eq '(^|:)18052$'; then
  echo "FAIL: host port 18052 is already in use"
  fail=1
else
  echo "PASS: host port 18052 is free"
fi

if curl -fsS http://127.0.0.1:18050/healthz >/dev/null; then
  echo "PASS: v0.2-A Receipt Verifier is reachable"
else
  echo "FAIL: v0.2-A Receipt Verifier is not reachable"
  fail=1
fi

if curl -fsS http://127.0.0.1:18051/healthz >/dev/null; then
  echo "PASS: v0.2-B Agent Demo is reachable"
else
  echo "FAIL: v0.2-B Agent Demo is not reachable"
  fail=1
fi

exit "$fail"
