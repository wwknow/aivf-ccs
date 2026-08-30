#!/usr/bin/env bash
set -euo pipefail

fail=0

if ss -ltn | awk '{print $4}' | grep -Eq '(^|:)18051$'; then
  echo "FAIL: host port 18051 is already in use"
  fail=1
else
  echo "PASS: host port 18051 is free"
fi

if curl -fsS http://127.0.0.1:8080/healthz >/dev/null; then
  echo "PASS: v0.1 CCS Core health is reachable"
else
  echo "FAIL: v0.1 CCS Core health is not reachable"
  fail=1
fi

if curl -fsS http://127.0.0.1:18050/healthz >/dev/null; then
  echo "PASS: v0.2-A Public Receipt Verifier is reachable"
else
  echo "FAIL: v0.2-A Public Receipt Verifier is not reachable"
  fail=1
fi

exit "$fail"
