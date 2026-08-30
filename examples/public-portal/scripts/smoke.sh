#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:18052}"

echo "[portal health]"
HEALTH="$(curl -fsS "$BASE/healthz")"
echo "$HEALTH" | python3 -m json.tool

echo
echo "[homepage]"
STATUS="$(curl -sS -o /tmp/aivfportal-home.html -w '%{http_code}' "$BASE/")"
echo "HTTP $STATUS"
test "$STATUS" = "200"
grep -q "Free Receipt Verifier" /tmp/aivfportal-home.html
grep -q "Agent Runtime Demo" /tmp/aivfportal-home.html

echo
echo "[safe demo through portal]"
SAFE="$(curl -fsS -X POST "$BASE/api/demo/safe")"
echo "$SAFE" | python3 -m json.tool

echo
echo "[attack demo through portal]"
ATTACK="$(curl -fsS -X POST "$BASE/api/demo/attack")"
echo "$ATTACK" | python3 -m json.tool

python3 - "$HEALTH" "$SAFE" "$ATTACK" <<'PY'
import json, sys
health=json.loads(sys.argv[1])
safe=json.loads(sys.argv[2])
attack=json.loads(sys.argv[3])

assert health["status"] == "ok", health
assert health["checks"]["receipt_verifier"]["ok"] is True, health
assert health["checks"]["agent_demo"]["ok"] is True, health

assert safe["ccs_verdict"] == "allow", safe
assert safe["tool_executed"] is True, safe
assert safe["real_shell_used"] is False, safe
assert safe["evidence_verification"]["signature_valid"] is True, safe
assert safe["evidence_verification"]["authentic"] is True, safe

assert attack["ccs_verdict"] == "deny", attack
assert attack["tool_executed"] is False, attack
assert attack["real_shell_used"] is False, attack
assert attack["evidence_verification"]["signature_valid"] is True, attack
assert attack["evidence_verification"]["authentic"] is True, attack

print()
print("PASS: unified portal health")
print("PASS: homepage renders verifier + demo")
print("PASS: safe ALLOW through portal")
print("PASS: attack DENY through portal")
print("PASS: signed evidence verifies through portal")
PY
