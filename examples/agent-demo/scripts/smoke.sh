#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:18051}"

echo "[health]"
curl -fsS "$BASE/healthz"
echo

echo
echo "[safe]"
SAFE="$(curl -fsS -X POST "$BASE/api/demo/safe")"
echo "$SAFE" | python3 -m json.tool

echo
echo "[attack]"
ATTACK="$(curl -fsS -X POST "$BASE/api/demo/attack")"
echo "$ATTACK" | python3 -m json.tool

python3 - "$SAFE" "$ATTACK" <<'PY'
import json, sys
safe=json.loads(sys.argv[1]); attack=json.loads(sys.argv[2])

assert safe["ccs_verdict"] == "allow", safe
assert safe["tool_executed"] is True, safe
assert safe["real_shell_used"] is False, safe
assert safe["evidence_verification"]["signature_valid"] is True, safe
assert safe["evidence_verification"]["authentic"] is True, safe

assert attack["ccs_verdict"] == "deny", attack
assert attack["tool_executed"] is False, attack
assert attack["real_shell_used"] is False, attack
assert "RCE" in (attack["block_reason"] or ""), attack
assert attack["evidence_verification"]["signature_valid"] is True, attack
assert attack["evidence_verification"]["authentic"] is True, attack

print()
print("PASS: safe ALLOW + attack DENY + signed evidence verification")
print("PASS: demo never invokes a real shell")
PY
