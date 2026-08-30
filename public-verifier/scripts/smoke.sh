#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:18050}"
echo "Health:"
curl -fsS "$BASE/healthz"; echo
echo "Public key:"
curl -fsS "$BASE/api/public-key"; echo
echo "Homepage status:"
curl -fsS -o /dev/null -w '%{http_code}\n' "$BASE/"
