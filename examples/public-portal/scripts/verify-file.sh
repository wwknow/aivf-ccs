#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/receipt.json"
  exit 2
fi

curl -fsS \
  -H 'Content-Type: application/json' \
  --data-binary @"$1" \
  http://127.0.0.1:18052/api/verify \
  | python3 -m json.tool
