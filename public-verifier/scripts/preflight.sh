#!/usr/bin/env bash
set -euo pipefail
KEY=../public/ed25519.pub

if [[ ! -f "$KEY" ]]; then
  echo "FAIL: $KEY is missing"
  echo "Export the v0.1 public key before starting v0.2."
  exit 1
fi

PUB="$(tr -d '\r\n ' < "$KEY")"
if [[ ! "$PUB" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "FAIL: public key file is not 64 hex characters"
  exit 1
fi

echo "PASS: public key present: ${PUB}"

if ss -ltnH | awk '{print $4}' | grep -Eq '(^|:)18050$'; then
  echo "FAIL: host port 18050 is already in use"
  exit 1
fi

echo "PASS: host port 18050 is free"

if curl -fsS http://127.0.0.1:8080/healthz >/dev/null; then
  echo "PASS: v0.1 core health endpoint is reachable"
else
  echo "WARN: v0.1 core health endpoint is not reachable at 127.0.0.1:8080"
fi
