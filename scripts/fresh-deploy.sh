#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[1/8] release checks"
bash scripts/secret-scan.sh
bash scripts/oss-boundary-scan.sh
bash scripts/namespace-scan.sh
bash scripts/oss-test-all.sh

echo "[2/8] prepare fresh runtime directories"
mkdir -p data/keys public
# Core container runs as uid/gid 10001.
chown -R 10001:10001 data
chmod 700 data data/keys
rm -f public/ed25519.pub

echo "[3/8] start AIVF CCS core"
cp -n .env.example .env || true
docker compose build
docker compose up -d
sleep 8
curl -fsS http://127.0.0.1:8080/healthz
echo

echo "[4/8] export public key only"
docker compose exec -T aivf-ccs-verifier \
  aivf-ccs-admin public-key \
  | tr -d '\r\n' > public/ed25519.pub
test -s public/ed25519.pub
chmod 644 public/ed25519.pub
echo "public_key=$(cat public/ed25519.pub)"

echo "[5/8] start public verifier"
(
  cd public-verifier
  docker compose build
  docker compose up -d
  sleep 5
  bash scripts/smoke.sh
)

echo "[6/8] start safe agent demo"
(
  cd examples/agent-demo
  docker compose build
  docker compose up -d
  sleep 5
  bash scripts/smoke.sh
)

echo "[7/8] start public portal"
(
  cd examples/public-portal
  docker compose build
  docker compose up -d
  sleep 5
  bash scripts/smoke.sh
  bash scripts/public-hardening-smoke.sh
)

echo "[8/8] final status"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
  | grep -E 'NAMES|aivf-ccs|aivf-wwknow' || true

echo
echo "PASS: fresh AIVF CCS stack deployed"
echo "Core:            http://127.0.0.1:8080/healthz"
echo "Public verifier: http://127.0.0.1:18050/"
echo "Agent demo:      http://127.0.0.1:18051/"
echo "Public portal:   http://127.0.0.1:18052/"
