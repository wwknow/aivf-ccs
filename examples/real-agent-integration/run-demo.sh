#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export CCS_HOST="${CCS_HOST:-127.0.0.1}"
export CCS_PORT="${CCS_PORT:-50051}"
export AIVF_PUBLIC_VERIFY_URL="${AIVF_PUBLIC_VERIFY_URL:-http://127.0.0.1:18050/api/verify}"
export AIVF_HTTP_MODE="${AIVF_HTTP_MODE:-real}"

node examples/real-agent-integration/agent.mjs --demo
