#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

grep -q 'actions/workflows/ci.yml/badge.svg' README.md
grep -q 'https://aivf.wwknow.com/' README.md
grep -q '5-minute Quick Start' README.md
grep -q 'Minimal Node.js SDK example' README.md
grep -q 'aivf-ccs-verifier/' ARCHITECTURE.md

LEGACY_PATTERN='cor''rectover'
if grep -RIni -- "$LEGACY_PATTERN" README.md QUICKSTART.md ARCHITECTURE.md examples .github; then
  echo "FAIL: legacy namespace found in polished public docs/examples"
  exit 1
fi

node examples/sdk-minimal.mjs | tee /tmp/aivf-sdk-minimal.out
grep -q 'safe verdict: allow' /tmp/aivf-sdk-minimal.out
grep -q 'attack blocked: true' /tmp/aivf-sdk-minimal.out
grep -q 'dangerous function ran: false' /tmp/aivf-sdk-minimal.out

echo "PASS: GitHub polish smoke"
