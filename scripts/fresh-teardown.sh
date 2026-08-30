#!/usr/bin/env bash
set -euo pipefail
docker rm -f \
  aivf-wwknow-public-portal \
  aivf-ccs-agent-demo \
  aivf-ccs-public-verifier \
  aivf-ccs-verifier \
  2>/dev/null || true
echo "AIVF CCS containers removed. Runtime files were not deleted."
