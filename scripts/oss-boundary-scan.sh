#!/usr/bin/env bash
set -euo pipefail

bad=0
echo "[OSS public-boundary scan]"

if find . -type f \( -name '*.seed' -o -name '*.db' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \) -print -quit | grep -q .; then
  echo "FAIL: runtime/private file detected"
  bad=1
fi

if grep -RInE --exclude-dir=.git --exclude='oss-boundary-scan.sh' \
  '(\$199|Security Test Kit|premium rule pack|enterprise policy pack)' . >/tmp/oss-internal-plan-hits.txt; then
  echo "FAIL: internal monetization-plan language found in public OSS tree"
  cat /tmp/oss-internal-plan-hits.txt
  bad=1
fi

if [ "$bad" -eq 0 ]; then
  echo "PASS: no private runtime artifacts or internal monetization-plan terms found"
fi
exit "$bad"
