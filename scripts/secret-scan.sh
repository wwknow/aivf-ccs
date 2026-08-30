#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bad=0

# Block actual private/runtime files, while allowing documentation and code to mention their expected names.
if find . -type f \( -name '*.seed' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -print | grep -q .; then
  echo 'FAIL: private/runtime file found:'
  find . -type f \( -name '*.seed' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -print
  bad=1
fi

# Block private-key material and likely literal production tokens.
for pattern in '-----BEGIN OPENSSH PRIVATE KEY-----' '-----BEGIN PRIVATE KEY-----' 'CLOUDFLARE_API_TOKEN=[A-Za-z0-9_-]' 'CF_API_TOKEN=[A-Za-z0-9_-]'; do
  if grep -RInE --exclude-dir=.git --exclude='secret-scan.sh' -- "$pattern" . >/tmp/aivf-secret-scan.out 2>/dev/null; then
    echo "FAIL: sensitive material pattern found: $pattern"
    cat /tmp/aivf-secret-scan.out
    bad=1
  fi
done

if [ "$bad" -ne 0 ]; then exit 1; fi
echo 'PASS: no private/runtime files or obvious literal secrets found'
