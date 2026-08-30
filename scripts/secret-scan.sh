#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bad=0
tmp_hits="$(mktemp)"
trap 'rm -f "$tmp_hits"' EXIT

# Public-candidate files:
# - tracked/staged files
# - untracked files that are NOT ignored by .gitignore
#
# This deliberately excludes runtime data such as data/evidence.db,
# data/keys/ed25519.seed, .env, and public/ed25519.pub when those paths are
# correctly ignored. If a private file is ever force-added to Git, it becomes a
# cached file and this scan will fail.
candidate_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files --cached --others --exclude-standard -z
  else
    find . -type f ! -path './.git/*' -print0
  fi
}

echo "[secret scan: public candidate files]"

private_found=0
while IFS= read -r -d '' f; do
  f="${f#./}"
  case "$f" in
    *.seed|*.pem|*.p12|*.pfx|*.db|*.sqlite|*.sqlite3)
      echo "FAIL: private/runtime file is publishable or tracked: $f"
      private_found=1
      bad=1
      ;;
  esac
done < <(candidate_files)

# Scan only public-candidate text for obvious private-key material and literal
# production tokens. Ignored runtime files are intentionally outside the public
# repository boundary.
patterns=(
  '-----BEGIN OPENSSH PRIVATE KEY-----'
  '-----BEGIN PRIVATE KEY-----'
  'CLOUDFLARE_API_TOKEN=[A-Za-z0-9_-]+'
  'CF_API_TOKEN=[A-Za-z0-9_-]+'
)

for pattern in "${patterns[@]}"; do
  : > "$tmp_hits"
  while IFS= read -r -d '' f; do
    f="${f#./}"
    [ "$f" = "scripts/secret-scan.sh" ] && continue
    if grep -nIE -- "$pattern" "$f" >>"$tmp_hits" 2>/dev/null; then
      :
    fi
  done < <(candidate_files)

  if [ -s "$tmp_hits" ]; then
    echo "FAIL: sensitive material pattern found: $pattern"
    cat "$tmp_hits"
    bad=1
  fi
done

if [ "$bad" -ne 0 ]; then
  exit 1
fi

echo "PASS: no private/runtime files or obvious literal secrets in public candidate files"
