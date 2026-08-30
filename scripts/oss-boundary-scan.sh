#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bad=0
tmp_hits="$(mktemp)"
trap 'rm -f "$tmp_hits"' EXIT

candidate_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files --cached --others --exclude-standard -z
  else
    find . -type f ! -path './.git/*' -print0
  fi
}

echo "[OSS public-boundary scan]"

while IFS= read -r -d '' f; do
  f="${f#./}"
  case "$f" in
    *.seed|*.pem|*.p12|*.pfx|*.db|*.sqlite|*.sqlite3)
      echo "FAIL: runtime/private file is publishable or tracked: $f"
      bad=1
      ;;
  esac
done < <(candidate_files)

internal_pattern='(\$199|Security Test Kit|premium rule pack|enterprise policy pack)'
: > "$tmp_hits"

while IFS= read -r -d '' f; do
  f="${f#./}"
  [ "$f" = "scripts/oss-boundary-scan.sh" ] && continue
  if grep -nIE -- "$internal_pattern" "$f" >>"$tmp_hits" 2>/dev/null; then
    :
  fi
done < <(candidate_files)

if [ -s "$tmp_hits" ]; then
  echo "FAIL: internal monetization-plan language found in public candidate files"
  cat "$tmp_hits"
  bad=1
fi

if [ "$bad" -eq 0 ]; then
  echo "PASS: no private runtime artifacts or internal monetization-plan terms in public candidate files"
fi

exit "$bad"
