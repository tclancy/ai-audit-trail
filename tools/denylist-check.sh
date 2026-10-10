#!/usr/bin/env bash
# Scans staged content and the commit message against a LOCAL, UNCOMMITTED denylist.
# Create .denylist.local (gitignored) with one case-insensitive pattern per line:
# employer system names, counterparties, field names, ticket prefixes.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
[ -f .denylist.local ] || { echo "denylist: no .denylist.local; create one (see tools/denylist-check.sh)"; exit 1; }
hits=0
while IFS= read -r pat; do
  [ -z "$pat" ] && continue
  if git diff --cached -U0 | grep -qi -- "$pat"; then echo "denylist hit in staged diff: $pat"; hits=1; fi
  if [ -n "${1:-}" ] && [ -f "$1" ] && grep -qi -- "$pat" "$1"; then echo "denylist hit in commit message: $pat"; hits=1; fi
done < .denylist.local
exit $hits
