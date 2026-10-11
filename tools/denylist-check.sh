#!/usr/bin/env bash
# Scans content against a LOCAL, UNCOMMITTED denylist: .denylist.local (gitignored),
# one case-insensitive pattern per line (employer system names, counterparties,
# field names, ticket prefixes). Exits 1 on any hit, on a missing denylist, on a
# missing file, or when given nothing to scan. It does not scan history.
#
# Usage: tools/denylist-check.sh [--staged] [FILE...]
#   --staged   the staged diff            (pre-commit stage)
#   FILE       a commit message file      (commit-msg stage)
#              or a PR body               (make pr)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
DENYLIST=.denylist.local

usage() {
  echo "usage: tools/denylist-check.sh [--staged] [FILE...]" >&2
  exit 1
}

require_denylist() {
  [ -f "$DENYLIST" ] || { echo "denylist: no $DENYLIST; create one (see tools/denylist-check.sh)" >&2; exit 1; }
}

# Prints every denylist pattern found in file $2, labelled $1. Returns 1 on any hit.
scan_file() {
  local label=$1 path=$2 hits=0 pat
  while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    if grep -qi -- "$pat" "$path"; then echo "denylist hit in $label: $pat"; hits=1; fi
  done < "$DENYLIST"
  return $hits
}

scan_staged() {
  local tmp
  tmp=$(mktemp)
  git diff --cached -U0 > "$tmp"
  scan_file "staged diff" "$tmp" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
}

[ $# -gt 0 ] || usage
require_denylist
status=0
for arg in "$@"; do
  case $arg in
    --staged) scan_staged || status=1 ;;
    -*) usage ;;
    *)
      [ -f "$arg" ] || { echo "denylist: no such file: $arg" >&2; exit 1; }
      scan_file "$arg" "$arg" || status=1 ;;
  esac
done
exit $status
