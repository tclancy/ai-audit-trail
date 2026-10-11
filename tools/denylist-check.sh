#!/usr/bin/env bash
# Scans content against a LOCAL, UNCOMMITTED denylist: .denylist.local in the main
# worktree's root (gitignored; linked worktrees share it). One case-insensitive
# literal string per line: employer system names, counterparties, field names,
# ticket prefixes. Blank lines and lines starting with # are skipped; CR and
# surrounding whitespace are stripped. A hit reports the pattern's line number in
# the denylist and the line it was found on, never the pattern itself.
#
# Exits 1 on any hit, on a missing, unreadable or pattern-less denylist, on a
# missing file, on a git or grep error, or when given nothing to scan. It does not
# scan history, and a string split across two lines is not found.
#
# Usage: tools/denylist-check.sh [--staged] [--commit-msg FILE] [FILE...]
#   --staged            the staged diff, minus removed lines      (pre-commit stage)
#   --commit-msg FILE   the message git will keep: cut at the scissors line,
#                       comments stripped                         (commit-msg stage)
#   FILE                scanned whole, e.g. a PR title and body   (make pr)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
DENYLIST="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")/.denylist.local"

usage() {
  echo "usage: tools/denylist-check.sh [--staged] [--commit-msg FILE] [FILE...]" >&2
  exit 1
}

# Prints "lineno<TAB>pattern" for every usable denylist line.
patterns() {
  tr -d '\r' < "$DENYLIST" | awk '{
    sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "")
    if ($0 != "" && substr($0, 1, 1) != "#") print NR "\t" $0
  }'
}

require_denylist() {
  [ -r "$DENYLIST" ] || { echo "denylist: cannot read $DENYLIST; create it (see tools/denylist-check.sh)" >&2; exit 1; }
  [ "$(patterns | wc -l)" -gt 0 ] || { echo "denylist: $DENYLIST has no patterns" >&2; exit 1; }
}

# Prints the line number of the first line of file $2 containing literal $1 (any
# case), or nothing. A grep error (exit > 1) aborts the script.
first_hit_line() {
  local rc=0 line
  line=$(grep -aniF -m1 -- "$1" "$2" | cut -d: -f1) || rc=$?
  [ "$rc" -le 1 ] || { echo "denylist: grep failed ($rc) on $2" >&2; exit 1; }
  printf '%s' "$line"
}

# Reports every denylist pattern found in file $2, labelled $1. Returns 1 on any hit.
scan_file() {
  local label=$1 path=$2 hits=0 lineno pat at
  while IFS=$'\t' read -r lineno pat || [ -n "$pat" ]; do
    at=$(first_hit_line "$pat" "$path") || exit 1
    if [ -n "$at" ]; then
      echo "denylist hit: $label line $at matches $DENYLIST line $lineno"
      hits=1
    fi
  done < <(patterns)
  return $hits
}

# Scans the staged diff as text. Lines starting with - are removed content or the
# old-file header, neither of which is being committed, so they are dropped and
# deleting a leak is not itself a hit. A git failure aborts. (Every failure here is
# checked explicitly because errexit is off inside a function called with ||.)
scan_staged() {
  local tmp
  tmp=$(mktemp) || exit 1
  trap 'rm -f "$tmp"' RETURN
  git diff --cached -U0 --text | LC_ALL=C sed '/^-/d' > "$tmp" || { echo "denylist: git diff failed" >&2; exit 1; }
  scan_file "staged diff" "$tmp"
}

# Scans only what git will keep of a commit message: everything above the
# scissors line, with comment lines removed (git stripspace honours commentChar).
scan_commit_msg() {
  local tmp
  tmp=$(mktemp) || exit 1
  trap 'rm -f "$tmp"' RETURN
  LC_ALL=C sed '/^# -* >8 -*$/q' "$1" | git stripspace --strip-comments > "$tmp" || { echo "denylist: cannot read commit message" >&2; exit 1; }
  scan_file "commit message" "$tmp"
}

require_file() {
  [ -f "$1" ] && [ -r "$1" ] || { echo "denylist: cannot read file: $1" >&2; exit 1; }
}

[ $# -gt 0 ] || usage
require_denylist
status=0
while [ $# -gt 0 ]; do
  case $1 in
    --staged) scan_staged || status=1 ;;
    --commit-msg)
      [ $# -ge 2 ] || usage
      require_file "$2"
      scan_commit_msg "$2" || status=1
      shift ;;
    -*) usage ;;
    *)
      require_file "$1"
      scan_file "$1" "$1" || status=1 ;;
  esac
  shift
done
exit $status
