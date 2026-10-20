#!/usr/bin/env bash
# guards/tests/scan-sh-drift.sh — fail if the vendored scan.sh drifts from the
# server's app/scan.sh in https://github.com/gramatr/guards-unified.
#
# The vendored copy is the server file with its first line (the shebang)
# followed by a two-line vendored header; everything else must be identical,
# byte for byte. Without this check a scanner fix that lands in only one
# place goes unnoticed until someone diffs the files by hand.
#
# Which server file is compared:
#   SERVER_SCAN_SH=path   a local file (used by scan-sh-drift.test.sh; no network)
#   SERVER_REF=ref        a branch or tag of guards-unified
#   otherwise             the tag being built (GITHUB_REF_TYPE=tag) if the server
#                         has the same tag, else main
#
#   bash guards/tests/scan-sh-drift.sh   # exit non-zero on drift

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDORED="${VENDORED_SCAN_SH:-$HERE/../vendor/secret-guard-core/scan.sh}"
RAW="https://raw.githubusercontent.com/gramatr/guards-unified"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

fetch() { # fetch REF -> $TMP; non-zero if the file is not there
  curl -fsSL --retry 3 --retry-delay 2 -o "$TMP" "$RAW/$1/app/scan.sh"
}

if [ -n "${SERVER_SCAN_SH:-}" ]; then
  cp "$SERVER_SCAN_SH" "$TMP" || exit 2
  ref="$SERVER_SCAN_SH"
elif [ -n "${SERVER_REF:-}" ]; then
  fetch "$SERVER_REF" || { echo "drift check: cannot fetch app/scan.sh at $SERVER_REF" >&2; exit 2; }
  ref="$SERVER_REF"
else
  ref=main
  if [ "${GITHUB_REF_TYPE:-}" = tag ] && fetch "$GITHUB_REF_NAME" 2>/dev/null; then
    ref="$GITHUB_REF_NAME"
  else
    fetch main || { echo "drift check: cannot fetch app/scan.sh at main" >&2; exit 2; }
  fi
fi
[ -s "$TMP" ] || { echo "drift check: server scan.sh is empty" >&2; exit 2; }

# The header is exactly lines 2-3 of the vendored copy and must be comments.
if [ "$(sed -n 2,3p "$VENDORED" | grep -c '^#')" -ne 2 ]; then
  echo "drift check: lines 2-3 of the vendored scan.sh are not the two-line '#' header" >&2
  exit 1
fi

if diff -u <(sed -n 1p "$TMP"; sed 1d "$TMP") <(sed -n 1p "$VENDORED"; sed 1,3d "$VENDORED") >&2; then
  echo "scan.sh drift check: vendored copy matches guards-unified app/scan.sh at $ref"
else
  echo "scan.sh drift check FAILED: the vendored copy differs from guards-unified app/scan.sh at $ref (diff above; '-' is the server, '+' is the vendored copy)." >&2
  echo "Change app/scan.sh in guards-unified first, then copy it here keeping the two-line header." >&2
  exit 1
fi
