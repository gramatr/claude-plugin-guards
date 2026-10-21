#!/usr/bin/env bash
# guards/tests/gitleaks-assets-drift.sh -- fail if the vendored gitleaks-assets.sha256 differs
# from guards-unified's docs/gitleaks-assets.sha256 (comments and order aside).
#
# The self-heal script checks a downloaded patched gitleaks against the vendored file; the
# server's file is what its CI builds must hash to. If they drift, a correct download fails the
# check (or, worse, a wrong one passes). Same source selection as scan-sh-drift.sh:
#   SERVER_FILE=path   a local file (used by the tests; no network)
#   SERVER_REF=ref     a branch or tag of guards-unified
#   otherwise          the tag being built if the server has it, else main
#
#   bash guards/tests/gitleaks-assets-drift.sh   # exit non-zero on drift
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDORED="${VENDORED_FILE:-$HERE/../vendor/secret-guard-core/gitleaks-assets.sha256}"
RAW="https://raw.githubusercontent.com/gramatr/guards-unified"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

fetch() { curl -fsSL --retry 3 --retry-delay 2 -o "$TMP" "$RAW/$1/docs/gitleaks-assets.sha256"; }

if [ -n "${SERVER_FILE:-}" ]; then
  cp "$SERVER_FILE" "$TMP" || exit 2
  ref="$SERVER_FILE"
elif [ -n "${SERVER_REF:-}" ]; then
  fetch "$SERVER_REF" || { echo "gitleaks assets drift: cannot fetch the server file at $SERVER_REF" >&2; exit 2; }
  ref="$SERVER_REF"
else
  ref=main
  if [ "${GITHUB_REF_TYPE:-}" = tag ] && fetch "$GITHUB_REF_NAME" 2> /dev/null; then
    ref="$GITHUB_REF_NAME"
  else
    fetch main || { echo "gitleaks assets drift: cannot fetch the server file at main" >&2; exit 2; }
  fi
fi
[ -s "$TMP" ] || { echo "gitleaks assets drift: the server file is empty" >&2; exit 2; }

norm() { grep -v '^[[:space:]]*#' "$1" | grep . | sort; }
if diff -u <(norm "$TMP") <(norm "$VENDORED") >&2; then
  echo "gitleaks assets drift check: vendored hashes match guards-unified docs/gitleaks-assets.sha256 at $ref"
else
  echo "gitleaks assets drift check FAILED: the vendored hashes differ from guards-unified docs/gitleaks-assets.sha256 at $ref ('-' is the server, '+' is the vendored copy)." >&2
  echo "Change the server file first (it is what its CI builds must hash to), then copy it here." >&2
  exit 1
fi
