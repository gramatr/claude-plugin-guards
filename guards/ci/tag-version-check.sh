#!/usr/bin/env bash
# guards/ci/tag-version-check.sh TAG — the plugin's tag check.
#
# claude-plugin-guards and guards-unified are one product in two packages and
# carry the same version and the same tag (guards-unified docs/RELEASING.md,
# "Release rules"). Plugin installs track main and are identified by commit, so a
# tag here is a label, but a label that disagrees with VERSION, or with
# guards-unified's VERSION, defeats the point of lockstep. Fails loudly:
#
#   1. TAG (without the leading v) must equal this repo's VERSION file.
#   2. It must equal guards-unified's VERSION, read at the same tag when that tag
#      exists (HTTP 404 means it does not yet; the plugin is tagged first) and
#      otherwise at main. An unreachable or unreadable answer FAILS: it is never
#      a silent pass (re-run the job).
#
# Environment (for tests): VERSION_FILE, UNIFIED_RAW (raw-content base URL).
set -uo pipefail
TAG="${1:-${GITHUB_REF_NAME:-}}"
VERSION_FILE="${VERSION_FILE:-VERSION}"
UNIFIED_RAW="${UNIFIED_RAW:-https://raw.githubusercontent.com/gramatr/guards-unified}"
SEMVER='^[0-9]+\.[0-9]+\.[0-9]+$'

[ -n "$TAG" ] || { echo "::error::no tag given"; exit 1; }
tag="${TAG#v}"
file="$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null)"
if [ "$tag" != "$file" ]; then
  echo "::error::Tag v$tag does not match VERSION ($file) on this commit. Bump VERSION in a PR, merge it, THEN tag that merge commit."
  exit 1
fi

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fetch() { # fetch REF -- prints the HTTP status ("000" when curl failed); body in $T/body
  local code
  code="$(curl -sS --retry 3 --retry-delay 2 --max-time 20 -o "$T/body" -w '%{http_code}' "$UNIFIED_RAW/$1/VERSION" 2>"$T/err")" || code=000
  printf '%s' "${code:-000}"
}
ref="v$tag"
code="$(fetch "$ref")"
if [ "$code" = 404 ]; then ref=main; code="$(fetch main)"; fi
if [ "$code" != 200 ]; then
  echo "::error::Could not read guards-unified's VERSION at $ref (HTTP $code), so lockstep could not be checked. Re-run this job; the check fails rather than pass unchecked. $(head -c 200 "$T/err" 2>/dev/null)"
  exit 1
fi
other="$(tr -d '[:space:]' < "$T/body")"
if ! printf '%s' "$other" | grep -Eq "$SEMVER"; then
  echo "::error::guards-unified's VERSION at $ref is not a version number; lockstep could not be checked."
  exit 1
fi
if [ "$other" != "$tag" ]; then
  echo "::error::Tag v$tag does not match guards-unified's VERSION ($other at $ref). The two repos carry the same version: bump and merge guards-unified first (docs/RELEASING.md in guards-unified, Release rules, rule 4)."
  exit 1
fi
echo "Tag v$tag matches VERSION here and guards-unified's VERSION at $ref."
