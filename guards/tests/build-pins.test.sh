#!/usr/bin/env bash
# guards/tests/build-pins.test.sh -- build inputs of this repo must be pinned.
#
# The vendored Dockerfile's external images (FROM, COPY --from) need a tag AND a
# sha256 digest, and a git clone by branch or tag is refused (fetch a commit); every
# GitHub Actions `uses:` in .github must be a full 40-hex commit SHA. Mirrors
# guards-unified/tests/dockerfile_pins_test.sh. Self-checks prove each rule fires.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/../.." || exit 1

check_file() {
  local f="$1" ref base
  { grep -E '^[[:space:]]*FROM[[:space:]]' "$f" | sed -E 's/^[[:space:]]*FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+).*/\2/'
    grep -oE -e '--from=[^[:space:]]+' "$f" | sed 's/^--from=//'
  } | while IFS= read -r ref; do
    case "$ref" in *[/:]*) ;; *) continue ;; esac
    base="${ref%%@*}"
    case "$base" in
      *:latest) echo "$f: floating tag: $ref"; continue ;;
      */*:*|*:*) ;;
      *) echo "$f: no tag: $ref"; continue ;;
    esac
    case "$ref" in *@sha256:*) ;; *) echo "$f: no digest: $ref" ;; esac
  done
  grep -nE 'git[[:space:]]+clone[^|;&]*--(branch|tag)' "$f" | sed "s|^|$f: git clone by branch or tag (use a commit): |"
}

check_actions() {
  grep -rnE '^[[:space:]-]*uses:[[:space:]]*[^[:space:]]+' "$1" --include='*.yml' --include='*.yaml' 2> /dev/null \
    | grep -vE 'uses:[[:space:]]*\./' \
    | grep -vE 'uses:[[:space:]]*[^[:space:]@]+@[0-9a-f]{40}([[:space:]]|$)' \
    | sed 's|^|floating action reference: |'
}

fail=0
out="$(check_file guards/vendor/secret-guard-core/Dockerfile)"
if [ -n "$out" ]; then printf '%s\n' "$out"; fail=1; fi
out="$(check_actions .github)"; if [ -n "$out" ]; then printf '%s\n' "$out"; fail=1; fi

tmp="$(mktemp)"; tdir="$(mktemp -d)"
trap 'rm -rf "$tmp" "$tdir"' EXIT
D="sha256:$(printf '0%.0s' $(seq 1 64))"
printf 'FROM python:3.12-slim\nFROM python:3.12-slim@%s\nCOPY --from=ghcr.io/example/tool:latest /a /b\nCOPY --from=ghcr.io/example/other /c /d\nCOPY --from=builder /e /f\nRUN git clone --depth 1 --branch v1 https://example.invalid/x.git /src\n' "$D" > "$tmp"
n="$(check_file "$tmp" | wc -l)"
if [ "$n" -ne 4 ]; then echo "FAIL: self-check expected 4 findings, got $n"; fail=1; fi
printf 'jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@%s # v4\n      - uses: ./.github/actions/x\n' "$(printf 'a%.0s' $(seq 1 40))" > "$tdir/w.yml"
n="$(check_actions "$tdir" | wc -l)"
if [ "$n" -ne 1 ]; then echo "FAIL: actions self-check expected 1 finding, got $n"; fail=1; fi

[ "$fail" -eq 0 ] && echo "build pins: ok" || echo "build pins: FAILED"
exit "$fail"
