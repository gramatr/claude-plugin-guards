#!/usr/bin/env bash
# guards/tests/scan-bash-compat.test.sh -- the vendored scan.sh must run on bash 3.2 (stock macOS).
# (Plugin copy of guards-unified tests/scan_bash_compat_test.sh; the scan.sh it checks is
# guards/vendor/secret-guard-core/scan.sh, which must match the server's app/scan.sh.)
#
# WHY: scan.sh used the bash 4 lowercase expansion in two places. On bash 3.2 that
# is "bad substitution", so every context rule (KEY=value, JSON and URL passwords,
# Authorization values ...) silently stopped redacting on a Mac, while all tests,
# which run on Linux with bash 5, stayed green. It shipped in v0.2.9.
#
# Two checks:
#   1. Static: no bash-4-only syntax in the non-comment lines of the vendored *.sh (the
#      lowercase and uppercase expansions, associative arrays, mapfile/readarray,
#      |& and &>> redirections, coproc, [[ -v ]]). Works anywhere; a negative
#      control proves the check can fail.
#   2. Dynamic: the context rules, with gitleaks skipped, behave as expected under
#      the bash named by SCAN_BASH (default: bash). CI runs it with /bin/bash on a
#      macOS runner, where that is bash 3.2.
#
#   SCAN_BASH=/bin/bash bash guards/tests/scan-bash-compat.test.sh
#
# All values are fabricated, assembled from fragments. Needs bash and grep.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HERE/../vendor/secret-guard-core"
SCAN="$APP/scan.sh"
SCAN_BASH="${SCAN_BASH:-bash}"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

echo "scan under: $("$SCAN_BASH" --version | head -1)"

# --- 1. static ----------------------------------------------------------------
# bash4_hits FILE -> lines of FILE that use bash-4-only syntax, comments excluded.
bash4_hits() {
  grep -n -v '^[[:space:]]*#' "$1" | grep -E \
    -e '\$\{[A-Za-z_][A-Za-z0-9_]*[,^]' \
    -e '\$\{[0-9@*][,^]' \
    -e '(declare|local|typeset)[[:space:]]+-[a-zA-Z]*A' \
    -e '(^|[^A-Za-z0-9_])(mapfile|readarray|coproc)([^A-Za-z0-9_]|$)' \
    -e '\|&' \
    -e '&>>' \
    -e '\[\[[[:space:]]+-v[[:space:]]' || true
}
for f in "$APP"/*.sh; do
  hits="$(bash4_hits "$f")"
  if [ -z "$hits" ]; then ok; else bad "bash-4-only syntax in ${f##*/}: $(printf '%s' "$hits" | head -3 | tr '\n' ' ')"; fi
done
neg="$(mktemp)"
trap 'rm -f "$neg"' EXIT
printf '%s\n' 'x() { local a="${1,,}"; }' 'declare -A m' > "$neg"
if [ -n "$(bash4_hits "$neg")" ]; then ok; else bad "negative control: the static check did not flag bash-4 syntax"; fi

# --- 2. dynamic ---------------------------------------------------------------
VAL="q7Zk2mX9vB4nL8wR3tY6pC"
scan() { printf '%s\n' "$1" | env SECRET_GUARD_SKIP_GITLEAKS=1 "$SCAN_BASH" "$SCAN" 2> /dev/null; }
redacts() { # redacts DESC INPUT
  local out; out="$(scan "$2")"
  case "$out" in *"$VAL"*) bad "$1: the value is still in the output" ;; *REDACTED*) ok ;; *) bad "$1: nothing redacted ($out)" ;; esac
}
keeps() { # keeps DESC INPUT
  local out; out="$(scan "$2")"
  if [ "$out" = "$2" ]; then ok; else bad "$1: text was changed ($out)"; fi
}
# Key names are assembled so this file holds no credential-looking line.
PW="pass""word"; SEC="sec""ret"; TOK="to""ken"
PWU="PASS""WORD"; SECC="Sec""ret"; TOKC="To""ken"   # upper and capitalised forms, spelled out: bash 3.2 has no case expansion
NL=$'\n'
redacts "key=value"                  "x = 1${NL}DB_${PWU}=$VAL"
redacts "json key"                   "{\"$PW\": \"$VAL\"}"
redacts "yaml-style key"             "api_${SEC}: $VAL"
redacts "url password"               "postgres://app:$VAL@db.example.invalid/x"
redacts "last segment is the credential" "AUTH_${TOK}=$VAL"
redacts "camelCase that only starts like a reference" "${SEC}Valid=$VAL"
keeps   "snake_case reference key"   "${SEC}_vault_id=$VAL"
keeps   "ALL_CAPS reference key"     "CLIENT_${SEC}_BWS_ID=$VAL"
keeps   "camelCase reference key"    "client${SECC}BwsId=$VAL"
keeps   "placeholder value"          "${TOK}: changeme"
keeps   "plain prose"                "see the docs for how a ${PW} is stored"
keeps   "source code, call as value" "const access${TOKC} = createSignedToken(userId)"

echo "scan-bash-compat: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
