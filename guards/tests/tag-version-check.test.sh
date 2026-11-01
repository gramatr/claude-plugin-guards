#!/usr/bin/env bash
# guards/ci/tag-version-check.sh: tag equals VERSION and guards-unified's VERSION.
# curl is a stub keyed on the URL (fabricated versions, no network). NEGATIVE
# CONTROL: the previous check (tag equals this repo's VERSION only) accepts the
# same mismatch that the new one must fail.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/../ci/tag-version-check.sh"
pass=0 fail=0
ok() { pass=$((pass+1)); }
no() { fail=$((fail+1)); echo "FAIL: $1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
# Stub curl: STUB_TAG_CODE/STUB_TAG_BODY answer the .../v<tag>/VERSION url, STUB_MAIN_CODE/STUB_MAIN_BODY the .../main/VERSION one.
cat > "$T/bin/curl" <<'STUB'
#!/usr/bin/env bash
out="" url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -w|--max-time|--retry|--retry-delay) shift 2;; -*) shift;; *) url="$1"; shift;; esac; done
case "$url" in
  */main/VERSION) code="${STUB_MAIN_CODE:-200}"; body="${STUB_MAIN_BODY:-}";;
  *)              code="${STUB_TAG_CODE:-404}";  body="${STUB_TAG_BODY:-}";;
esac
[ "$code" = FAIL ] && { echo "curl: (6) Could not resolve host" >&2; exit 6; }
printf '%s\n' "$body" > "$out"; printf '%s' "$code"
STUB
chmod +x "$T/bin/curl"

run() { # run TAG OWNVERSION [ENV...] -> rc, output in $T/out
  printf '%s\n' "$2" > "$T/VERSION"
  local tag="$1"; shift 2
  env PATH="$T/bin:$PATH" VERSION_FILE="$T/VERSION" "$@" bash "$CHECK" "$tag" > "$T/out" 2>&1
}
expect() { # expect DESC WANT_RC [grep pattern] -- after run
  local d="$1" want="$2" pat="${3:-}" rc="$RC"
  [ "$rc" -eq "$want" ] || { no "$d (rc=$rc, want $want): $(head -c 200 "$T/out")"; return; }
  [ -z "$pat" ] || grep -q "$pat" "$T/out" || { no "$d (output lacks '$pat'): $(head -c 200 "$T/out")"; return; }
  ok
}

run v9.9.9 9.9.9 STUB_MAIN_BODY=9.9.9; RC=$?;                       expect "tag absent upstream, main equal: passes" 0 "matches"
run v9.9.9 9.9.9 STUB_TAG_CODE=200 STUB_TAG_BODY=9.9.9; RC=$?;      expect "same tag upstream, equal: passes" 0 "matches"
run v9.9.9 9.9.9 STUB_MAIN_BODY=9.9.8; RC=$?;                       expect "main differs: fails" 1 "guards-unified's VERSION (9.9.8 at main)"
run v9.9.9 9.9.9 STUB_TAG_CODE=200 STUB_TAG_BODY=9.9.8; RC=$?;      expect "tag exists upstream with another version: fails" 1 "9.9.8 at v9.9.9"
run v9.9.9 9.9.8 STUB_MAIN_BODY=9.9.9; RC=$?;                       expect "tag differs from own VERSION: fails" 1 "does not match VERSION"
run v9.9.9 9.9.9 STUB_TAG_CODE=FAIL; RC=$?;                         expect "unreachable: fails, never a silent pass" 1 "Could not read"
run v9.9.9 9.9.9 STUB_TAG_CODE=500; RC=$?;                          expect "server error: fails" 1 "HTTP 500"
run v9.9.9 9.9.9 STUB_MAIN_CODE=503; RC=$?;                         expect "main unreadable: fails" 1 "HTTP 503"
run v9.9.9 9.9.9 STUB_MAIN_BODY="<html>oops</html>"; RC=$?;         expect "garbage body: fails" 1 "not a version"

# Negative control: the previous inline check, run on the mismatching case, passes.
old_check() { local t="${1#v}" f; f="$(tr -d '[:space:]' < "$T/VERSION")"; [ "$t" = "$f" ]; }
printf '9.9.9\n' > "$T/VERSION"
if old_check v9.9.9 && ! env PATH="$T/bin:$PATH" VERSION_FILE="$T/VERSION" STUB_MAIN_BODY=9.9.8 bash "$CHECK" v9.9.9 >/dev/null 2>&1; then
  ok
else
  no "control: the previous check was expected to accept the mismatch that the new one rejects"
fi
echo "tag-version-check: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
