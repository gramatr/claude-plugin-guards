#!/usr/bin/env bash
# hook-deadlines.test.sh must never wait unbounded. Its one external call is the
# git fetch of the negative-control commit; here that fetch hangs (a fake git on
# PATH), and the suite must still end by itself, quickly, saying the control was
# unavailable. NEGATIVE CONTROL: the suite as it was before the bound (read from
# git history) is run the same way under an outer limit and must be cut off by
# it, i.e. it hangs. A test that passes on both proves nothing.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
if ! command -v timeout >/dev/null 2>&1; then echo "SKIP: needs GNU timeout"; echo "hook-deadlines-bounded: 0 passed, 0 failed (skipped)"; exit 0; fi
PRE="${PRE_BOUND_COMMIT:-4aed0a5}"   # origin/main before the bound
pass=0 fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "FAIL: $1"; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
REAL_GIT="$(command -v git)"
mkdir -p "$T/bin"
cat > "$T/bin/git" <<STUB
#!/usr/bin/env bash
# fake git: a fetch hangs (a stalled network); everything else is the real git
for a in "\$@"; do [ "\$a" = fetch ] && exec sleep 300; done
exec "$REAL_GIT" "\$@"
STUB
chmod +x "$T/bin/git"
NOBASE=0000000000000000000000000000000000000001   # a commit that does not exist, so the suite tries to fetch it

# Fixed suite: the fetch limit (3 s here) ends the hang; the suite finishes on its own.
s0=$(date +%s)
out="$(env PATH="$T/bin:$PATH" DEADLINE_BASE="$NOBASE" DEADLINE_FETCH_TIMEOUT=3 DEADLINE_REQUIRE_CONTROL=0 \
  timeout -k 2 150 bash "$REPO/guards/tests/hook-deadlines.test.sh" 2>&1)"; rc=$?
secs=$(( $(date +%s) - s0 ))
[ "$rc" -ne 124 ] && ok || bad "fixed suite hung on a stalled fetch (outer limit reached after ${secs}s)"
printf '%s' "$out" | grep -q 'negative controls skipped' && ok || bad "fixed suite did not report the control as unavailable"
printf '%s' "$out" | grep -q '^hook-deadlines: .* 0 failed' && ok || bad "fixed suite did not finish with 0 failed: $(printf '%s' "$out" | tail -3)"

# The overall limit: a suite that outlives it is a FAIL with a message.
out2="$(env DEADLINE_TEST_LIMIT=5 timeout -k 2 60 bash "$REPO/guards/tests/hook-deadlines.test.sh" 2>&1)"; rc2=$?
[ "$rc2" -eq 124 ] && printf '%s' "$out2" | grep -q 'exceeded its overall limit' && ok || bad "overall limit did not stop the suite with a message (rc=$rc2)"

# Negative control: the suite before the bound, same stalled fetch, outer limit of 20 s: it must hang.
"$REAL_GIT" -C "$REPO" cat-file -e "$PRE:guards/tests/hook-deadlines.test.sh" 2>/dev/null \
  || GIT_TERMINAL_PROMPT=0 timeout -k 2 60 "$REAL_GIT" -C "$REPO" fetch -q --depth=1 origin "$PRE" 2>/dev/null
if "$REAL_GIT" -C "$REPO" cat-file -e "$PRE:guards/tests/hook-deadlines.test.sh" 2>/dev/null; then
  mkdir -p "$T/old/guards/tests" "$T/old/guards/hooks"
  "$REAL_GIT" -C "$REPO" show "$PRE:guards/tests/hook-deadlines.test.sh" \
    | sed "s/^BASE=\"[0-9a-f]*\"/BASE=$NOBASE/" > "$T/old/guards/tests/hook-deadlines.test.sh"
  cp "$REPO"/guards/hooks/*.sh "$T/old/guards/hooks/"; cp -r "$REPO/guards/hooks/hooks.json" "$T/old/guards/hooks/" 2>/dev/null
  ( cd "$T/old" && "$REAL_GIT" init -q . && true )
  env PATH="$T/bin:$PATH" timeout -k 2 20 bash "$T/old/guards/tests/hook-deadlines.test.sh" >/dev/null 2>&1; orc=$?
  [ "$orc" -eq 124 ] && ok || bad "control: the unbounded suite was expected to hang on the stalled fetch (rc=$orc)"
else
  [ "${DEADLINE_REQUIRE_CONTROL:-0}" = 1 ] && bad "commit $PRE not available for the negative control" || echo "note: commit $PRE not available, negative control skipped"
fi
echo "hook-deadlines-bounded: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
