#!/usr/bin/env bash
# guards/tests/hook-deadlines.test.sh — every hook enforces its own deadline
# below its Claude Code `timeout` and applies a deliberate outcome when it
# expires. Claude Code fails OPEN when a hook outlives its timeout (the tool
# call proceeds as if the hook did not exist), so "the hook answered before the
# timeout" is the property under test.
#
# For each hook the scanner (the guards-unified call and the vendored scan.sh)
# is stubbed with something that hangs. The hook runs under `timeout` set to
# the value in hooks.json, standing in for Claude Code's kill, and must answer
# with its own outcome before that. NEGATIVE CONTROL: the same assertion is run
# against the hook as it was before this change (commit $BASE, fetched from git)
# and must FAIL there: that hook hangs until the stand-in kill and produces
# nothing, which is the fail-open. A test that passes on both proves nothing.
#
# Also covered: the lib's crash handling (exit status other than 0/2), the
# pass-through of exit 0 and 2, the `timeout`-less watchdog path, and a
# SendMessage run against a real listener that accepts and never answers (the
# documented degrade to the local scan, within the timeout).
#
# Fabricated values only. Wall time is about the longest hook timeout (the
# control for the publish guard, 40 s): the cases run in parallel.

# shellcheck disable=SC2034  # the PAYLOAD_* variables are read by name in run_case
set -uo pipefail
# This suite needs bash 4 (declare -A) and GNU timeout(1), its stand-in for Claude Code's kill.
# Stock macOS has neither; the watchdog path it would exercise is covered there by deadline-fallback.
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || ! command -v timeout >/dev/null 2>&1; then
  echo "SKIP: hook-deadlines needs bash 4 and GNU timeout (bash ${BASH_VERSION}); deadline-fallback covers the timeout-less path"
  echo "hook-deadlines: 0 passed, 0 failed (skipped)"
  exit 0
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
HOOKS_JSON="$REPO/guards/hooks/hooks.json"
BASE="70ad26775a11c1bc3c608ef91a67291bd4eeda35"   # origin/main before the deadlines change

T="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
pass=0 fail=0
ok()  { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
check() { # check DESC COMMAND... -- passes when the command succeeds
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then ok; else bad "$d"; fi
}

# --- trees: new hooks, and the hooks as they were (control) -------------------
for tree in new old; do
  mkdir -p "$T/$tree/hooks" "$T/$tree/vendor/secret-guard-core"
  printf '#!/usr/bin/env bash\nsleep 300\n' > "$T/$tree/vendor/secret-guard-core/scan.sh"
  chmod +x "$T/$tree/vendor/secret-guard-core/scan.sh"
done
cp "$REPO"/guards/hooks/*.sh "$T/new/hooks/"
have_old=1
if ! git -C "$REPO" cat-file -e "$BASE:guards/hooks/publish-guard.sh" 2>/dev/null; then
  git -C "$REPO" fetch -q --depth=1 origin "$BASE" 2>/dev/null
fi
for f in combined-hook credfile-guard mcp-output-guard publish-guard secret-scan-lib sendmessage-guard userpromptsubmit-guard; do
  git -C "$REPO" show "$BASE:guards/hooks/$f.sh" > "$T/old/hooks/$f.sh" 2>/dev/null || have_old=0
done
if [ "$have_old" -eq 0 ]; then
  if [ "${DEADLINE_REQUIRE_CONTROL:-0}" = 1 ]; then bad "commit $BASE not available for the negative control"; fi
  echo "note: commit $BASE not available, negative controls skipped"
fi

# --- stubs that hang ----------------------------------------------------------
mkdir -p "$T/stubs"
for s in curl realpath; do   # curl ignores -m on purpose: only the hook's own deadline can end it
  printf '#!/usr/bin/env bash\nsleep 300\n' > "$T/stubs/$s"; chmod +x "$T/stubs/$s"
done
# curl hangs for everything but credfile's case, which hangs on realpath instead
# (the one external call it makes); each case gets its own PATH.
mkdir -p "$T/stubs-cred"; cp "$T/stubs/realpath" "$T/stubs-cred/realpath"

hook_timeout() { jq -r --arg n "$1" '[.hooks[][].hooks[] | select(.args[0] | endswith("/" + $n))][0].timeout' "$HOOKS_JSON"; }

PAYLOAD_publish="$(jq -nc --arg c "gh issue create -R o/r --title t --body 'a plain sentence'" --arg cwd "$T" '{tool_name:"Bash", tool_input:{command:$c}, cwd:$cwd, permission_mode:"default"}')"
PAYLOAD_credfile="$(jq -nc --arg cwd "$T" '{tool_name:"Read", tool_input:{file_path:"notes.txt"}, cwd:$cwd, permission_mode:"default"}')"
PAYLOAD_combined='{"tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_response":{"stdout":"a plain sentence","stderr":"","interrupted":false,"isImage":false}}'
PAYLOAD_mcp='{"tool_name":"mcp__demo__lookup","tool_input":{},"tool_response":[{"type":"text","text":"a plain sentence"}]}'
PAYLOAD_sendmessage='{"tool_name":"SendMessage","tool_input":{"to":"x","message":"a plain sentence"}}'
PAYLOAD_userprompt='{"prompt":"a plain sentence"}'

declare -A SCRIPT=(
  [publish]=publish-guard [credfile]=credfile-guard [combined]=combined-hook
  [mcp]=mcp-output-guard [sendmessage]=sendmessage-guard [userprompt]=userpromptsubmit-guard)

# Expected outcome per hook, as a predicate over the hook's stdout file. Each
# requires a non-empty file first: some jq versions exit 0 for -e on empty input.
outcome_publish()     { [ -s "$1" ] && jq -e '.hookSpecificOutput.permissionDecision == "deny"' "$1"; }
outcome_credfile()    { outcome_publish "$1"; }
outcome_sendmessage() { outcome_publish "$1"; }
outcome_combined()    { [ -s "$1" ] && jq -e '.hookSpecificOutput.updatedToolOutput | (.stdout | test("the command ran, but its output was withheld")) and .stderr == ""' "$1"; }
outcome_mcp()         { [ -s "$1" ] && jq -e '.hookSpecificOutput.updatedToolOutput[0].text | test("the tool ran, but its result was withheld")' "$1"; }
outcome_userprompt()  { [ ! -s "$1" ]; }   # advisory: no note, no decision

echo "plain text" > "$T/notes.txt"

run_case() { # run_case NAME TREE -- in the background; results under $T/res
  local name="$1" tree="$2" limit stubs payload var="PAYLOAD_$1" s0 s1
  limit="$(hook_timeout "${SCRIPT[$name]}.sh")"
  stubs="$T/stubs"; [ "$name" = credfile ] && stubs="$T/stubs-cred"
  payload="${!var}"
  mkdir -p "$T/res"
  (
    s0="$(date +%s.%N)"
    printf '%s' "$payload" | env "PATH=$stubs:$PATH" HOME="$T" \
      GUARDS_ENDPOINT="http://127.0.0.1:9" GUARDS_SECRET_SCAN="$T/$tree/vendor/secret-guard-core/scan.sh" \
      timeout "$limit" bash "$T/$tree/hooks/${SCRIPT[$name]}.sh" > "$T/res/$name.$tree.out" 2>/dev/null
    echo $? > "$T/res/$name.$tree.rc"
    s1="$(date +%s.%N)"
    awk -v a="$s0" -v b="$s1" 'BEGIN { printf "%.1f\n", b - a }' > "$T/res/$name.$tree.secs"
  ) &
  CASE_PIDS+=($!)
}
CASE_PIDS=()

for n in publish credfile combined mcp sendmessage userprompt; do
  run_case "$n" new
  [ "$have_old" -eq 1 ] && run_case "$n" old
done

# --- meanwhile: the real-listener degrade and the lib's own behavior -----------
python3 -I - "$T/port" <<'EOF' &
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
conns = []
while True:
    conns.append(s.accept()[0])   # accept, read nothing, never answer
EOF
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
PORT="$(cat "$T/port")"
sm_limit="$(hook_timeout sendmessage-guard.sh)"
sm0="$(date +%s)"
printf '%s' '{"tool_name":"SendMessage","tool_input":{"to":"x","message":"a plain sentence"}}' \
  | env GUARDS_ENDPOINT="http://127.0.0.1:$PORT" timeout "$sm_limit" bash "$REPO/guards/hooks/sendmessage-guard.sh" > "$T/sm.out" 2>/dev/null
sm_rc=$?; sm_secs=$(( $(date +%s) - sm0 ))
check "sendmessage vs unresponsive service: exits 0 in time (rc=$sm_rc, ${sm_secs}s of ${sm_limit}s)" test "$sm_rc" -eq 0 -a "$sm_secs" -lt "$sm_limit"
check "sendmessage vs unresponsive service: degrades to the local scan, allow + note" \
  jq -e '.hookSpecificOutput.permissionDecision == "allow" and (.hookSpecificOutput.additionalContext | test("unreachable"))' "$T/sm.out"

# Lib: pass-through of 0 and 2, crash outcome per kind, expiry without `timeout`.
LIB="$REPO/guards/hooks/deadline-lib.sh"
mklib_hook() { # mklib_hook KIND SECS BODY -> path
  local f; f="$(mktemp -p "$T" hook.XXXXXX.sh)"
  printf '#!/usr/bin/env bash\n. "%s" && guards_deadline %s %s\n%s\n' "$LIB" "$1" "$2" "$3" > "$f"; echo "$f"
}
h="$(mklib_hook deny 5 'cat >/dev/null; echo passthrough; echo errline >&2; exit 2')"
out="$(echo '{}' | bash "$h" 2>"$T/e")"; rc=$?
check "exit 2 passes through (stdout, stderr, status)" test "$rc" -eq 2 -a "$out" = passthrough -a "$(cat "$T/e")" = errline
h="$(mklib_hook deny 5 'cat >/dev/null; echo fine; exit 0')"
check "exit 0 passes through" test "$(echo '{}' | bash "$h" 2>/dev/null)" = fine
for kind in deny withhold-bash withhold-mcp silent; do
  h="$(mklib_hook "$kind" 5 'cat >/dev/null; echo partial-output-must-be-dropped; exit 1')"
  case "$kind" in withhold-mcp) in='{"tool_name":"mcp__a__b","tool_response":"raw text"}' ;; *) in='{"tool_name":"Bash","tool_response":{"stdout":"raw text","interrupted":true}}' ;; esac
  echo "$in" | bash "$h" > "$T/crash.$kind" 2>/dev/null; rc=$?
  check "$kind: a crash (exit 1) exits 0" test "$rc" -eq 0
  check "$kind: a crash drops the inner output" bash -c "! grep -q 'partial-output\|raw text' '$T/crash.$kind'"
  case "$kind" in
    deny)          check "deny: crash outcome is a deny" jq -e '.hookSpecificOutput.permissionDecision == "deny"' "$T/crash.$kind" ;;
    withhold-bash) check "withhold-bash: crash outcome withholds, keeps interrupted" jq -e '.hookSpecificOutput.updatedToolOutput | (.stdout | test("withheld")) and .interrupted == true' "$T/crash.$kind" ;;
    withhold-mcp)  check "withhold-mcp: string result replaced by a string" jq -e '.hookSpecificOutput.updatedToolOutput | type == "string" and test("withheld")' "$T/crash.$kind" ;;
    silent)        check "silent: no output" test ! -s "$T/crash.$kind" ;;
  esac
done
h="$(mklib_hook withhold-mcp 5 'cat >/dev/null; exit 1')"
echo '{"tool_name":"mcp__a__b","tool_response":{"content":[{"type":"text","text":"raw"}],"isError":false}}' | bash "$h" > "$T/o" 2>/dev/null
check "withhold-mcp: object result keeps its wrapper" jq -e '.hookSpecificOutput.updatedToolOutput | .isError == false and (.content[0].text | test("withheld"))' "$T/o"
echo '{"tool_name":"mcp__a__b","tool_response":{"image":"x"}}' | bash "$h" > "$T/o" 2>/dev/null
check "withhold-mcp: a shape the hook never scans is left alone" test ! -s "$T/o"

# Expiry without `timeout` installed: the pure-bash watchdog.
mkdir -p "$T/notimeout"
for d in /usr/local/bin /usr/bin /bin; do
  for f in "$d"/*; do n="$(basename "$f")"; [ "$n" = timeout ] || [ -e "$T/notimeout/$n" ] || ln -s "$f" "$T/notimeout/$n" 2>/dev/null; done
done
h="$(mklib_hook deny 2 'cat >/dev/null; sleep 300')"
w0="$(date +%s)"
echo '{}' | env "PATH=$T/notimeout" bash "$h" > "$T/o" 2>/dev/null
check "no timeout binary: watchdog expires the hook and denies in time" test "$(( $(date +%s) - w0 ))" -lt 8 -a "$(jq -r .hookSpecificOutput.permissionDecision "$T/o")" = deny

# --- collect the parallel cases -------------------------------------------------
wait "${CASE_PIDS[@]}"
for n in publish credfile combined mcp sendmessage userprompt; do
  limit="$(hook_timeout "${SCRIPT[$n]}.sh")"
  secs="$(cat "$T/res/$n.new.secs" 2>/dev/null || echo 999)"; rc="$(cat "$T/res/$n.new.rc" 2>/dev/null || echo 999)"
  check "$n: exits 0 (rc=$rc)" test "$rc" -eq 0
  check "$n: answers in ${secs}s, at least 3 s inside the ${limit}s hook timeout" awk -v s="$secs" -v l="$limit" 'BEGIN { exit !(s <= l - 3) }'
  check "$n: deadline outcome" "outcome_$n" "$T/res/$n.new.out"
  if [ "$have_old" -eq 1 ]; then
    orc="$(cat "$T/res/$n.old.rc")"
    check "$n control: the unmodified hook is killed at its ${limit}s timeout (rc=$orc), i.e. fails open" test "$orc" -eq 124
    if [ "$n" != userprompt ] && "outcome_$n" "$T/res/$n.old.out" >/dev/null 2>&1; then bad "$n control: the unmodified hook produced the deadline outcome"; else ok; fi
  fi
done

echo "hook-deadlines: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
