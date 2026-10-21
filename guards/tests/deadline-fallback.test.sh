#!/usr/bin/env bash
# guards/tests/deadline-fallback.test.sh -- the deadline wrapper on a machine
# without `timeout` (stock macOS).
#
# deadline-lib.sh bounds every hook with `timeout` when it exists and with a
# bash watchdog when it does not. CI runs on Linux, where `timeout` exists, so
# the watchdog path was only ever tested against a hung command. It had a race:
# when the hook finished in time, the cleanup killed the watchdog's `sleep`,
# the watchdog fell through to its next line, planted the "expired" flag, and
# the wrapper reported a timeout that never happened. The fail-closed hooks then
# denied an ordinary call at random (3 percent of plain reads on a Mac, far more
# on a fast Linux box with `timeout` hidden).
#
# Here a PATH without `timeout` or `gtimeout` is built from the real one, then:
#   1. a hook that finishes at once is never reported as expired (many runs);
#   2. the real credential-file guard allows an ordinary read every time;
#   3. a hook that really hangs is still cut at its deadline with a deny;
#   4. under CPU load a hook's deny is never lost: the watchdog is a subshell, and
#      an EXIT trap that removed the work directory used to run in it when it was
#      killed, so the wrapper then read nothing and a deny came out as no decision.
# Set GUARDS_HOOKS_DIR to run the same checks against another copy of the hooks
# (for example the previous deadline-lib.sh, to see cases 1 and 2 fail).
# Fabricated values only. Needs bash, jq.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="${GUARDS_HOOKS_DIR:-$HERE/../hooks}"
BASH_BIN="$(command -v bash)"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d)"
LOAD_PIDS=""
trap 'for p in $LOAD_PIDS; do kill "$p" 2> /dev/null; done; rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"
# Every tool on PATH except `timeout` and `gtimeout`. One `ln` per directory (the
# first directory on PATH wins), not one per file: a per-file loop takes minutes
# on a machine with thousands of tools on PATH and slow process launches.
IFS=: read -ra dirs <<< "$PATH"
for ((i = ${#dirs[@]} - 1; i >= 0; i--)); do
  [ -d "${dirs[$i]}" ] && ln -sf "${dirs[$i]}"/* "$BIN"/ 2> /dev/null
done
rm -f "$BIN/timeout" "$BIN/gtimeout"

if env -i PATH="$BIN" "$BASH_BIN" -c 'command -v timeout > /dev/null 2>&1 || command -v gtimeout > /dev/null 2>&1'; then
  bad "setup: timeout is still visible on the test PATH"
else
  ok
fi

# 1. A hook that finishes at once: no output means the wrapper did not call it expired.
cat > "$T/quick.sh" << EOF
. "$HOOKS/deadline-lib.sh" && guards_deadline deny 5
exit 0
EOF
RUNS=60
spurious=0 noisy=0
for _ in $(seq 1 "$RUNS"); do
  out="$(printf '{}' | env PATH="$BIN" "$BASH_BIN" "$T/quick.sh" 2> "$T/quick.err")"
  [ -z "$out" ] || spurious=$((spurious + 1))
  [ ! -s "$T/quick.err" ] || noisy=$((noisy + 1))
done
if [ "$spurious" -eq 0 ]; then ok; else bad "a hook that finished at once was reported as expired $spurious of $RUNS times"; fi
if [ "$noisy" -eq 0 ]; then ok; else bad "a hook that finished at once wrote to stderr $noisy of $RUNS times (a bash job notice such as 'Terminated')"; fi

# 2. The real credential-file guard on an ordinary read, without timeout.
payload='{"tool_name":"Read","permission_mode":"default","cwd":"/tmp","tool_input":{"file_path":"/etc/hosts"}}'
RUNS2=40
spurious=0
for _ in $(seq 1 "$RUNS2"); do
  out="$(printf '%s' "$payload" | env PATH="$BIN" "$BASH_BIN" "$HOOKS/credfile-guard.sh" 2> /dev/null)"
  [ -z "$out" ] || spurious=$((spurious + 1))
done
if [ "$spurious" -eq 0 ]; then ok; else bad "credfile-guard denied or asked on an ordinary read $spurious of $RUNS2 times without timeout"; fi

# 3. A hook that really hangs is still cut at its deadline, with a deny.
cat > "$T/hang.sh" << EOF
. "$HOOKS/deadline-lib.sh" && guards_deadline deny 2
sleep 30
EOF
start=$SECONDS
out="$(printf '{}' | env PATH="$BIN" "$BASH_BIN" "$T/hang.sh" 2> /dev/null)"
elapsed=$((SECONDS - start))
case "$out" in
  *'"permissionDecision":"deny"'*) ok ;;
  *) bad "a hung hook was not denied at its deadline (output: ${out:-empty})" ;;
esac
if [ "$elapsed" -le 6 ]; then ok; else bad "a hung hook took ${elapsed}s against a 2s deadline"; fi

# 4. A deny survives CPU load. 3 busy loops per core (at most 24) for the duration.
cat > "$T/denier.sh" << EOF
. "$HOOKS/deadline-lib.sh" && guards_deadline deny 5
printf '{"decision":"deny"}\n'
exit 0
EOF
cores="$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo 2)"
loops=$((cores * 3)); [ "$loops" -le 24 ] || loops=24
for ((k = 0; k < loops; k++)); do
  (while :; do :; done) &
  LOAD_PIDS="$LOAD_PIDS $!"
done
sleep 1
RUNS3=30
lost=0
for _ in $(seq 1 "$RUNS3"); do
  out="$(printf '{}' | env PATH="$BIN" "$BASH_BIN" "$T/denier.sh" 2> /dev/null)"
  [ -n "$out" ] || lost=$((lost + 1))
done
for p in $LOAD_PIDS; do kill "$p" 2> /dev/null; done
wait 2> /dev/null
LOAD_PIDS=""
if [ "$lost" -eq 0 ]; then ok; else bad "a deny was lost $lost of $RUNS3 times under CPU load (the answer was deleted before it was read)"; fi

echo "deadline-fallback: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
