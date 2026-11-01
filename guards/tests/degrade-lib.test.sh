#!/usr/bin/env bash
# guards/tests/degrade-lib.test.sh -- the shared degraded-service state (hooks/degrade-lib.sh).
#
# Pins: how one curl answer is classified (down, slow, http, malformed, ok) against real curl and loopback
# stubs; that a connect-class failure is recorded per address and any answer clears it; that two writers
# never leave half a line; that an unreadable or unwritable state directory means "behave as before" and
# never hides a notice; the two-day cleanup; session ids with odd characters; the mode transitions that
# decide when the person is told something; and the off switch. Then, hook by hook, that a hook run
# against a refused port records the failure and against a live stub clears it, and that
# GUARDS_DEGRADED_NOTE=0 writes nothing. A stub service stands in for guards-unified; all values are fabricated.
# Needs: bash, jq, python3, curl.
#
# HOOKS_DIR=/path/to/other/hooks runs the same cases against a different copy of the hooks (the negative
# control: the tree before degrade-lib.sh existed fails the cases that need it).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="${HOOKS_DIR:-$HERE/../hooks}"
T="$(mktemp -d)"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
eq() { if [ "$2" = "$3" ]; then ok; else bad "$1 (got: '$2', want: '$3')"; fi; }

if [ ! -f "$HOOKS/degrade-lib.sh" ]; then
  bad "degrade-lib.sh exists in $HOOKS"
  echo "degrade-lib: $pass passed, $fail failed"; exit 1
fi

start_stub() { # start_stub NAME MODE [DELAY] -> prints the endpoint
  mkdir -p "$T/$1"
  python3 -I "$HERE/degrade-stub.py" "$T/$1" "$2" "${3:-0}" >/dev/null 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/$1/port" ] && break; sleep 0.1; done
  echo "http://127.0.0.1:$(cat "$T/$1/port")"
}

# in_lib CODE -- run CODE in a fresh shell with the lib sourced and its own state directory.
in_lib() {
  GUARDS_STATE_DIR="${ST:-$T/state}" bash -c ". '$HOOKS/degrade-lib.sh'; $1"
}

# --- 1. classification of one curl answer, table ---------------------------------------------------
cls() { in_lib "dg_classify $1 '$2' $3; printf %s \"\$DG_OUTCOME\""; }
eq "200 with a scan body is ok" "$(cls 0 '200 0.0010' 1)" ok
eq "200 without a scan body is malformed" "$(cls 0 '200 0.0010' 0)" malformed
eq "500 is http" "$(cls 0 '500 0.0010' 0)" http
eq "413 is http" "$(cls 0 '413 0.0010' 1)" http
eq "connection refused (7) is down" "$(cls 7 '000 0.000000' 0)" down
eq "name not found (6) is down" "$(cls 6 '000 0.000000' 0)" down
eq "timeout before the connection (28, no connect time) is down" "$(cls 28 '000 0.000000' 0)" down
eq "timeout after the connection (28) is slow" "$(cls 28 '000 0.000312' 0)" slow
eq "timeout while the body arrived (28, status known) is slow" "$(cls 28 '200 0.000312' 0)" slow
eq "a connection broken after connect (56) is http" "$(cls 56 '000 0.000312' 0)" http
eq "SIGPIPE of an earlier pipeline stage does not hide an answer" "$(cls 141 '200 0.000312' 1)" ok
eq "SIGPIPE with no answer is not an answer" "$(cls 141 '000 0.000000' 0)" http

eq "the three-field answer of real curl is read: a blackholed attempt is down and took a second" "$(in_lib "dg_classify 28 '000 0.000000 1.001203' 0; printf '%s %s' \"\$DG_OUTCOME\" \"\$DG_TOTAL\"")" "down 1.001203"
eq "...and a refused one took no time" "$(in_lib "dg_classify 7 '000 0.000000 0.000412' 0; printf '%s %s' \"\$DG_OUTCOME\" \"\$DG_TOTAL\"")" "down 0.000412"

# --- 2. classification against real curl ----------------------------------------------------------
UP="$(start_stub up up)"
SLOW="$(start_stub slow slow 3)"
E500="$(start_stub e500 http500)"
MAL="$(start_stub mal malformed)"
real() { # real URL TOTAL_TIMEOUT -> outcome
  local meta rc
  meta="$(printf '{"text":"x"}' | curl -sS --connect-timeout 1 -m "$2" -X POST "$1/v1/scan" -H 'Content-Type: application/json' -d @- -o "$T/body" -w '%{http_code} %{time_connect}' 2>/dev/null)"; rc=$?
  in_lib "b=0; jq -e '.findings | type == \"array\"' '$T/body' >/dev/null 2>&1 && b=1; dg_classify $rc '$meta' \$b; printf %s \"\$DG_OUTCOME\""
}
eq "real curl: a live stub is ok" "$(real "$UP" 2)" ok
eq "real curl: a closed port is down" "$(real http://127.0.0.1:1 2)" down
eq "real curl: a blackholed address (documentation range) is down" "$(real http://192.0.2.1:8700 2)" down
eq "real curl: a stub that sleeps past -m is slow, not down" "$(real "$SLOW" 1)" slow
eq "real curl: a 500 is http" "$(real "$E500" 2)" http
eq "real curl: a 200 that is not a scan result is malformed" "$(real "$MAL" 2)" malformed

# --- 3. the service record -------------------------------------------------------------------------
ST="$T/s3"
in_lib 'dg_service_down http://svc.invalid:8700 rc7'
F="$(ls "$ST/service" | head -1)"
case "$(cat "$ST/service/$F")" in [0-9]*" 1 rc7") ok ;; *) bad "first failure writes 'EPOCH 1 rc7' (got: $(cat "$ST/service/$F"))" ;; esac
in_lib 'dg_service_down http://svc.invalid:8700 rc7'
case "$(cat "$ST/service/$F")" in [0-9]*" 2 rc7") ok ;; *) bad "second failure counts 2 (got: $(cat "$ST/service/$F"))" ;; esac
eq "one file per address" "$(ls "$ST/service" | wc -l | tr -d ' ')" 1
in_lib 'dg_service_down http://other.invalid:8700 rc6'
eq "another address gets its own file" "$(ls "$ST/service" | wc -l | tr -d ' ')" 2
case "$(ls "$ST/service")" in *svc*|*other*|*invalid*|*8700*) bad "file names must not carry the host" ;; *) ok ;; esac
case "$(cat "$ST/service/"*)" in *invalid*|*8700*) bad "the record must not carry the host" ;; *) ok ;; esac
in_lib 'dg_observe http://svc.invalid:8700 0 "500 0.001" 0'
[ ! -e "$ST/service/$F" ] && ok || bad "an answer, even an error one, clears the record"
in_lib 'dg_observe http://svc.invalid:8700 7 "000 0.000000" 0; printf %s "$DG_OUTCOME" > "'"$T"'/o1"'
eq "dg_observe classifies a refused connection as down" "$(cat "$T/o1")" down
[ -e "$ST/service/$F" ] && ok || bad "dg_observe records a down outcome"
in_lib 'dg_observe http://svc.invalid:8700 0 "200 0.001" 1'
[ ! -e "$ST/service/$F" ] && ok || bad "a full success clears the record"

# --- 4. two writers at once never leave half a line -----------------------------------------------
ST="$T/s4"
for _ in 1 2; do
  ( for _ in $(seq 1 30); do in_lib 'dg_service_down http://svc.invalid:8700 rc7'; done ) &
done
wait
F="$(ls "$ST/service" | head -1)"
eq "concurrent writers: one record file, no stray temp files" "$(ls "$ST/service" | wc -l | tr -d ' ')" 1
case "$(cat "$ST/service/$F")" in [0-9]*" "[0-9]*" rc7") ok ;; *) bad "concurrent writers leave one whole line (got: $(cat "$ST/service/$F"))" ;; esac
eq "concurrent writers: the record is a single line" "$(wc -l < "$ST/service/$F" | tr -d ' ')" 1

# --- 5. unreadable or unwritable state: behave as before, never hide a notice ----------------------
: > "$T/afile"
ST="$T/afile/state"   # a path below a regular file: nothing can be created there
out="$(in_lib 'dg_service_down http://svc.invalid:8700 rc7; dg_service_up http://svc.invalid:8700; dg_mode_update sid1 down http://svc.invalid:8700; printf "%s" "$DG_NOTICE"; dg_mode_update sid1 down http://svc.invalid:8700; printf " %s" "$DG_NOTICE"' 2>&1)"
eq "unwritable state: no error output, and a note is still due every time" "$out" "enter enter"
ST="$T/s5b"; mkdir -p "$ST/mode"; echo 'garbage line' > "$ST/mode/sid2"
eq "an unreadable mode file reads as full" "$(in_lib 'dg_mode_update sid2 down x; printf %s "$DG_NOTICE"')" enter

# --- 6. two-day cleanup -----------------------------------------------------------------------------
ST="$T/s6"; mkdir -p "$ST/service" "$ST/mode"
touch -d '4 days ago' "$ST/service/111" "$ST/mode/old1" 2>/dev/null || touch -t "$(date -d '4 days ago' +%Y%m%d%H%M 2>/dev/null || date -v-4d +%Y%m%d%H%M)" "$ST/service/111" "$ST/mode/old1"
in_lib 'dg_service_down http://svc.invalid:8700 rc7; dg_mode_update newsid down http://svc.invalid:8700'
[ ! -e "$ST/service/111" ] && [ ! -e "$ST/mode/old1" ] && ok || bad "files older than two days are removed when a new one is started"
[ -e "$ST/mode/newsid" ] && ok || bad "the new mode file is kept"

# --- 7. session ids ---------------------------------------------------------------------------------
ST="$T/s7"
eq "a plain id names its own file" "$(in_lib 'dg_sidkey sess-1_A; printf %s "$DG_KEY"')" sess-1_A
k1="$(in_lib 'dg_sidkey "a/b c"; printf %s "$DG_KEY"')"
k2="$(in_lib 'dg_sidkey "../x"; printf %s "$DG_KEY"')"
case "$k1" in h[0-9]*) ok ;; *) bad "an id with odd characters becomes h<number> (got: $k1)" ;; esac
[ "$k1" != "$k2" ] && ok || bad "different odd ids get different keys"
eq "an empty id shares one key" "$(in_lib 'dg_sidkey ""; printf %s "$DG_KEY"')" nosid
long="$(printf 'a%.0s' $(seq 1 300))"
case "$(in_lib "dg_sidkey $long; printf %s \"\$DG_KEY\"")" in h[0-9]*) ok ;; *) bad "an id over 128 characters is turned into a number" ;; esac
r="$(in_lib 'dg_sidkey "a/b c"; dg_mode_update "$DG_KEY" down http://svc.invalid:8700; printf %s "$DG_NOTICE "; dg_mode_update "$DG_KEY" down http://svc.invalid:8700; printf %s "$DG_NOTICE"')"
eq "an odd session id still gets one note, not one per call" "$r" "enter none"
[ -z "$(find "$ST" -name '*/*' 2>/dev/null)" ] && ok || bad "an odd id must not escape the state directory"

# --- 8. the mode transitions that decide when to tell the person ------------------------------------
ST="$T/s8"
seq_notice() { # seq_notice KEY MODE... -> notice per step
  local k="$1" out="" m; shift
  for m in "$@"; do out="$out$(in_lib "dg_mode_update '$k' $m http://svc.invalid:8700; printf '%s ' \"\$DG_NOTICE\"")"; done
  printf '%s' "${out% }"
}
eq "up, up: nothing" "$(seq_notice t1 full full)" "none none"
eq "full to down: one note, then none while it stays down, then one recovery" "$(seq_notice t2 down down down full full)" "enter none none recover none"
eq "a second outage is a new note" "$(seq_notice t3 down full down full)" "enter recover enter recover"
eq "slow is noted once per session and never as a recovery" "$(seq_notice t4 slow full slow full slow)" "slow none none none none"
eq "slow to down is an outage; down to slow is not a recovery" "$(seq_notice t5 slow down slow full)" "slow enter none none"
eq "an unavailable axis is noted once; clearing it is a recovery" "$(seq_notice t6 axis:injection axis:injection full)" "enter none recover"
eq "a second axis joining is a new note" "$(seq_notice t7 axis:injection axis:pii+injection full)" "enter enter recover"
eq "two sessions do not share a mode" "$(seq_notice ta down)/$(seq_notice tb down)" "enter/enter"
eq "no session id: told once per machine, through the shared key" "$(seq_notice nosid down down full)" "enter none recover"
ST="$T/s8up"
in_lib 'dg_observe http://svc.invalid:8700 0 "200 0.001" 1; dg_mode_update sid full http://svc.invalid:8700'
[ ! -e "$ST" ] && ok || bad "the service-up path creates no state directory"

# --- 9. the off switch -------------------------------------------------------------------------------
ST="$T/s9"
r="$(GUARDS_DEGRADED_NOTE=0 in_lib 'dg_service_down http://svc.invalid:8700 rc7; dg_mode_update sid down http://svc.invalid:8700; printf %s "$DG_NOTICE"')"
eq "GUARDS_DEGRADED_NOTE=0: no notice" "$r" none
[ ! -e "$ST" ] && ok || bad "GUARDS_DEGRADED_NOTE=0: nothing is written"

# --- 10. hook by hook: a refused port is recorded, a live stub clears it, output is identical --------
DOWN="http://127.0.0.1:1"
BODY="build step 1 ok
build step 2 ok"
run_hook() { # run_hook HOOK ENDPOINT [ENV...] -> stdout
  local h="$1" ep="$2"; shift 2
  case "$h" in
    bash) jq -nc --arg o "$BODY" '{session_id:"s10", tool_name:"Bash", tool_input:{command:"x"}, tool_response:{stdout:$o, stderr:"", interrupted:false, isImage:false}}' | env GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="$ep" "$@" bash "$HOOKS/combined-hook.sh" 2>/dev/null ;;
    message) jq -nc '{session_id:"s10", tool_name:"SendMessage", tool_input:{to:"a", message:"all good"}}' | env GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="$ep" "$@" bash "$HOOKS/sendmessage-guard.sh" 2>/dev/null ;;
    prompt) jq -nc '{session_id:"s10", prompt:"please summarise the design doc"}' | env GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="$ep" "$@" bash "$HOOKS/userpromptsubmit-guard.sh" 2>/dev/null ;;
    mcp) jq -nc --arg o "$BODY" '{session_id:"s10", tool_name:"mcp__x__y", tool_input:{}, tool_response:[{type:"text", text:$o}]}' | env GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="$ep" "$@" bash "$HOOKS/mcp-output-guard.sh" 2>/dev/null ;;
  esac
}
for h in bash message prompt mcp; do
  ST="$T/s10-$h"; export ST
  run_hook "$h" "$DOWN" > "$T/out-down-$h"
  n="$(ls "$ST/service" 2>/dev/null | wc -l | tr -d ' ')"
  eq "$h hook: a refused port is recorded" "$n" 1
  in_lib "dg_service_down $UP rc7"   # as if this service had been down a moment ago
  eq "$h hook: (setup) two addresses are recorded" "$(ls "$ST/service" | wc -l | tr -d ' ')" 2
  run_hook "$h" "$UP" > "$T/out-up-$h"
  n="$(ls "$ST/service" 2>/dev/null | wc -l | tr -d ' ')"
  eq "$h hook: ...and a live service clears its own record, only" "$n" 1
  ST="$T/s10-off-$h"
  run_hook "$h" "$DOWN" GUARDS_DEGRADED_NOTE=0 > "$T/out-off-$h"
  [ ! -e "$ST" ] && ok || bad "$h hook: GUARDS_DEGRADED_NOTE=0 writes no state"
done

# --- the session id out of a hook payload (dg_rawsid): no fork for the usual compact payload, jq otherwise ---
sid_of() { RAW_IN="$1" in_lib 'RAW="$RAW_IN"; dg_rawsid; printf %s "$DG_SID"' 2>/dev/null; }
eq "dg_rawsid: a compact payload with session_id first" "$(sid_of '{"session_id":"abc-1","tool_name":"Bash"}')" abc-1
eq "dg_rawsid: session_id not first (read with jq)" "$(sid_of '{"tool_name":"Bash","session_id":"abc-2"}')" abc-2
eq "dg_rawsid: spaced JSON (read with jq)" "$(sid_of '{ "session_id": "abc-3", "x": 1 }')" abc-3
eq "dg_rawsid: no session id at all" "$(sid_of '{"tool_name":"Bash"}')" ""
eq "dg_rawsid: the words session_id inside tool output do not count" "$(sid_of '{"tool_name":"Bash","tool_response":{"stdout":"x session_id y"},"session_id":"abc-4"}')" abc-4

echo "degrade-lib: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
