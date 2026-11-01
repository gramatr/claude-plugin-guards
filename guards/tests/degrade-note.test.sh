#!/usr/bin/env bash
# guards/tests/degrade-note.test.sh -- the once-per-session note about a degraded service, in all four
# hooks that call it (Bash output, MCP result, SendMessage, prompt), and the recovery note.
#
# The four checks of coordination #128, hook by hook: the first call in a degraded state says so and the next
# ten do not; a restart of the service gives exactly one recovery note; a second session is told for itself.
# Plus: an outage, slowness and an error answer are worded as what they are; an unavailable axis is named;
# a secret found while the service is away is still redacted and still reported; no scanned text reaches a
# note or the state directory; and GUARDS_DEGRADED_NOTE=0 says nothing and writes nothing.
# Stubs stand in for guards-unified (degrade-stub.py); values are fabricated at run time.
# Needs: bash, jq, python3.
#
# HOOKS_DIR=/path/to/other/hooks runs the same cases against another copy (the negative control).

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
has() { case "$2" in *"$3"*) ok ;; *) bad "$1 (no '$3' in: ${2:0:200})" ;; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1 (found '$3')" ;; *) ok ;; esac; }

start_stub() { # start_stub NAME MODE [DELAY] -> endpoint
  mkdir -p "$T/$1"
  python3 -I "$HERE/degrade-stub.py" "$T/$1" "$2" "${3:-0}" >/dev/null 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/$1/port" ] && break; sleep 0.1; done
  echo "http://127.0.0.1:$(cat "$T/$1/port")"
}
UP="$(start_stub up up)"
SLOW="$(start_stub slow slow 6)"
E500="$(start_stub e500 http500)"
AXERR="$(start_stub axerr axiserr)"
UNAVAIL="$(start_stub unavail unavailable)"
DOWN="http://127.0.0.1:1"

MARK="textmarker$(printf '%s' "$$" | tr 0-9 a-j)zq"      # text that must never reach a note or the state
BODY="build step one ok $MARK
build step two ok"
# A secret-shaped value built at run time (never a literal in the source), for the local scanner.
SECRET="password=$(printf 'Tq7v%sN2x' 'Lm9Kd4')RzP8wYb"

payload() { # payload HOOK SID [TEXT]
  local txt="${3:-$BODY}"
  case "$1" in
    bash) jq -nc --arg o "$txt" --arg sid "$2" '{session_id:$sid, tool_name:"Bash", tool_input:{command:"x"}, tool_response:{stdout:$o, stderr:"", interrupted:false, isImage:false}}' ;;
    message) jq -nc --arg m "$txt" --arg sid "$2" '{session_id:$sid, tool_name:"SendMessage", tool_input:{to:"a", message:$m}}' ;;
    prompt) jq -nc --arg p "$txt" --arg sid "$2" '{session_id:$sid, prompt:$p}' ;;
    mcp) jq -nc --arg o "$txt" --arg sid "$2" '{session_id:$sid, tool_name:"mcp__x__y", tool_input:{}, tool_response:[{type:"text", text:$o}]}' ;;
  esac
}
script_of() { case "$1" in bash) echo combined-hook.sh ;; message) echo sendmessage-guard.sh ;; prompt) echo userpromptsubmit-guard.sh ;; mcp) echo mcp-output-guard.sh ;; esac; }
# run HOOK ENDPOINT SID [TEXT] -> hook stdout (state in $ST)
run() {
  payload "$1" "$3" "${4:-}" | env GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="$2" bash "$HOOKS/$(script_of "$1")" 2>/dev/null
}
note_of() { printf '%s' "$1" | jq -r '.systemMessage // empty' 2>/dev/null; }
ctx_of() { printf '%s' "$1" | jq -r '.hookSpecificOutput.additionalContext // empty' 2>/dev/null; }

if [ ! -f "$HOOKS/degrade-lib.sh" ]; then bad "degrade-lib.sh exists"; echo "degrade-note: $pass passed, $fail failed"; exit 1; fi

# --- per hook: down, ten quiet calls, recovery, second session ---------------------------------------
for h in bash message prompt mcp; do
  ST="$T/st-$h"
  out="$(run "$h" "$DOWN" sessA)"
  n="$(note_of "$out")"
  has "$h: the first call in an outage says the service could not be reached" "$n" "could not be reached"
  still_checked="scanned locally"; [ "$h" = prompt ] && still_checked="not being checked for secrets"   # (no case inside $(): bash 3.2 cannot parse it)
  has "$h: ...and says what is still checked" "$n" "$still_checked"
  has "$h: ...and who can look" "$n" "guards_status"
  hasnt "$h: the note is not an instruction to the model" "$n" "You must"
  has "$h: the same text reaches the model as context" "$(ctx_of "$out")" "could not be reached"
  quiet=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    o="$(run "$h" "$DOWN" sessA)"
    [ -z "$(note_of "$o")" ] && [ -z "$(ctx_of "$o")" ] && quiet=$((quiet + 1))
  done
  eq "$h: the next ten calls in the same outage say nothing" "$quiet" 10
  o="$(run "$h" "$DOWN" sessB)"
  has "$h: a second session is told for itself" "$(note_of "$o")" "could not be reached"
  o="$(run "$h" "$UP" sessA)"
  has "$h: the service coming back gives one recovery note" "$(note_of "$o")" "answering again"
  o="$(run "$h" "$UP" sessA)"
  eq "$h: ...and only one" "$(note_of "$o")" ""
  o="$(run "$h" "$DOWN" sessA)"
  has "$h: a second outage in the same session is a new note" "$(note_of "$o")" "could not be reached"
  # nothing from the scanned text, no host name, in any state file
  state="$(cat "$ST"/service/* "$ST"/mode/* 2>/dev/null)"
  hasnt "$h: no scanned text in the state files" "$state" "textmarker"
  hasnt "$h: no host in the state files" "$state" "127.0.0.1"
done

# --- the hooks share one mode per session: a note shown by one is not repeated by another -----------
ST="$T/st-shared"
a="$(note_of "$(run bash "$DOWN" sessS)")"
b="$(note_of "$(run message "$DOWN" sessS)")"
c="$(note_of "$(run mcp "$DOWN" sessS)")"
has "shared: the first hook to see the outage says so" "$a" "could not be reached"
eq "shared: the message hook then says nothing" "$b" ""
eq "shared: nor does the MCP hook" "$c" ""

# --- slowness is not an outage: noted once, no recovery note ------------------------------------------
ST="$T/st-slow"
o="$(run bash "$SLOW" sessL)"
n="$(note_of "$o")"
has "bash: a service that connects but does not answer is slow, not down" "$n" "did not answer within the time limit"
hasnt "bash: ...and is not called unreachable" "$n" "could not be reached"
has "bash: ...and says so is not an outage" "$n" "not an outage"
eq "bash: the second slow call says nothing" "$(note_of "$(run bash "$SLOW" sessL)")" ""
eq "bash: coming back from slow gives no recovery note" "$(note_of "$(run bash "$UP" sessL)")" ""
eq "bash: ...and a later slow call is not noted again" "$(note_of "$(run bash "$SLOW" sessL)")" ""
[ -z "$(ls "$ST/service" 2>/dev/null)" ] && ok || bad "slow: no failure record is written (a slow service is reachable)"

# --- an error answer is named as such, once ----------------------------------------------------------
for h in bash message; do
  ST="$T/st-e500-$h"
  n="$(note_of "$(run "$h" "$E500" sessE)")"
  has "$h: an HTTP error answer is worded as an error" "$n" "answered with an error"
  hasnt "$h: ...and not as unreachable" "$n" "could not be reached"
  eq "$h: ...once" "$(note_of "$(run "$h" "$E500" sessE)")" ""
done

# --- a model axis that is unavailable is named; one-off errors are counted, then promoted ------------
ST="$T/st-unavail"
n="$(note_of "$(run bash "$UNAVAIL" sessU)")"
has "bash: an axis reported unavailable is named" "$n" "injection check is not working"
hasnt "bash: ...and the service is not called down" "$n" "could not be reached"
eq "bash: ...once" "$(note_of "$(run bash "$UNAVAIL" sessU)")" ""
ST="$T/st-axerr"
r1="$(note_of "$(run bash "$AXERR" sessX)")"; r2="$(note_of "$(run bash "$AXERR" sessX)")"; r3="$(note_of "$(run bash "$AXERR" sessX)")"
eq "bash: one-off axis errors are counted, not announced (1)" "$r1" ""
eq "bash: ...(2)" "$r2" ""
has "bash: ...the third in a row is announced" "$r3" "check is not working"
eq "bash: ...and then it is not repeated" "$(note_of "$(run bash "$AXERR" sessX)")" ""
ST="$T/st-axerr2"
run bash "$AXERR" sessY >/dev/null; run bash "$AXERR" sessY >/dev/null; run bash "$UP" sessY >/dev/null
eq "bash: a success resets the count" "$(note_of "$(run bash "$AXERR" sessY)")" ""
ST="$T/st-axmsg"
run message "$UNAVAIL" sessM >/dev/null
eq "message: an axis the secret-only route cannot see is not cleared by it" "$(note_of "$(run mcp "$UP" sessM)")" ""
has "message: ...but the full scan clearing it is a recovery" "$(note_of "$(run message "$UP" sessM)")" "answering again"

# --- the message guard still redacts a secret found locally, even after the note was shown ------------
ST="$T/st-msgsecret"
run message "$DOWN" sessR >/dev/null
o="$(run message "$DOWN" sessR "key $SECRET end")"
has "message: a secret found while the service is away is still redacted" "$(printf '%s' "$o" | jq -r '.hookSpecificOutput.updatedInput.message')" "REDACTED"
has "message: ...and reported" "$(ctx_of "$o")" "a secret was found and redacted by the local-only scan"
eq "message: ...without repeating the outage note" "$(note_of "$o")" ""
has "message: ...and says the service could not be reached for this message" "$(ctx_of "$o")" "could not be reached"
hasnt "message: the redacted value is not echoed" "$o" "$SECRET"

# --- the Bash hook keeps redacting and keeps the note out of the way of its own rewrite ------------------
ST="$T/st-bashsecret"
o="$(run bash "$DOWN" sessQ "ok $SECRET end")"
has "bash: a secret found while the service is away is redacted" "$(printf '%s' "$o" | jq -r '.hookSpecificOutput.updatedToolOutput.stdout')" "REDACTED"
has "bash: ...and the note rides on the same answer" "$(ctx_of "$o")" "could not be reached"
hasnt "bash: the secret is not in the answer" "$o" "$SECRET"

# --- off switch: nothing said, nothing written --------------------------------------------------------------
for h in bash message prompt mcp; do
  ST="$T/st-off-$h"
  o="$(payload "$h" sessO | env GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="$DOWN" GUARDS_DEGRADED_NOTE=0 bash "$HOOKS/$(script_of "$h")" 2>/dev/null)"
  eq "$h: GUARDS_DEGRADED_NOTE=0 adds no note" "$(note_of "$o")" ""
  [ ! -e "$ST" ] && ok || bad "$h: GUARDS_DEGRADED_NOTE=0 writes no state"
done

# --- a state directory that cannot be written: the note is still shown ------------------------------------
: > "$T/afile"
ST="$T/afile/state"
has "bash: an unwritable state directory never hides the note" "$(note_of "$(run bash "$DOWN" sessW)")" "could not be reached"

echo "degrade-note: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
