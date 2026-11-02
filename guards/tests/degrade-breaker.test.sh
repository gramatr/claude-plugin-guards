#!/usr/bin/env bash
# guards/tests/degrade-breaker.test.sh -- the breaker for a service that is known to be gone.
#
# A blackholed or half-open address costs a hook its whole connect timeout on every call (1 s on the secret
# route, 2 s in the message hook, 3 s in the prompt hook). After one attempt has failed SLOWLY at the
# connection stage, later calls inside GUARDS_BREAKER_SECS open no connection at all. Cheap failures never
# trip it (a refused connection and a name that does not resolve are over in a millisecond), nor do a slow
# answer, an error status or a malformed body: the service is there in those cases.
#
# A fake `curl` first on PATH stands in for the network, so the cases take no wall time and every connection
# the hooks open is counted in a log: "no connection" is proved by the log not growing, not by a stopwatch.
# Values are fabricated. Needs: bash, jq.
#
# HOOKS_DIR=/path/to/other/hooks runs the same cases against another copy (the negative control).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="${HOOKS_DIR:-$HERE/../hooks}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME" "$T/bin"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
eq() { if [ "$2" = "$3" ]; then ok; else bad "$1 (got: '$2', want: '$3')"; fi; }

if [ ! -f "$HOOKS/degrade-lib.sh" ] || ! grep -q dg_breaker_open "$HOOKS/degrade-lib.sh"; then
  bad "the breaker exists in $HOOKS"; echo "degrade-breaker: $pass passed, $fail failed"; exit 1
fi

# The fake curl: logs one line per call, then answers as FAKE_CURL_MODE says.
cat > "$T/bin/curl" <<'SH'
#!/usr/bin/env bash
echo "curl" >> "$FAKE_CURL_LOG"
w="" out=""
while [ $# -gt 0 ]; do
  case "$1" in -w) w="$2"; shift ;; -o) out="$2"; shift ;; esac
  shift
done
cat > /dev/null
scan='{"findings":[{"type":"secret","verdict":"clean","reason_code":null,"detail":{}},{"type":"pii","verdict":"clean","reason_code":null,"detail":{"entities":[]}},{"type":"injection","verdict":"clean","reason_code":null,"detail":{"score":0.1}}],"redacted_text":""}'
emit() { # emit CODE CONNECT TOTAL BODY RC
  if [ -n "$out" ]; then printf '%s' "$4" > "$out"; else printf '%s' "$4"; fi
  case "$w" in '\n'*) printf '\n' ;; esac
  printf '%s %s %s' "$1" "$2" "$3"
  exit "$5"
}
case "${FAKE_CURL_MODE:-blackhole}" in
  blackhole) emit 000 0.000000 1.001203 "" 28 ;;
  refused) emit 000 0.000000 0.000412 "" 7 ;;
  nodns) emit 000 0.000000 0.003100 "" 6 ;;
  slow) emit 000 0.000212 2.001100 "" 28 ;;
  e500) emit 500 0.000212 0.010000 '{"detail":"x"}' 0 ;;
  malformed) emit 200 0.000212 0.010000 '{"unexpected":true}' 0 ;;
  ok) emit 200 0.000212 0.010000 "$scan" 0 ;;
esac
SH
chmod +x "$T/bin/curl"
export FAKE_CURL_LOG="$T/curl.log"
: > "$FAKE_CURL_LOG"
calls() { wc -l < "$FAKE_CURL_LOG" | tr -d ' '; }

BODY="build step one ok
build step two ok"
payload() { # payload HOOK SID
  case "$1" in
    bash) jq -nc --arg o "$BODY" --arg sid "$2" '{session_id:$sid, tool_name:"Bash", tool_input:{command:"x"}, tool_response:{stdout:$o, stderr:"", interrupted:false, isImage:false}}' ;;
    message) jq -nc --arg m "$BODY" --arg sid "$2" '{session_id:$sid, tool_name:"SendMessage", tool_input:{to:"a", message:$m}}' ;;
    prompt) jq -nc --arg p "$BODY" --arg sid "$2" '{session_id:$sid, prompt:$p}' ;;
    mcp) jq -nc --arg o "$BODY" --arg sid "$2" '{session_id:$sid, tool_name:"mcp__x__y", tool_input:{}, tool_response:[{type:"text", text:$o}]}' ;;
  esac
}
script_of() { case "$1" in bash) echo combined-hook.sh ;; message) echo sendmessage-guard.sh ;; prompt) echo userpromptsubmit-guard.sh ;; mcp) echo mcp-output-guard.sh ;; esac; }
# run HOOK [ENV...] -- one hook call against the fake network (state in $ST, endpoint a fixed fake address)
run() {
  local h="$1"; shift
  payload "$h" s1 | env "PATH=$T/bin:$PATH" GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="http://svc.invalid:8700" "$@" bash "$HOOKS/$(script_of "$h")" 2>/dev/null
}
record() { cat "$ST"/service/* 2>/dev/null; }
age_record() { # age_record SECONDS -- pretend the last failure was that long ago
  local f line rest
  for f in "$ST"/service/*; do
    line="$(cat "$f")"; rest="${line#* }"
    printf '%s %s\n' "$(( $(date +%s) - $1 ))" "$rest" > "$f"
  done
}

for h in bash message prompt mcp; do
  # --- a blackholed service: the first call pays, later calls inside the window open nothing -------------
  ST="$T/st-$h"; : > "$FAKE_CURL_LOG"
  FAKE_CURL_MODE=blackhole run "$h" > /dev/null
  first="$(calls)"
  [ "$first" -ge 1 ] && ok || bad "$h: the first call tries the service"
  case "$(record)" in [0-9]*" "[0-9]*" rc28 slow") ok ;; *) bad "$h: a slow connect failure is recorded as slow (got: $(record))" ;; esac
  rec1="$(record)"
  : > "$FAKE_CURL_LOG"
  for _ in 1 2 3 4 5; do FAKE_CURL_MODE=blackhole run "$h" > /dev/null; done
  eq "$h: five later calls inside the window open no connection" "$(calls)" 0
  eq "$h: skipped calls leave the record alone, so the window does not slide" "$(record)" "$rec1"

  # --- after the window one call probes -----------------------------------------------------------------
  age_record 31
  : > "$FAKE_CURL_LOG"
  FAKE_CURL_MODE=blackhole run "$h" > /dev/null
  n="$(calls)"
  [ "$n" -ge 1 ] && [ "$n" -le 2 ] && ok || bad "$h: after the window the service is tried again (calls: $n)"
  rec2="$(record)"; c1="${rec1#* }"; c1="${c1%% *}"; c2="${rec2#* }"; c2="${c2%% *}"
  [ "$c2" -gt "$c1" ] && [ "${rec2%% *}" -gt "$(( $(date +%s) - 31 ))" ] && ok || bad "$h: the failed probe is counted and opens a new window (was: $rec1, now: $rec2)"
  : > "$FAKE_CURL_LOG"
  FAKE_CURL_MODE=blackhole run "$h" > /dev/null
  eq "$h: ...and the calls after the probe are skipped again" "$(calls)" 0

  # --- a successful probe closes the breaker -------------------------------------------------------------
  age_record 31
  FAKE_CURL_MODE=ok run "$h" > /dev/null
  [ -z "$(record)" ] && ok || bad "$h: an answer from the service clears the record"
  : > "$FAKE_CURL_LOG"
  FAKE_CURL_MODE=ok run "$h" > /dev/null
  [ "$(calls)" -ge 1 ] && ok || bad "$h: with the record gone the service is used again"

  # --- failures that must not trip it ---------------------------------------------------------------------
  for mode in refused nodns slow e500 malformed; do
    ST="$T/st-$h-$mode"; : > "$FAKE_CURL_LOG"
    FAKE_CURL_MODE=$mode run "$h" > /dev/null
    : > "$FAKE_CURL_LOG"
    FAKE_CURL_MODE=$mode run "$h" > /dev/null
    [ "$(calls)" -ge 1 ] && ok || bad "$h: '$mode' does not trip the breaker (the second call still tried the service)"
  done

  # --- off switch and unwritable state --------------------------------------------------------------------
  ST="$T/st-$h-off"
  FAKE_CURL_MODE=blackhole run "$h" GUARDS_BREAKER_SECS=0 > /dev/null
  : > "$FAKE_CURL_LOG"
  FAKE_CURL_MODE=blackhole run "$h" GUARDS_BREAKER_SECS=0 > /dev/null
  [ "$(calls)" -ge 1 ] && ok || bad "$h: GUARDS_BREAKER_SECS=0 never skips the service"
  for bogus in abc -5 1.5; do
    ST="$T/st-$h-bogus"; rm -rf "$ST"
    FAKE_CURL_MODE=blackhole run "$h" GUARDS_BREAKER_SECS=$bogus > /dev/null
    : > "$FAKE_CURL_LOG"
    FAKE_CURL_MODE=blackhole run "$h" GUARDS_BREAKER_SECS=$bogus > /dev/null
    [ "$(calls)" -ge 1 ] && ok || bad "$h: GUARDS_BREAKER_SECS=$bogus (not a whole number) turns the breaker off"
  done
  : > "$T/afile"
  ST="$T/afile/state"; : > "$FAKE_CURL_LOG"
  FAKE_CURL_MODE=blackhole run "$h" > /dev/null
  FAKE_CURL_MODE=blackhole run "$h" > /dev/null
  [ "$(calls)" -ge 2 ] && ok || bad "$h: an unwritable state directory means today's behaviour (every call tries)"
done

# --- the secret decision does not depend on the breaker ---------------------------------------------------
# With the breaker open the Bash hook still scans locally and still redacts.
ST="$T/st-secret"
SECRET="password=$(printf 'Tq7v%sN2x' 'Lm9Kd4')RzP8wYb"
FAKE_CURL_MODE=blackhole run bash > /dev/null
out="$(jq -nc --arg o "x $SECRET y" '{session_id:"s1", tool_name:"Bash", tool_input:{command:"x"}, tool_response:{stdout:$o, stderr:"", interrupted:false, isImage:false}}' \
  | env "PATH=$T/bin:$PATH" GUARDS_STATE_DIR="$ST" GUARDS_ENDPOINT="http://svc.invalid:8700" FAKE_CURL_MODE=blackhole bash "$HOOKS/combined-hook.sh" 2>/dev/null)"
case "$out" in *"$SECRET"*) bad "a secret is redacted while the breaker is open" ;; *REDACTED*) ok ;; *) bad "a secret is redacted while the breaker is open (no redaction marker)" ;; esac

# --- the flag scan never probes -------------------------------------------------------------------------------
ST="$T/st-flag"
FAKE_CURL_MODE=blackhole run bash > /dev/null
age_record 31      # window over: the secret route probes, the background flag scan must not
: > "$FAKE_CURL_LOG"
FAKE_CURL_MODE=blackhole run bash > /dev/null
eq "bash: after the window only the secret route probes, not the background flag scan too" "$(calls)" 1

echo "degrade-breaker: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
