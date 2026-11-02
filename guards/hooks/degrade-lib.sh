#!/usr/bin/env bash
# shellcheck disable=SC2034  # the DG_* variables are read by the scripts that source this file
# guards/hooks/degrade-lib.sh -- sourced by the hooks; not run directly.
#
# WHY: when the guards service cannot do its job (down, too slow, an axis unavailable) four things had
# no shared answer: how to tell the cases apart, how to say so once instead of on every call, how to
# stop waiting for a service already known to be gone (the breaker), and how to show the state to the
# person. They need ONE small piece of state, kept here (coordination#93, #126, #127, #128; scope
# docs/scope/service-degradation-2026-11-01.md in guards-coordination).
#
# THE RULE THAT FALLS OUT: PII and injection are only ever downgraded, with a disclosure, and a SECRET
# decision never depends on anything in this file. A state directory that cannot be read or written
# means "behave as before the library existed".
#
# What is stored, all under ${GUARDS_STATE_DIR:-${XDG_STATE_HOME:-~/.local/state}/gramatr-guards}, and
# never any scanned text or host name (an address is kept as a number, a session id as itself when it
# is a plain token and as a number otherwise):
#   service/<addr>   one line "FAIL_EPOCH COUNT REASON": the service at <addr> could not be connected to.
#                    Written on a connect-class failure, removed on any answer. Machine-wide.
#   mode/<session>   one line "MODE EPOCH ADDR SLOW_NOTED ERRS_PII ERRS_INJECTION": what this session was
#                    last told. MODE is full, down, slow, or axis:LIST (LIST is pii, injection or pii+injection).
# Both are written through a temp file and a rename, so a reader never sees half a line, and files older
# than two days are removed when a new one is started.
#
# Off switches: GUARDS_DEGRADED_NOTE=0 turns the once-per-session note off, GUARDS_BREAKER_SECS=0 the breaker;
# with both off nothing here reads or writes a file.
#
# Bash 3.2 (macOS) compatible: no associative arrays, no printf %(%s)T. The clock is `date +%s`, read only
# off the service-up path.

DG_STATE="${GUARDS_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/nonexistent}/.local/state}/gramatr-guards}"
DG_TOTAL=""       # seconds the last attempt took (set by dg_classify)
DG_OUTCOME=""     # ok | down | slow | http | malformed  (set by dg_classify)
DG_ADDR=""        # number standing for the endpoint (set by dg_addr, which remembers the last one)
DG_ADDR_OF=""
DG_DOWN_DONE=""   # the address whose failure this process has already recorded (dg_service_down)
DG_KEY=""         # file name standing for the session (set by dg_sidkey)
DG_MODE=full SLOW_NOTED=0 DG_EPOCH=0 DG_ERRS_PII=0 DG_ERRS_INJECTION=0
DG_NOTICE=""      # none | enter | recover | slow  (set by dg_mode_update)

# dg_note_on / dg_breaker_on -- the two uses of the state. The breaker window is GUARDS_BREAKER_SECS seconds
# (default 30; 0 turns it off; anything that is not a whole number also turns it off, the safe direction).
dg_note_on() { [ "${GUARDS_DEGRADED_NOTE:-1}" != 0 ]; }
dg_breaker_on() {
  DG_BSECS="${GUARDS_BREAKER_SECS:-30}"
  case "$DG_BSECS" in ''|*[!0-9]*) DG_BSECS=0 ;; esac
  [ "$DG_BSECS" -gt 0 ]
}
# dg_active -- 0 unless the person turned both uses off (a state directory is worth touching at all).
dg_active() { dg_note_on || dg_breaker_on; }

# dg_hash STRING -> DG_H, an unsigned 32-bit number (djb2). Pure bash: no fork on the hot path.
dg_hash() {
  local s="$1" i=0 h=5381 n c
  n=${#s}
  while [ "$i" -lt "$n" ]; do
    printf -v c '%d' "'${s:$i:1}"
    h=$(( (h * 33 + c) & 4294967295 ))
    i=$((i + 1))
  done
  DG_H="$h"
}

# dg_addr ENDPOINT -> DG_ADDR
dg_addr() {
  [ "$1" = "${DG_ADDR_OF:-}" ] && return 0
  dg_hash "$1"; DG_ADDR="$DG_H"; DG_ADDR_OF="$1"
}

# dg_sidkey SESSION_ID -> DG_KEY. A session id that is not a plain token is turned into h<number> so it
# still names one file and a note is still shown once. A payload with no session id (Claude Code always
# sends one) shares the key "nosid", so such a caller is told once per machine rather than on every call.
dg_sidkey() {
  local sid="${1:-}"
  DG_KEY="nosid"
  [ -n "$sid" ] || return 0
  case "$sid" in
    *[!A-Za-z0-9_-]*) dg_hash "$sid"; DG_KEY="h$DG_H" ;;
    *) if [ "${#sid}" -le 128 ]; then DG_KEY="$sid"; else dg_hash "$sid"; DG_KEY="h$DG_H"; fi ;;
  esac
}

# dg_classify RC "HTTP_CODE TIME_CONNECT" BODY_OK -> DG_OUTCOME
#   RC          curl's exit status; the second argument is curl -w '%{http_code} %{time_connect} %{time_total}'
#               (DG_TOTAL is set to the last of the three: how long the attempt took, in seconds)
#   BODY_OK     1 when the body had the shape of a scan result (the caller checks), else 0
# down       could not connect: refused (7), name not found (5, 6), or a timeout that fired before the
#            connection was made (28 with time_connect 0, a blackholed address)
# slow       connected, then the total time limit ran out (28 after the connection)
# http       connected and got an error status, or the connection broke after it was made
# malformed  a 2xx whose body is not a scan result
# ok         a 2xx with a scan result
dg_classify() {
  local rc="$1" meta="${2:-}" body_ok="${3:-0}" code conn
  code="${meta%% *}"; conn="${meta#* }"; DG_TOTAL="${conn#* }"; conn="${conn%% *}"
  # A hook pipes the request body into curl; under pipefail an earlier stage killed by SIGPIPE (141)
  # would hide that curl itself got an answer.
  if [ "$rc" = 141 ]; then case "$code" in ''|000) ;; *) rc=0 ;; esac; fi
  case "$rc" in
    0)
      case "$code" in
        2??) if [ "$body_ok" = 1 ]; then DG_OUTCOME=ok; else DG_OUTCOME=malformed; fi ;;
        *) DG_OUTCOME=http ;;
      esac ;;
    5|6|7) DG_OUTCOME=down ;;
    28) case "$conn" in *[1-9]*) DG_OUTCOME=slow ;; *) DG_OUTCOME=down ;; esac ;;
    *) DG_OUTCOME=http ;;
  esac
}

# dg_write FILE LINE -- atomic: a temp file in the same directory, then a rename. Returns non-zero (and
# leaves nothing behind) when the directory cannot be written.
dg_write() {
  local f="$1" tmp
  tmp="$f.$$.${RANDOM:-0}"
  if printf '%s\n' "$2" > "$tmp" 2>/dev/null && mv -f "$tmp" "$f" 2>/dev/null; then return 0; fi
  rm -f "$tmp" 2>/dev/null
  return 1
}

# dg_dir SUBDIR -- make sure $DG_STATE/SUBDIR exists; non-zero when it cannot be made.
dg_dir() { mkdir -p "$DG_STATE/$1" 2>/dev/null; }

# dg_service_down ENDPOINT REASON [CLASS] -- record a connect-class failure. CLASS is "slow" when the attempt
# itself took long (a blackholed address, a slow resolver: the only failures a breaker saves anything on) and
# "fast" otherwise (refused, no such host: over in a millisecond, nothing to save).
dg_service_down() {
  local f count=0 now t c
  dg_active || return 0
  dg_addr "$1"
  # One failure is recorded once per hook run, however many of its requests saw it.
  [ "$DG_DOWN_DONE" = "$DG_ADDR" ] && return 0
  dg_dir service || return 0
  f="$DG_STATE/service/$DG_ADDR"
  if [ -f "$f" ]; then
    read -r t c _ < "$f" 2>/dev/null
    case "$c" in ''|*[!0-9]*) count=0 ;; *) count="$c" ;; esac
  else
    find "$DG_STATE/service" -type f -mtime +2 -delete 2>/dev/null
  fi
  now="${EPOCHSECONDS:-}"
  [ -n "$now" ] || now="$(date +%s)"
  dg_write "$f" "$now $((count + 1)) ${2:-down} ${3:-fast}" && DG_DOWN_DONE="$DG_ADDR"
  return 0
}

# dg_service_up ENDPOINT -- the service answered: forget a failure record.
dg_service_up() {
  dg_active || return 0
  dg_addr "$1"
  [ -e "$DG_STATE/service/$DG_ADDR" ] && rm -f "$DG_STATE/service/$DG_ADDR" 2>/dev/null
  return 0
}

# dg_observe ENDPOINT RC META BODY_OK -- classify one call and keep the service record in step:
# a connect-class failure is recorded, any answer (even a slow or an error one) clears it.
dg_observe() {
  local cls
  dg_classify "$2" "$3" "${4:-0}"
  case "$DG_OUTCOME" in
    down)
      cls=fast
      case "$DG_TOTAL" in 0.[5-9]*|[1-9]*) cls=slow ;; esac
      dg_service_down "$1" "rc$2" "$cls" ;;
    *) dg_service_up "$1" ;;
  esac
}

# dg_mode_read KEY -> DG_MODE, SLOW_NOTED, DG_EPOCH, DG_ERRS_PII, DG_ERRS_INJECTION (defaults when no file).
dg_mode_read() {
  local f="$DG_STATE/mode/$1" m e a s p i
  DG_MODE=full; SLOW_NOTED=0; DG_EPOCH=0; DG_ERRS_PII=0; DG_ERRS_INJECTION=0
  if [ -f "$f" ]; then
    read -r m e a s p i < "$f" 2>/dev/null
    case "$m" in full|down|slow|error|axis:[a-z+]*) DG_MODE="$m" ;; *) m="" ;; esac
    if [ -n "$m" ]; then
      case "$e" in ''|*[!0-9]*) ;; *) DG_EPOCH="$e" ;; esac
      case "$s" in 1|2|3) SLOW_NOTED="$s" ;; esac
      case "$p" in ''|*[!0-9]*) ;; *) DG_ERRS_PII="$p" ;; esac
      case "$i" in ''|*[!0-9]*) ;; *) DG_ERRS_INJECTION="$i" ;; esac
    fi
  fi
  DG_OLD="$DG_MODE $SLOW_NOTED $DG_ERRS_PII $DG_ERRS_INJECTION"
}

# _dg_commit KEY NEW ENDPOINT -> DG_NOTICE; remembers the result. dg_mode_read KEY has run, and the caller
# may have changed the DG_ERRS_* counters.
#   enter    the session moved into down or an unavailable axis (once per outage)
#   slow     the first slow call of the session (never repeated: slow is not an outage, and it flaps)
#   error    the first call of the session the service answered with an error (never repeated, same reason)
#   recover  the session moved from down or an unavailable axis back to full
#   none     anything else, including the same mode as last time
# An unwritable state directory remembers nothing, so every non-full call is noted: a quiet failure never
# hides a notice.
_dg_commit() {
  local key="$1" new="$2" f now
  DG_NOTICE=none
  if [ "$new" != "$DG_MODE" ]; then
    case "$new" in
      full) case "$DG_MODE" in down|axis:*) DG_NOTICE=recover ;; esac ;;
      slow) [ $((SLOW_NOTED & 1)) -eq 1 ] || { DG_NOTICE=slow; SLOW_NOTED=$((SLOW_NOTED | 1)); } ;;
      error) [ $((SLOW_NOTED & 2)) -eq 2 ] || { DG_NOTICE=error; SLOW_NOTED=$((SLOW_NOTED | 2)); } ;;
      *) DG_NOTICE=enter ;;
    esac
  fi
  [ "$new $SLOW_NOTED $DG_ERRS_PII $DG_ERRS_INJECTION" = "$DG_OLD" ] && return 0
  dg_addr "$3"
  dg_dir mode || return 0
  f="$DG_STATE/mode/$key"
  [ -e "$f" ] || find "$DG_STATE/mode" -type f -mtime +2 -delete 2>/dev/null
  now="$(date +%s)"
  dg_write "$f" "$new $now $DG_ADDR $SLOW_NOTED $DG_ERRS_PII $DG_ERRS_INJECTION"
  return 0
}

# dg_mode_update KEY NEWMODE ENDPOINT -> DG_NOTICE. The plain form: the caller already knows the mode.
dg_mode_update() {
  local k="${1:-nosid}"
  DG_NOTICE=none
  dg_note_on || return 0
  dg_mode_read "$k"
  _dg_commit "$k" "$2" "$3"
}

# dg_worse A B -> DG_WORST: the worse of two outcomes (down, slow, http/malformed, ok, empty).
dg_worse() {
  local a b
  case "$1" in down) a=5 ;; slow) a=4 ;; http|malformed) a=3 ;; ok) a=2 ;; *) a=1 ;; esac
  case "$2" in down) b=5 ;; slow) b=4 ;; http|malformed) b=3 ;; ok) b=2 ;; *) b=1 ;; esac
  if [ "$b" -gt "$a" ]; then DG_WORST="$2"; else DG_WORST="$1"; fi
}

# dg_axis VERDICT SRC TYPE -> DG_AX: ok | err | unavail | -  for one model axis of a scan answer.
#   TYPE     pii or injection
#   VERDICT  the axis's verdict from the answer ("" = the answer did not contain this axis: "-")
#   SRC      the answer as text, or @FILE; read (one jq) only for an "error" verdict, to tell the stable
#            reason code *_UNAVAILABLE (the axis cannot run: unavail) from a one-off failure (err)
dg_axis() {
  local type="$3"
  case "$1" in
    '') DG_AX=- ;;
    error)
      DG_AX=err
      if [ "${2#@}" != "$2" ]; then
        jq -e --arg t "$type" '[.findings[]? | select(.type == $t) | .reason_code[]? | tostring | endswith("_UNAVAILABLE")] | any' < "${2#@}" >/dev/null 2>&1 && DG_AX=unavail
      else
        printf '%s' "$2" | jq -e --arg t "$type" '[.findings[]? | select(.type == $t) | .reason_code[]? | tostring | endswith("_UNAVAILABLE")] | any' >/dev/null 2>&1 && DG_AX=unavail
      fi ;;
    *) DG_AX=ok ;;
  esac
}

# dg_axes SRC -> DG_AX_PII, DG_AX_INJ: ok | err | unavail | -  for the two model axes of a /v1/scan answer.
#   SRC   the answer as text, or @FILE
# An answer with no "error" in it (the usual one) costs no fork at all; only one that has it is read, with one
# jq, to tell the stable reason code *_UNAVAILABLE (the axis cannot run: unavail) from a one-off failure (err).
dg_axes() {
  local out="" prog='def st($t): ([.findings[]? | select(.type == $t)] | first) as $f
    | if $f == null or ($f.verdict // "") == "" then "-"
      elif $f.verdict == "error" then (if ([$f.reason_code[]? | tostring | endswith("_UNAVAILABLE")] | any) then "unavail" else "err" end)
      else "ok" end;
    "\(st("pii")) \(st("injection"))"'
  DG_AX_PII=ok; DG_AX_INJ=ok
  if [ "${1#@}" != "$1" ]; then
    grep -q '"error"' "${1#@}" 2>/dev/null || return 0
    out="$(jq -r "$prog" < "${1#@}" 2>/dev/null)"
  else
    case "$1" in *'"error"'*) ;; *) return 0 ;; esac
    out="$(printf '%s' "$1" | jq -r "$prog" 2>/dev/null)"
  fi
  case "$out" in
    *" "*) DG_AX_PII="${out%% *}"; DG_AX_INJ="${out#* }" ;;
  esac
}

# dg_rawsid -> DG_SID: the session id from the hook payload in $RAW. Claude Code writes the payload with
# session_id first, so the usual case is read with parameter expansion (no fork); a payload that does not
# start that way is read with jq, and one that has no session_id at all has none.
dg_rawsid() {
  local r="${RAW:-}" t pre='{"session_id":"'
  case "$r" in
    "$pre"*) t="${r#"$pre"}"; DG_SID="${t%%\"*}" ;;
    *session_id*) DG_SID="$(printf '%s' "$r" | jq -r '.session_id // ""' 2>/dev/null)" ;;
    *) DG_SID="" ;;
  esac
}

# dg_session_update KEY ENDPOINT OUTCOME PII INJ -> DG_NOTICE, DG_NOW_MODE
# One call's observation folded into the session's mode. OUTCOME is the worst service outcome of the call
# (ok, down, slow, http and malformed, which are the mode "error"); PII and INJ are ok, err, unavail, or - when this call could not see
# that axis (the secret-only route). An axis with one-off errors is counted, and after three in a row it
# counts as unavailable, so a model that fails every time is not silent forever. A call that cannot see
# the axes never clears an axis that is unavailable.
dg_session_update() {
  local key="$1" ep="$2" outcome="$3" pii="${4:--}" inj="${5:--}" new axes
  DG_NOTICE=none; DG_NOW_MODE=full
  dg_note_on || return 0
  key="${key:-nosid}"
  dg_mode_read "$key"
  case "$outcome" in
    down) new=down ;;
    slow) new=slow ;;
    http|malformed) new=error ;;
    *)
      case "$pii" in ok) DG_ERRS_PII=0 ;; err) [ "$DG_ERRS_PII" -ge 3 ] || DG_ERRS_PII=$((DG_ERRS_PII + 1)) ;; unavail) DG_ERRS_PII=3 ;; esac
      case "$inj" in ok) DG_ERRS_INJECTION=0 ;; err) [ "$DG_ERRS_INJECTION" -ge 3 ] || DG_ERRS_INJECTION=$((DG_ERRS_INJECTION + 1)) ;; unavail) DG_ERRS_INJECTION=3 ;; esac
      axes=""
      [ "$DG_ERRS_PII" -ge 3 ] && axes=pii
      [ "$DG_ERRS_INJECTION" -ge 3 ] && axes="${axes:+$axes+}injection"
      if [ -n "$axes" ]; then new="axis:$axes"
      elif [ "$pii$inj" = "--" ]; then
        case "$DG_MODE" in axis:*) new="$DG_MODE" ;; *) new=full ;; esac
      else new=full; fi ;;
  esac
  DG_NOW_MODE="$new"
  _dg_commit "$key" "$new" "$ep"
}

# dg_note_text HOOK -> DG_NOTE: what to say for DG_NOTICE / DG_NOW_MODE, empty when nothing is due.
# HOOK is bash, mcp, message or prompt, because what is still checked differs. The wording states what is
# true and who can look (the person, with guards_status), and does not give the model an instruction: an
# imperative line in context the model reads is the shape an injection defence flags.
#   DG_DETAIL  optional extra words for the slow note (for example "the 0.85 s flag budget")
dg_note_text() {
  local hook="$1" kept still axes during
  DG_NOTE=""
  case "$hook" in
    bash) kept="Secrets in tool output are still scanned locally; the PII and prompt-injection notes are not running"
          during="the PII and prompt-injection checks were skipped and secrets were scanned locally"
          still="the PII and prompt-injection notes are running again" ;;
    mcp) kept="Secrets in tool results are still scanned locally"
         during="secrets were scanned locally"
         still="the service route for secrets is running again" ;;
    message) kept="Secrets in outgoing messages are still scanned locally; the PII note is not running"
             during="the PII check was skipped and secrets were scanned locally"
             still="the PII note is running again" ;;
    prompt) kept="Prompts are not being checked for secrets (that check has no local fallback)"
            during="this prompt was not checked for secrets (that check has no local fallback)"
            still="the secret check of prompts is running again" ;;
    *) return 0 ;;
  esac
  case "$DG_NOTICE" in
    enter)
      case "$DG_NOW_MODE" in
        down) DG_NOTE="guards: the guards-unified service could not be reached (connection refused, no answer before the connect limit, or the address did not resolve). $kept until it answers again. The person can see the current state with guards_status. This is noted once; a second note says when the service is back." ;;
        axis:*)
          axes="${DG_NOW_MODE#axis:}"; axes="$(printf '%s' "$axes" | sed 's/+/ and /')"
          DG_NOTE="guards: the guards-unified service answers, but its $axes check is not working (it reports an error, or reported the axis unavailable). Secrets and the other checks still run. The person can see the current state with guards_status. This is noted once; a second note says when it is back." ;;
        *) return 0 ;;
      esac ;;
    slow)
      DG_NOTE="guards: the guards-unified service connected but did not answer within the time limit${DG_DETAIL:+ ($DG_DETAIL)} for this call; $during. This is slowness, not an outage, and is noted once per session." ;;
    error)
      DG_NOTE="guards: the guards-unified service answered with an error (an HTTP error status, or a reply that is not a scan result); for this call, $during. This is noted once per session." ;;
    recover)
      DG_NOTE="guards: the guards-unified service is answering again; $still." ;;
    *) return 0 ;;
  esac
}

# dg_axis_worse A B -> DG_AXW: the worse of two axis states (unavail, err, ok, -).
dg_axis_worse() {
  local a b
  case "$1" in unavail) a=4 ;; err) a=3 ;; ok) a=2 ;; *) a=1 ;; esac
  case "$2" in unavail) b=4 ;; err) b=3 ;; ok) b=2 ;; *) b=1 ;; esac
  if [ "$b" -gt "$a" ]; then DG_AXW="$2"; else DG_AXW="$1"; fi
}

# dg_call_add OUTCOME PII INJ -- fold one observation into the call-wide state a hook keeps while it
# scans several texts (stdout, stderr, three message fields): DG_CALL_OUT, DG_CALL_PII, DG_CALL_INJ.
DG_CALL_OUT="" DG_CALL_PII="-" DG_CALL_INJ="-"
dg_call_add() {
  dg_worse "$DG_CALL_OUT" "$1"; DG_CALL_OUT="$DG_WORST"
  dg_axis_worse "$DG_CALL_PII" "${2:--}"; DG_CALL_PII="$DG_AXW"
  dg_axis_worse "$DG_CALL_INJ" "${3:--}"; DG_CALL_INJ="$DG_AXW"
}

# dg_call_finish HOOK ENDPOINT -> DG_NOTE (empty when nothing is due). HOOK as in dg_note_text. The session
# id is read from the hook payload in $RAW (see dg_rawsid).
dg_call_finish() {
  DG_NOTE=""
  [ -n "$DG_CALL_OUT" ] || return 0
  dg_note_on || return 0
  dg_rawsid
  dg_sidkey "$DG_SID"
  # Everything fine and this session has no record: nothing to say, nothing to remember (no fork).
  if [ "$DG_CALL_OUT" = ok ]; then
    case "$DG_CALL_PII$DG_CALL_INJ" in *err*|*unavail*) ;; *) [ -f "$DG_STATE/mode/$DG_KEY" ] || return 0 ;; esac
  fi
  dg_session_update "$DG_KEY" "$2" "$DG_CALL_OUT" "$DG_CALL_PII" "$DG_CALL_INJ"
  [ "$DG_NOTICE" = none ] || dg_note_text "$1"
  return 0
}

# dg_breaker_open ENDPOINT [noprobe] -- is the service known to be gone, so that this call should not open a
# connection at all? True only when the last attempt failed SLOWLY at the connection stage (a blackholed or
# half-open address) less than GUARDS_BREAKER_SECS ago. A refused connection, a name that does not resolve,
# a slow answer, an error status and a malformed body never trip it: each of those is cheap or says the
# service is there. After the window one call is let through as the probe (a "noprobe" caller, such as the
# background flag scan, never probes and stays skipped until a probe has cleared the record). Callers treat
# an open breaker as the outcome "down" and leave the record alone, so the window does not slide.
# The hot path (service up, no record) costs one builtin file test.
dg_breaker_open() {
  local f t c r k now
  dg_breaker_on || return 1
  dg_addr "$1"
  f="$DG_STATE/service/$DG_ADDR"
  [ -f "$f" ] || return 1
  read -r t c r k < "$f" 2>/dev/null || return 1
  [ "$k" = slow ] || return 1
  case "$t" in ''|*[!0-9]*) return 1 ;; esac
  [ "${2:-}" = noprobe ] && return 0
  now="$(date +%s)"
  [ $((now - t)) -lt "$DG_BSECS" ]
}
