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
# Off switch: GUARDS_DEGRADED_NOTE=0 turns the state off; nothing here then reads or writes a file.
#
# Bash 3.2 (macOS) compatible: no associative arrays, no printf %(%s)T. The clock is `date +%s`, read only
# off the service-up path.

DG_STATE="${GUARDS_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/nonexistent}/.local/state}/gramatr-guards}"
DG_TOTAL=""       # seconds the last attempt took (set by dg_classify)
DG_OUTCOME=""     # ok | down | slow | http | malformed  (set by dg_classify)
DG_ADDR=""        # number standing for the endpoint (set by dg_addr)
DG_DOWN_DONE=""   # the address whose failure this process has already recorded (dg_service_down)
DG_KEY=""         # file name standing for the session (set by dg_sidkey)
DG_MODE=full SLOW_NOTED=0 DG_EPOCH=0 DG_ERRS_PII=0 DG_ERRS_INJECTION=0
DG_NOTICE=""      # none | enter | recover | slow  (set by dg_mode_update)

# dg_active -- 0 unless the person turned the state off (a state directory is worth touching at all).
dg_active() { [ "${GUARDS_DEGRADED_NOTE:-1}" != 0 ]; }

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
dg_addr() { dg_hash "$1"; DG_ADDR="$DG_H"; }

# dg_sidkey SESSION_ID -> DG_KEY (empty when there is no session id: nothing is remembered, so a note is
# shown every time, as pii_note_types does). A session id that is not a plain token is turned into
# h<number> so it still names one file and a note is still shown once.
dg_sidkey() {
  local sid="${1:-}"
  DG_KEY=""
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

# dg_service_down ENDPOINT REASON -- record a connect-class failure.
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
  dg_write "$f" "$now $((count + 1)) ${2:-down}" && DG_DOWN_DONE="$DG_ADDR"
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
  dg_classify "$2" "$3" "${4:-0}"
  case "$DG_OUTCOME" in
    down) dg_service_down "$1" "rc$2" ;;
    *) dg_service_up "$1" ;;
  esac
}

# dg_mode_read KEY -> DG_MODE, SLOW_NOTED, DG_EPOCH, DG_ERRS_PII, DG_ERRS_INJECTION (defaults when no file).
dg_mode_read() {
  local f="$DG_STATE/mode/$1" line m e a s p i
  DG_MODE=full; SLOW_NOTED=0; DG_EPOCH=0; DG_ERRS_PII=0; DG_ERRS_INJECTION=0
  [ -f "$f" ] || return 0
  line="$(cat "$f" 2>/dev/null)"
  read -r m e a s p i <<EOF
$line
EOF
  case "$m" in full|down|slow|axis:[a-z+]*) DG_MODE="$m" ;; *) return 0 ;; esac
  case "$e" in ''|*[!0-9]*) ;; *) DG_EPOCH="$e" ;; esac
  case "$s" in 1) SLOW_NOTED=1 ;; esac
  case "$p" in ''|*[!0-9]*) ;; *) DG_ERRS_PII="$p" ;; esac
  case "$i" in ''|*[!0-9]*) ;; *) DG_ERRS_INJECTION="$i" ;; esac
}

# dg_mode_update KEY NEWMODE ENDPOINT -> DG_NOTICE
# Decides whether the person and the agent are told something, and remembers what they were told:
#   enter    the session moved into down or an unavailable axis (once per outage)
#   slow     the first slow call of the session (never repeated: slow is not an outage, and it flaps)
#   recover  the session moved from down or an unavailable axis back to full
#   none     anything else, including the same mode as last time
# A missing KEY (no session id) remembers nothing, so every non-full call is noted. An unwritable state
# directory behaves the same way: a quiet failure never hides a notice.
dg_mode_update() {
  local key="$1" new="$2" f now
  DG_NOTICE=none
  dg_active || return 0
  dg_mode_read "${key:-.none}"
  if [ -z "$key" ]; then
    case "$new" in full) ;; slow) DG_NOTICE=slow ;; *) DG_NOTICE=enter ;; esac
    return 0
  fi
  [ "$new" = "$DG_MODE" ] && return 0
  case "$new" in
    full)
      case "$DG_MODE" in down|axis:*) DG_NOTICE=recover ;; esac ;;
    slow)
      [ "$SLOW_NOTED" = 1 ] || { DG_NOTICE=slow; SLOW_NOTED=1; } ;;
    *) DG_NOTICE=enter ;;
  esac
  dg_addr "$3"
  dg_dir mode || return 0
  f="$DG_STATE/mode/$key"
  [ -e "$f" ] || find "$DG_STATE/mode" -type f -mtime +2 -delete 2>/dev/null
  now="$(date +%s)"
  dg_write "$f" "$new $now $DG_ADDR $SLOW_NOTED $DG_ERRS_PII $DG_ERRS_INJECTION"
  return 0
}
