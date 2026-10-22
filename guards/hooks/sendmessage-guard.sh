#!/usr/bin/env bash
# guards/hooks/sendmessage-guard.sh — PreToolUse hook on SendMessage.
#
# REDACTS secrets, FLAGS PII, informs either way — matching
# combined-hook.sh's own posture now (#20): a leaked key is binary and
# costly regardless of context, so secrets stay hard-redacted
# unconditionally. PII is different — these messages travel between
# the operator's own agent fleet, not unknown third parties, and
# hard-redacting PII here was actively destroying real operational
# content (confirmed live: a peer-session coordination message
# containing a human reviewer's name came back with the name replaced
# by a placeholder tag, which is worse than useless for a message
# whose entire point was identifying who made a ruling). Default
# PII_GUARD_MODE=flag surfaces what was detected via additionalContext
# without touching the message/summary/content values at all.
# PII_GUARD_MODE=redact restores the old wholesale-replace behavior for
# a context where that's actually the right tradeoff (e.g. a channel
# with recipients outside the operator's own fleet).
#
# BACKEND-UNREACHABLE CASE: degrades, does not block outright. Used to
# deny every message outright when guards-unified was unreachable —
# changed after that fail-closed-on-outage behavior was blocking
# ordinary cross-agent coordination entirely on a single downstream
# dependency being down, with no way to route around it. Falls back to
# the same vendored gitleaks secret-only scan combined-hook.sh already
# uses for its own backend-unreachable case: secrets still get real
# local coverage (no network dependency); PII has no local equivalent
# to gitleaks, so PII coverage is just disclosed as unavailable in this
# case regardless of PII_GUARD_MODE — degraded and disclosed, never
# silently unsafe, never a blanket block.
#
# MUST remain the ONLY PreToolUse hook matched on SendMessage (or on a
# broad "*" that also matches it). Confirmed by actually testing, not
# assumed: with a second PreToolUse hook also registered on the same
# event (even one that emits no output at all), updatedInput was
# silently dropped and the original, unredacted message went through
# unchanged — the same "undefined resolution order across multiple
# hooks on one event" problem Claude Code's own docs already warn
# about for PostToolUse, now confirmed to apply here too. If this ever
# needs to coexist with another PreToolUse hook on SendMessage, they
# must be combined into one script, the same reason combined-hook.sh
# exists for the Bash PostToolUse case.
#
# EACH text-bearing field is scanned and redacted INDEPENDENTLY, from
# its OWN original content — not by copying one field's redacted
# result onto the others. `message`, `summary`, and `content` are NOT
# reliably "overlapping copies of the same text" (an earlier version
# of this script assumed they were, and copied `message`'s redacted
# text onto all three) — confirmed wrong by a real bug report
# (a user report): `summary` is a short,
# independently-authored label (the caller's example: ~38 chars) while
# `message` is the long body, and blanket-copying the longer field's
# redacted text into `summary` blew past its own schema's `maximum:
# 200` and failed validation outright, blocking every cross-session
# send that hit the redaction path. `summary` is STILL always
# hard-truncated to 200 chars after secret redaction, defensively —
# never trust a redaction step to respect a downstream schema's limit
# just because it shouldn't normally lengthen text much.
#
# The injection finding is out of scope for this decision either way —
# the message is authored by the sending agent itself, not forwarded
# untrusted content.

set -uo pipefail

# Own deadline below the hook timeout in hooks.json: Claude Code fails open when
# a hook outlives it. Re-runs this script bounded; see deadline-lib.sh.
# shellcheck source=guards/hooks/deadline-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/deadline-lib.sh" && guards_deadline deny 10

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDS_ROOT="$(dirname "$SCRIPT_DIR")"
SECRET_SCAN="$GUARDS_ROOT/vendor/secret-guard-core/scan.sh"
GUARDS_ENDPOINT="${GUARDS_ENDPOINT:-http://127.0.0.1:8700}"
SUMMARY_MAX=200
PII_GUARD_MODE="${PII_GUARD_MODE:-flag}"
SCAN_MAX_BYTES="${SCAN_MAX_BYTES:-24576}"

# Time budget inside the 10 s deadline (deadline-lib.sh): the service gets the
# first SERVICE_BUDGET seconds across all fields, local scans must end by
# LOCAL_BY. Running out of local time exits 124, which becomes a deny.
SM_T0="$(date +%s)"
SERVICE_BUDGET=4
LOCAL_BY=9
PII_UNAVAILABLE=0

TMP_FILES=()
trap 'rm -f "${TMP_FILES[@]}"' EXIT

RAW="$(cat)"
# shellcheck source=guards/hooks/json-lib.sh
. "$SCRIPT_DIR/json-lib.sh"
TOOL_NAME="$(jfield tool_name)"
if [ "$TOOL_NAME" != "SendMessage" ]; then
  exit 0
fi
# Redaction rewrites the message JSON, which needs jq: deny a message with
# credential material, allow a clean one with a note (json-lib.sh).
[ "$HAVE_JQ" -eq 1 ] || nojq_pre_guard sendmessage-guard "$SECRET_SCAN"

MESSAGE="$(printf '%s' "$RAW" | jq -r '.tool_input.message // ""' 2>/dev/null)"
ORIGINAL_INPUT="$(printf '%s' "$RAW" | jq -c '.tool_input')"
# ORIGINAL_INPUT embeds the full, pre-redaction message/summary/content
# verbatim -- passing it via --argjson (argv) has the exact same
# MAX_ARG_STRLEN crash risk as the individual fields below. Written to
# a file once, read back via --rawfile + fromjson in both jq calls
# that need it.
ORIGINAL_INPUT_FILE="$(mktemp)"
TMP_FILES+=("$ORIGINAL_INPUT_FILE")
printf '%s' "$ORIGINAL_INPUT" > "$ORIGINAL_INPUT_FILE"
HAS_SUMMARY="$(printf '%s' "$RAW" | jq -r '.tool_input | has("summary")' 2>/dev/null)"
HAS_CONTENT="$(printf '%s' "$RAW" | jq -r '.tool_input | has("content")' 2>/dev/null)"
SUMMARY="$(printf '%s' "$RAW" | jq -r '.tool_input.summary // ""' 2>/dev/null)"
CONTENT="$(printf '%s' "$RAW" | jq -r '.tool_input.content // ""' 2>/dev/null)"

# Gate on whether ANY of the three fields is non-empty, not just
# message -- an earlier version exited here purely on `message` being
# empty, before summary/content were ever read, even though both are
# otherwise scanned completely independently once the hook does run.
# Confirmed live: {"message":"","summary":"s","content":"<secret>"}
# exited clean with zero output, the secret in content never looked
# at.
if [ -z "$MESSAGE" ] && [ -z "$SUMMARY" ] && [ -z "$CONTENT" ]; then
  exit 0
fi

# truncate_summary TEXT -- hard cap at SUMMARY_MAX chars, defensively,
# regardless of what redaction did to the text. jq's `.[0:N]` on a
# string slices by Unicode codepoint, not byte, matching how the
# SendMessage schema's own `maximum` is almost certainly counted.
truncate_summary() {
  jq -nr --arg t "$1" --argjson n "$SUMMARY_MAX" '$t[0:$n]'
}

# add_rawfile_arg NAME VALUE -- appends --rawfile NAME <tmpfile> to the
# JQ_ARGS array (tmpfile holding VALUE), tracked in TMP_FILES for
# cleanup on exit. Used instead of --arg for every field going into
# the FINAL updatedInput jq call below -- a field value (message,
# summary, or content) large enough to exceed Linux's per-argument
# MAX_ARG_STRLEN (~128KB) would otherwise crash that jq call with
# E2BIG, silently dropping whatever redaction was about to ship
# (Claude Code falls back to the ORIGINAL unredacted input when a
# PreToolUse hook fails). --rawfile reads from a file, bypassing argv
# entirely -- no size ceiling on what this hook can safely send back.
# (TMP_FILES array + its cleanup trap are declared once, near the top
# of this script, since ORIGINAL_INPUT_FILE above needs them too.)
add_rawfile_arg() {
  local name="$1" value="$2" f
  f="$(mktemp)"
  printf '%s' "$value" > "$f"
  TMP_FILES+=("$f")
  JQ_ARGS+=(--rawfile "$name" "$f")
}

# scan_remote TEXT -- sets, as side effects:
#   SCAN_OUT             text with ONLY secret redaction applied (PII left intact)
#   SCAN_SECRET_FOUND    1 if a secret was found in this text, else 0
#   SCAN_PII_TYPES       comma-joined PII entity types found, empty if none
#   SCAN_COMBINED_OUT    text with BOTH secret and PII redacted (legacy wholesale), for PII_GUARD_MODE=redact
# Returns 1 if guards-unified itself didn't answer at all.
scan_remote() {
  local text="$1" resp
  local full_len scan_text remainder="" req_file
  SCAN_OUT="$text"
  SCAN_SECRET_FOUND=0
  SCAN_PII_TYPES=""
  SCAN_COMBINED_OUT="$text"
  SCAN_TRUNCATED=0

  # SCAN_MAX_BYTES caps what gets SENT TO THE SCANNER, not what comes
  # back out -- measured directly this session: a 20KB /v1/scan
  # request never completed (>60s) at guards-unified's original
  # cpus:1.0 limit, confirmed CPU-bound. Raising cpus to 16 (see
  # docker-compose.yml) fixed that specific case, but size still scales
  # worse than linear regardless of core count (100KB still ~40s even
  # at cpus:16), so this cap still matters -- just at a size actually
  # fast at cpus:16 (24KB default, comfortably under this function's
  # own 10s curl timeout) rather than a number picked before any of
  # this was measured. The untouched remainder is always reattached
  # below and disclosed by the caller -- never silently dropped, never
  # silently assumed clean.
  full_len="$(printf '%s' "$text" | wc -c)"
  if [ "$full_len" -gt "$SCAN_MAX_BYTES" ]; then
    scan_text="$(printf '%s' "$text" | head -c "$SCAN_MAX_BYTES")"
    remainder="$(printf '%s' "$text" | tail -c "+$((SCAN_MAX_BYTES + 1))")"
    SCAN_TRUNCATED=1
  else
    scan_text="$text"
  fi

  # --rawfile instead of --arg, here and for the final updatedInput
  # jq call below -- a text value large enough to exceed Linux's
  # per-argument MAX_ARG_STRLEN (~128KB) would otherwise crash the jq
  # call with E2BIG, silently dropping whatever redaction was about to
  # happen (Claude Code falls back to the ORIGINAL unredacted input
  # when a PreToolUse hook fails). --rawfile reads from a file,
  # bypassing argv entirely.
  req_file="$(mktemp)"
  printf '%s' "$scan_text" > "$req_file"
  local left=$((SM_T0 + SERVICE_BUDGET - $(date +%s)))
  if [ "$left" -lt 1 ]; then rm -f "$req_file"; return 1; fi
  resp="$(jq -n --rawfile text "$req_file" '{text: $text}' 2>/dev/null \
    | curl -sS --connect-timeout 2 -m "$left" -X POST "${GUARDS_ENDPOINT}/v1/scan" \
        -H "Content-Type: application/json" -d @- 2>/dev/null)"
  rm -f "$req_file"

  # A non-empty resp isn't enough on its own -- a truncated body or a
  # well-formed error JSON missing "findings" would otherwise make the
  # jq extraction below silently return "", indistinguishable from
  # "scanned, nothing found." Require the actual shape a real scan
  # result has.
  if [ -z "$resp" ] || ! echo "$resp" | jq -e '.findings | type == "array"' >/dev/null 2>&1; then
    return 1
  fi
  if [ "$(echo "$resp" | jq -r '.findings[]? | select(.type=="secret") | .verdict // ""' 2>/dev/null)" = "found" ]; then
    SCAN_SECRET_FOUND=1
    SCAN_OUT="$(echo "$resp" | jq -r '.findings[] | select(.type=="secret") | .detail.redacted_text // empty' 2>/dev/null)"
    [ -z "$SCAN_OUT" ] && SCAN_OUT="$scan_text"
  else
    SCAN_OUT="$scan_text"
  fi
  SCAN_PII_TYPES="$(echo "$resp" | jq -r '[.findings[] | select(.type=="pii") | .detail.entities[]?.entity_type] | unique | join(", ")' 2>/dev/null)"
  SCAN_COMBINED_OUT="$(echo "$resp" | jq -r '.redacted_text // empty' 2>/dev/null)"
  [ -z "$SCAN_COMBINED_OUT" ] && SCAN_COMBINED_OUT="$scan_text"

  # Reattach the untouched remainder (empty string when not truncated)
  # to BOTH output variants -- never to the caller's $text, which would
  # double it.
  SCAN_OUT="${SCAN_OUT}${remainder}"
  SCAN_COMBINED_OUT="${SCAN_COMBINED_OUT}${remainder}"
  return 0
}

# scan_remote_or_local TEXT -- scan_remote, but if the service gives up (its
# time budget is shared by all three fields) the field gets the local
# secret-only scan instead of passing unscanned; PII is then unavailable.
scan_remote_or_local() {
  scan_remote "$1" && return 0
  scan_local_secret_only "$1"
  SCAN_SECRET_FOUND="$SCAN_FOUND"; SCAN_PII_TYPES=""; SCAN_COMBINED_OUT="$SCAN_OUT"; SCAN_TRUNCATED=0
  PII_UNAVAILABLE=1
}

# scan_local_secret_only TEXT -- sets SCAN_OUT and SCAN_FOUND=0|1,
# via the vendored gitleaks fallback (no network dependency).
scan_local_secret_only() {
  local text="$1" redacted
  SCAN_OUT="$text"
  SCAN_FOUND=0
  [ -z "$text" ] && return 0
  if [ -x "$SECRET_SCAN" ]; then
    local left=$((SM_T0 + LOCAL_BY - $(date +%s)))
    [ "$left" -ge 1 ] || exit 124
    local rc_file; rc_file="$(mktemp)"; TMP_FILES+=("$rc_file")
    if command -v timeout >/dev/null 2>&1; then
      redacted="$(printf '%s' "$text" | timeout -k 1 "$left" "$SECRET_SCAN" 2>/dev/null; echo "$?" > "$rc_file")"
      case "$(cat "$rc_file")" in 124|137) exit 124 ;; esac
    else
      redacted="$(printf '%s' "$text" | "$SECRET_SCAN" 2>/dev/null)"
    fi
    if [ -n "$redacted" ] && [ "$redacted" != "$text" ]; then
      SCAN_OUT="$redacted"
      SCAN_FOUND=1
    fi
  fi
}

# Reachability is decided once, off the required `message` field — if
# guards-unified is down for this call it's down for all three fields,
# so there is no partial-reachable state to handle.
if ! scan_remote "$MESSAGE"; then
  # SECRET_NOTE must reflect whether a secret was found in ANY of the
  # three fields, not just message -- confirmed live this was wrong:
  # message clean + a real secret in content, backend down, came back
  # with content correctly redacted while the disclosed reason said
  # "no secret found by local scan," directly contradicting the
  # redaction that had just happened. Aggregate across all three
  # before composing the disclosed text, same as the reachable-backend
  # path below already does via ANY_SECRET.
  ANY_LOCAL_SECRET=0
  MSG_OUT="$MESSAGE"
  scan_local_secret_only "$MESSAGE"
  if [ "$SCAN_FOUND" -eq 1 ]; then
    MSG_OUT="$SCAN_OUT"
    ANY_LOCAL_SECRET=1
  fi
  MERGE='{message: $msg}'
  JQ_ARGS=()
  add_rawfile_arg msg "$MSG_OUT"
  if [ "$HAS_SUMMARY" = "true" ]; then
    scan_local_secret_only "$SUMMARY"
    [ "$SCAN_FOUND" -eq 1 ] && ANY_LOCAL_SECRET=1
    SUM_OUT="$(truncate_summary "$SCAN_OUT")"
    MERGE="$MERGE + {summary: \$sum}"
    add_rawfile_arg sum "$SUM_OUT"
  fi
  if [ "$HAS_CONTENT" = "true" ]; then
    scan_local_secret_only "$CONTENT"
    [ "$SCAN_FOUND" -eq 1 ] && ANY_LOCAL_SECRET=1
    MERGE="$MERGE + {content: \$con}"
    add_rawfile_arg con "$SCAN_OUT"
  fi
  if [ "$ANY_LOCAL_SECRET" -eq 1 ]; then
    SECRET_NOTE="a secret was found and redacted by the local-only scan"
  else
    SECRET_NOTE="no secret found by local scan"
  fi
  jq -n \
    --rawfile orig_raw "$ORIGINAL_INPUT_FILE" \
    --arg reason "sendmessage-guard: guards-unified backend unreachable — sent via local-only secret scan (${SECRET_NOTE}); PII scan unavailable until backend is back" \
    --arg ctx "sendmessage-guard: guards-unified is unreachable right now. This message was checked for secrets via a local-only scan (${SECRET_NOTE}), but PII scanning could not run — review it yourself if it might contain PII, before assuming it's clean." \
    "${JQ_ARGS[@]}" \
    "{
      hookSpecificOutput: {
        hookEventName: \"PreToolUse\",
        permissionDecision: \"allow\",
        permissionDecisionReason: \$reason,
        updatedInput: ((\$orig_raw | fromjson) + $MERGE),
        additionalContext: \$ctx
      }
    }"
  exit 0
fi

# Snapshot message's own result immediately — scan_remote's globals
# are reused below for summary/content, and get overwritten by their
# own scan_remote calls, so anything that needs MESSAGE's result later
# must read it from these snapshots, never the live globals (confirmed
# by hitting exactly this once already: content's "reuse message's
# result" branch read the globals AFTER summary's own scan had already
# clobbered them).
MSG_SECRET_OUT="$SCAN_OUT"
MSG_SECRET_FOUND="$SCAN_SECRET_FOUND"
MSG_PII_TYPES="$SCAN_PII_TYPES"
MSG_COMBINED_OUT="$SCAN_COMBINED_OUT"
MSG_TRUNCATED="$SCAN_TRUNCATED"

ANY_SECRET=0
ALL_PII_TYPES=""
ANY_TRUNCATED=0
MERGE='{message: $msg}'

if [ "$PII_GUARD_MODE" = "redact" ]; then
  MSG_FIELD_OUT="$MSG_COMBINED_OUT"
else
  MSG_FIELD_OUT="$MSG_SECRET_OUT"
fi
[ "$MSG_SECRET_FOUND" -eq 1 ] && ANY_SECRET=1
[ -n "$MSG_PII_TYPES" ] && ALL_PII_TYPES="$MSG_PII_TYPES"
[ "$MSG_TRUNCATED" -eq 1 ] && ANY_TRUNCATED=1
JQ_ARGS=()
add_rawfile_arg msg "$MSG_FIELD_OUT"

if [ "$HAS_SUMMARY" = "true" ]; then
  if [ "$SUMMARY" = "$MESSAGE" ]; then
    SUM_SECRET_OUT="$MSG_SECRET_OUT"; SUM_SECRET_FOUND="$MSG_SECRET_FOUND"
    SUM_PII_TYPES="$MSG_PII_TYPES"; SUM_COMBINED_OUT="$MSG_COMBINED_OUT"; SUM_TRUNCATED="$MSG_TRUNCATED"
  else
    scan_remote_or_local "$SUMMARY"
    SUM_SECRET_OUT="$SCAN_OUT"; SUM_SECRET_FOUND="$SCAN_SECRET_FOUND"
    SUM_PII_TYPES="$SCAN_PII_TYPES"; SUM_COMBINED_OUT="$SCAN_COMBINED_OUT"; SUM_TRUNCATED="$SCAN_TRUNCATED"
  fi
  if [ "$PII_GUARD_MODE" = "redact" ]; then
    SUM_FIELD_OUT="$SUM_COMBINED_OUT"
  else
    SUM_FIELD_OUT="$SUM_SECRET_OUT"
  fi
  SUM_FIELD_OUT="$(truncate_summary "$SUM_FIELD_OUT")"
  [ "$SUM_SECRET_FOUND" -eq 1 ] && ANY_SECRET=1
  [ -n "$SUM_PII_TYPES" ] && ALL_PII_TYPES="${ALL_PII_TYPES:+$ALL_PII_TYPES, }$SUM_PII_TYPES"
  [ "$SUM_TRUNCATED" -eq 1 ] && ANY_TRUNCATED=1
  MERGE="$MERGE + {summary: \$sum}"
  add_rawfile_arg sum "$SUM_FIELD_OUT"
fi

if [ "$HAS_CONTENT" = "true" ]; then
  if [ "$CONTENT" = "$MESSAGE" ]; then
    CON_SECRET_OUT="$MSG_SECRET_OUT"; CON_SECRET_FOUND="$MSG_SECRET_FOUND"
    CON_PII_TYPES="$MSG_PII_TYPES"; CON_COMBINED_OUT="$MSG_COMBINED_OUT"; CON_TRUNCATED="$MSG_TRUNCATED"
  else
    scan_remote_or_local "$CONTENT"
    CON_SECRET_OUT="$SCAN_OUT"; CON_SECRET_FOUND="$SCAN_SECRET_FOUND"
    CON_PII_TYPES="$SCAN_PII_TYPES"; CON_COMBINED_OUT="$SCAN_COMBINED_OUT"; CON_TRUNCATED="$SCAN_TRUNCATED"
  fi
  if [ "$PII_GUARD_MODE" = "redact" ]; then
    CON_FIELD_OUT="$CON_COMBINED_OUT"
  else
    CON_FIELD_OUT="$CON_SECRET_OUT"
  fi
  [ "$CON_SECRET_FOUND" -eq 1 ] && ANY_SECRET=1
  [ -n "$CON_PII_TYPES" ] && ALL_PII_TYPES="${ALL_PII_TYPES:+$ALL_PII_TYPES, }$CON_PII_TYPES"
  [ "$CON_TRUNCATED" -eq 1 ] && ANY_TRUNCATED=1
  MERGE="$MERGE + {content: \$con}"
  add_rawfile_arg con "$CON_FIELD_OUT"
fi

# A flag-mode PII note honours GUARDS_PII_IGNORE_ENTITIES and is shown once per session per type
# (json-lib.sh). In redact mode the service already replaced the values, so the note is not filtered.
if [ "$PII_GUARD_MODE" != "redact" ] && [ -n "$ALL_PII_TYPES" ]; then
  ALL_PII_TYPES="$(pii_note_types "$ALL_PII_TYPES" "$(jfield session_id)")"
fi

if [ "$ANY_SECRET" -eq 0 ] && [ -z "$ALL_PII_TYPES" ] && [ "$ANY_TRUNCATED" -eq 0 ] && [ "$PII_UNAVAILABLE" -eq 0 ]; then
  exit 0
fi

# De-dupe the PII type list (message/summary/content can each surface
# the same type independently).
if [ -n "$ALL_PII_TYPES" ]; then
  ALL_PII_TYPES="$(printf '%s' "$ALL_PII_TYPES" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | sort -u | paste -sd, - | sed 's/,/, /g')"
fi

REASON_PARTS=()
CTX_PARTS=()
if [ "$ANY_SECRET" -eq 1 ]; then
  REASON_PARTS+=("redacted secret")
  CTX_PARTS+=("A secret was found and redacted before send.")
fi
if [ -n "$ALL_PII_TYPES" ]; then
  if [ "$PII_GUARD_MODE" = "redact" ]; then
    REASON_PARTS+=("redacted pii (${ALL_PII_TYPES})")
    CTX_PARTS+=("PII (${ALL_PII_TYPES}) was found and redacted before send.")
  else
    REASON_PARTS+=("flagged pii (${ALL_PII_TYPES}), not redacted")
    CTX_PARTS+=("sendmessage-guard flagged possible PII (${ALL_PII_TYPES}) in this message — values left intact, not redacted. Verify this is appropriate for the recipient before relying on it being clean.")
  fi
fi
if [ "$ANY_TRUNCATED" -eq 1 ]; then
  REASON_PARTS+=("one or more fields exceeded ${SCAN_MAX_BYTES} bytes, only the first ${SCAN_MAX_BYTES} bytes of each were scanned")
  CTX_PARTS+=("One or more fields were larger than the ${SCAN_MAX_BYTES}-byte scan limit -- only the first ${SCAN_MAX_BYTES} bytes of each were checked for secrets/PII. The rest was sent as-is, unscanned. Review it yourself before assuming it's clean.")
fi
if [ "$PII_UNAVAILABLE" -eq 1 ]; then
  REASON_PARTS+=("summary/content got a local secret-only scan, PII scan unavailable (service out of time)")
  CTX_PARTS+=("The guards-unified service ran out of time for the summary or content field, so those were checked for secrets by the local scan only and not for PII.")
fi
REASON="sendmessage-guard: $(printf '%s; ' "${REASON_PARTS[@]}")"
CTX="$(printf '%s ' "${CTX_PARTS[@]}")"

# additionalContext is written as a plain factual statement, not an
# imperative instruction, per Claude Code's own hooks docs: imperative
# phrasing in a field designed to inject context back into the model
# is exactly the shape a prompt-injection defense watches for, and
# this hook has no business tripping that itself.
jq -n \
  --rawfile orig_raw "$ORIGINAL_INPUT_FILE" \
  --arg reason "$REASON" \
  --arg ctx "$CTX" \
  "${JQ_ARGS[@]}" \
  "{
    hookSpecificOutput: {
      hookEventName: \"PreToolUse\",
      permissionDecision: \"allow\",
      permissionDecisionReason: \$reason,
      updatedInput: ((\$orig_raw | fromjson) + $MERGE),
      additionalContext: \$ctx
    }
  }"
exit 0
