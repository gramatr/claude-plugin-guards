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
# (gramatr/claude-plugin-guards#25): `summary` is a short,
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDS_ROOT="$(dirname "$SCRIPT_DIR")"
SECRET_SCAN="$GUARDS_ROOT/vendor/secret-guard-core/scan.sh"
GUARDS_ENDPOINT="${GUARDS_ENDPOINT:-http://127.0.0.1:8700}"
SUMMARY_MAX=200
PII_GUARD_MODE="${PII_GUARD_MODE:-flag}"

RAW="$(cat)"
TOOL_NAME="$(printf '%s' "$RAW" | jq -r '.tool_name // ""' 2>/dev/null)"
if [ "$TOOL_NAME" != "SendMessage" ]; then
  exit 0
fi

MESSAGE="$(printf '%s' "$RAW" | jq -r '.tool_input.message // ""' 2>/dev/null)"
if [ -z "$MESSAGE" ]; then
  exit 0
fi

ORIGINAL_INPUT="$(printf '%s' "$RAW" | jq -c '.tool_input')"
HAS_SUMMARY="$(printf '%s' "$RAW" | jq -r '.tool_input | has("summary")' 2>/dev/null)"
HAS_CONTENT="$(printf '%s' "$RAW" | jq -r '.tool_input | has("content")' 2>/dev/null)"
SUMMARY="$(printf '%s' "$RAW" | jq -r '.tool_input.summary // ""' 2>/dev/null)"
CONTENT="$(printf '%s' "$RAW" | jq -r '.tool_input.content // ""' 2>/dev/null)"

# truncate_summary TEXT -- hard cap at SUMMARY_MAX chars, defensively,
# regardless of what redaction did to the text. jq's `.[0:N]` on a
# string slices by Unicode codepoint, not byte, matching how the
# SendMessage schema's own `maximum` is almost certainly counted.
truncate_summary() {
  jq -nr --arg t "$1" --argjson n "$SUMMARY_MAX" '$t[0:$n]'
}

# scan_remote TEXT -- sets, as side effects:
#   SCAN_OUT             text with ONLY secret redaction applied (PII left intact)
#   SCAN_SECRET_FOUND    1 if a secret was found in this text, else 0
#   SCAN_PII_TYPES       comma-joined PII entity types found, empty if none
#   SCAN_COMBINED_OUT    text with BOTH secret and PII redacted (legacy wholesale), for PII_GUARD_MODE=redact
# Returns 1 if guards-unified itself didn't answer at all.
scan_remote() {
  local text="$1" resp
  SCAN_OUT="$text"
  SCAN_SECRET_FOUND=0
  SCAN_PII_TYPES=""
  SCAN_COMBINED_OUT="$text"
  resp="$(jq -n --arg text "$text" '{text: $text}' 2>/dev/null \
    | curl -sS -m 10 -X POST "${GUARDS_ENDPOINT}/v1/scan" \
        -H "Content-Type: application/json" -d @- 2>/dev/null)"
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
    [ -z "$SCAN_OUT" ] && SCAN_OUT="$text"
  fi
  SCAN_PII_TYPES="$(echo "$resp" | jq -r '[.findings[] | select(.type=="pii") | .detail.entities[]?.entity_type] | unique | join(", ")' 2>/dev/null)"
  SCAN_COMBINED_OUT="$(echo "$resp" | jq -r '.redacted_text // empty' 2>/dev/null)"
  [ -z "$SCAN_COMBINED_OUT" ] && SCAN_COMBINED_OUT="$text"
  return 0
}

# scan_local_secret_only TEXT -- sets SCAN_OUT and SCAN_FOUND=0|1,
# via the vendored gitleaks fallback (no network dependency).
scan_local_secret_only() {
  local text="$1" redacted
  SCAN_OUT="$text"
  SCAN_FOUND=0
  [ -z "$text" ] && return 0
  if [ -x "$SECRET_SCAN" ]; then
    redacted="$(printf '%s' "$text" | "$SECRET_SCAN" 2>/dev/null)"
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
  JQ_ARGS=(--arg msg "$MSG_OUT")
  if [ "$HAS_SUMMARY" = "true" ]; then
    scan_local_secret_only "$SUMMARY"
    [ "$SCAN_FOUND" -eq 1 ] && ANY_LOCAL_SECRET=1
    SUM_OUT="$(truncate_summary "$SCAN_OUT")"
    MERGE="$MERGE + {summary: \$sum}"
    JQ_ARGS+=(--arg sum "$SUM_OUT")
  fi
  if [ "$HAS_CONTENT" = "true" ]; then
    scan_local_secret_only "$CONTENT"
    [ "$SCAN_FOUND" -eq 1 ] && ANY_LOCAL_SECRET=1
    MERGE="$MERGE + {content: \$con}"
    JQ_ARGS+=(--arg con "$SCAN_OUT")
  fi
  if [ "$ANY_LOCAL_SECRET" -eq 1 ]; then
    SECRET_NOTE="a secret was found and redacted by the local-only scan"
  else
    SECRET_NOTE="no secret found by local scan"
  fi
  jq -n \
    --argjson orig "$ORIGINAL_INPUT" \
    --arg reason "sendmessage-guard: guards-unified backend unreachable — sent via local-only secret scan (${SECRET_NOTE}); PII scan unavailable until backend is back" \
    --arg ctx "sendmessage-guard: guards-unified is unreachable right now. This message was checked for secrets via a local-only scan (${SECRET_NOTE}), but PII scanning could not run — review it yourself if it might contain PII, before assuming it's clean." \
    "${JQ_ARGS[@]}" \
    "{
      hookSpecificOutput: {
        hookEventName: \"PreToolUse\",
        permissionDecision: \"allow\",
        permissionDecisionReason: \$reason,
        updatedInput: (\$orig + $MERGE),
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

ANY_SECRET=0
ALL_PII_TYPES=""
MERGE='{message: $msg}'

if [ "$PII_GUARD_MODE" = "redact" ]; then
  MSG_FIELD_OUT="$MSG_COMBINED_OUT"
else
  MSG_FIELD_OUT="$MSG_SECRET_OUT"
fi
[ "$MSG_SECRET_FOUND" -eq 1 ] && ANY_SECRET=1
[ -n "$MSG_PII_TYPES" ] && ALL_PII_TYPES="$MSG_PII_TYPES"
JQ_ARGS=(--arg msg "$MSG_FIELD_OUT")

if [ "$HAS_SUMMARY" = "true" ]; then
  if [ "$SUMMARY" = "$MESSAGE" ]; then
    SUM_SECRET_OUT="$MSG_SECRET_OUT"; SUM_SECRET_FOUND="$MSG_SECRET_FOUND"
    SUM_PII_TYPES="$MSG_PII_TYPES"; SUM_COMBINED_OUT="$MSG_COMBINED_OUT"
  else
    scan_remote "$SUMMARY"
    SUM_SECRET_OUT="$SCAN_OUT"; SUM_SECRET_FOUND="$SCAN_SECRET_FOUND"
    SUM_PII_TYPES="$SCAN_PII_TYPES"; SUM_COMBINED_OUT="$SCAN_COMBINED_OUT"
  fi
  if [ "$PII_GUARD_MODE" = "redact" ]; then
    SUM_FIELD_OUT="$SUM_COMBINED_OUT"
  else
    SUM_FIELD_OUT="$SUM_SECRET_OUT"
  fi
  SUM_FIELD_OUT="$(truncate_summary "$SUM_FIELD_OUT")"
  [ "$SUM_SECRET_FOUND" -eq 1 ] && ANY_SECRET=1
  [ -n "$SUM_PII_TYPES" ] && ALL_PII_TYPES="${ALL_PII_TYPES:+$ALL_PII_TYPES, }$SUM_PII_TYPES"
  MERGE="$MERGE + {summary: \$sum}"
  JQ_ARGS+=(--arg sum "$SUM_FIELD_OUT")
fi

if [ "$HAS_CONTENT" = "true" ]; then
  if [ "$CONTENT" = "$MESSAGE" ]; then
    CON_SECRET_OUT="$MSG_SECRET_OUT"; CON_SECRET_FOUND="$MSG_SECRET_FOUND"
    CON_PII_TYPES="$MSG_PII_TYPES"; CON_COMBINED_OUT="$MSG_COMBINED_OUT"
  else
    scan_remote "$CONTENT"
    CON_SECRET_OUT="$SCAN_OUT"; CON_SECRET_FOUND="$SCAN_SECRET_FOUND"
    CON_PII_TYPES="$SCAN_PII_TYPES"; CON_COMBINED_OUT="$SCAN_COMBINED_OUT"
  fi
  if [ "$PII_GUARD_MODE" = "redact" ]; then
    CON_FIELD_OUT="$CON_COMBINED_OUT"
  else
    CON_FIELD_OUT="$CON_SECRET_OUT"
  fi
  [ "$CON_SECRET_FOUND" -eq 1 ] && ANY_SECRET=1
  [ -n "$CON_PII_TYPES" ] && ALL_PII_TYPES="${ALL_PII_TYPES:+$ALL_PII_TYPES, }$CON_PII_TYPES"
  MERGE="$MERGE + {content: \$con}"
  JQ_ARGS+=(--arg con "$CON_FIELD_OUT")
fi

if [ "$ANY_SECRET" -eq 0 ] && [ -z "$ALL_PII_TYPES" ]; then
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
REASON="sendmessage-guard: $(printf '%s; ' "${REASON_PARTS[@]}")"
CTX="$(printf '%s ' "${CTX_PARTS[@]}")"

# additionalContext is written as a plain factual statement, not an
# imperative instruction, per Claude Code's own hooks docs: imperative
# phrasing in a field designed to inject context back into the model
# is exactly the shape a prompt-injection defense watches for, and
# this hook has no business tripping that itself.
jq -n \
  --argjson orig "$ORIGINAL_INPUT" \
  --arg reason "$REASON" \
  --arg ctx "$CTX" \
  "${JQ_ARGS[@]}" \
  "{
    hookSpecificOutput: {
      hookEventName: \"PreToolUse\",
      permissionDecision: \"allow\",
      permissionDecisionReason: \$reason,
      updatedInput: (\$orig + $MERGE),
      additionalContext: \$ctx
    }
  }"
exit 0
