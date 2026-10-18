#!/usr/bin/env bash
# guards/hooks/sendmessage-guard.sh — PreToolUse hook on SendMessage.
#
# REDACTS and informs, rather than blocking outright — matching
# secret-guard/pii-guard's own posture everywhere else in this stack
# (exact-span redaction, not a whole-call denial), now that
# guards-unified's redacted_text gives us the same exact-span
# information for an outgoing message that it already gives for
# incoming tool output.
#
# BACKEND-UNREACHABLE CASE: degrades, does not block outright. Used to
# deny every message outright when guards-unified was unreachable —
# changed after that fail-closed-on-outage behavior was blocking
# ordinary cross-agent coordination entirely on a single downstream
# dependency being down, with no way to route around it. Now falls
# back to the same vendored gitleaks secret-only scan combined-hook.sh
# already uses for its own backend-unreachable case: secrets still get
# real local coverage (no network dependency), and the message is
# allowed through with a clear warning that PII scanning couldn't run
# (no local equivalent to gitleaks exists for PII) — degraded and
# disclosed, not silently unsafe, and not a blanket block either.
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
# hard-truncated to 200 chars after its own redaction, defensively —
# never trust a redaction step to respect a downstream schema's limit
# just because it shouldn't normally lengthen text much.
#
# Both secret and PII findings get redacted here — a different policy
# than a user's own prompt to their own agent (where PII isn't acted
# on, because it's the user's own data in their own conversation): the
# recipient of a SendMessage call is a different agent, possibly a
# different party entirely. The injection finding is ignored for this
# decision — the message is authored by the sending agent itself, not
# forwarded untrusted content.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDS_ROOT="$(dirname "$SCRIPT_DIR")"
SECRET_SCAN="$GUARDS_ROOT/vendor/secret-guard-core/scan.sh"
GUARDS_ENDPOINT="${GUARDS_ENDPOINT:-http://127.0.0.1:8700}"
SUMMARY_MAX=200

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

# scan_remote TEXT -- sets SCAN_OUT (redacted text) and SCAN_TYPES
# (comma-joined finding types, empty if clean) as a side effect.
# Returns 1 if guards-unified itself didn't answer at all.
scan_remote() {
  local text="$1" resp
  SCAN_OUT="$text"
  SCAN_TYPES=""
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
  SCAN_TYPES="$(echo "$resp" | jq -r '[.findings[] | select(.type=="secret" or .type=="pii") | select(.verdict=="found") | .type] | unique | join(", ")' 2>/dev/null)"
  if [ -n "$SCAN_TYPES" ]; then
    SCAN_OUT="$(echo "$resp" | jq -r '.redacted_text' 2>/dev/null)"
  fi
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
  MSG_OUT="$MESSAGE"
  SECRET_NOTE="no secret found by local scan"
  scan_local_secret_only "$MESSAGE"
  if [ "$SCAN_FOUND" -eq 1 ]; then
    MSG_OUT="$SCAN_OUT"
    SECRET_NOTE="a secret was found and redacted by the local-only scan"
  fi
  MERGE='{message: $msg}'
  JQ_ARGS=(--arg msg "$MSG_OUT")
  if [ "$HAS_SUMMARY" = "true" ]; then
    scan_local_secret_only "$SUMMARY"
    SUM_OUT="$(truncate_summary "$SCAN_OUT")"
    MERGE="$MERGE + {summary: \$sum}"
    JQ_ARGS+=(--arg sum "$SUM_OUT")
  fi
  if [ "$HAS_CONTENT" = "true" ]; then
    scan_local_secret_only "$CONTENT"
    MERGE="$MERGE + {content: \$con}"
    JQ_ARGS+=(--arg con "$SCAN_OUT")
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

# Snapshot message's own result immediately — scan_remote's SCAN_OUT/
# SCAN_TYPES are reused below for summary/content, and get overwritten
# by their own scan_remote calls, so anything that needs MESSAGE's
# result later must read it from these snapshots, never the live
# globals (confirmed by hitting exactly this: content's "reuse
# message's result" branch read the globals AFTER summary's own scan
# had already clobbered them, silently sending summary's redacted text
# in the content field instead of message's).
MSG_OUT="$SCAN_OUT"
MSG_TYPES="$SCAN_TYPES"
ALL_TYPES="$MSG_TYPES"
MERGE='{message: $msg}'
JQ_ARGS=(--arg msg "$MSG_OUT")

if [ "$HAS_SUMMARY" = "true" ]; then
  if [ "$SUMMARY" = "$MESSAGE" ]; then
    SUM_OUT="$MSG_OUT"
    SUM_TYPES="$MSG_TYPES"
  else
    scan_remote "$SUMMARY"
    SUM_OUT="$SCAN_OUT"
    SUM_TYPES="$SCAN_TYPES"
  fi
  SUM_OUT="$(truncate_summary "$SUM_OUT")"
  [ -n "$SUM_TYPES" ] && ALL_TYPES="${ALL_TYPES:+$ALL_TYPES, }$SUM_TYPES"
  MERGE="$MERGE + {summary: \$sum}"
  JQ_ARGS+=(--arg sum "$SUM_OUT")
fi

if [ "$HAS_CONTENT" = "true" ]; then
  if [ "$CONTENT" = "$MESSAGE" ]; then
    CON_OUT="$MSG_OUT"
    CON_TYPES="$MSG_TYPES"
  else
    scan_remote "$CONTENT"
    CON_OUT="$SCAN_OUT"
    CON_TYPES="$SCAN_TYPES"
  fi
  [ -n "$CON_TYPES" ] && ALL_TYPES="${ALL_TYPES:+$ALL_TYPES, }$CON_TYPES"
  MERGE="$MERGE + {content: \$con}"
  JQ_ARGS+=(--arg con "$CON_OUT")
fi

if [ -z "$ALL_TYPES" ]; then
  exit 0
fi

# De-dupe the type list (message/summary/content can each surface the
# same type independently).
ALL_TYPES="$(printf '%s' "$ALL_TYPES" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | sort -u | paste -sd, - | sed 's/,/, /g')"

# additionalContext is written as a plain factual statement, not an
# imperative instruction, per Claude Code's own hooks docs: imperative
# phrasing in a field designed to inject context back into the model
# is exactly the shape a prompt-injection defense watches for, and
# this hook has no business tripping that itself.
jq -n \
  --argjson orig "$ORIGINAL_INPUT" \
  --arg reason "sendmessage-guard: redacted ${ALL_TYPES} from the outgoing message before send" \
  --arg ctx "sendmessage-guard found and redacted ${ALL_TYPES} in this outgoing message before it was sent. The recipient will see the redacted version, not the original." \
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
