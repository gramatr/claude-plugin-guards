#!/usr/bin/env bash
# guards/hooks/sendmessage-guard.sh — PreToolUse hook on SendMessage.
#
# Blocks an outgoing agent-to-agent message if it contains a secret or
# PII, BEFORE the message is sent — this is a different trust boundary
# than UserPromptSubmit (a user's own prompt to their own agent): the
# recipient here is a different agent/session, possibly a different
# user, possibly logged or relayed elsewhere. Both secret and PII
# findings gate the call; the injection finding is ignored for this
# decision (the message is authored by the sending agent itself, not
# forwarded untrusted content, so "is this an injection attempt" isn't
# the relevant question here).
#
# Scans tool_input.message — confirmed by actually harvesting a real
# SendMessage PreToolUse payload this session, NOT tool_input.content,
# which is a truncated preview ("...for h…") that would silently miss
# content past the truncation point.
#
# Fails CLOSED here, not open like combined-hook.sh's Bash stage: if
# guards-unified is unreachable, this hook denies the call rather than
# letting it through unchecked. Reasoning: combined-hook.sh's fail-open
# is about not blocking a session on a missed *detection* (annoying but
# recoverable); here the thing being protected is an irreversible send
# to another party — once a message leaves, it's left. Fail-open would
# turn "backend happens to be down" into a silent bypass of the one
# control this hook exists to provide.

set -uo pipefail

GUARDS_ENDPOINT="${GUARDS_ENDPOINT:-http://127.0.0.1:8700}"

RAW="$(cat)"
TOOL_NAME="$(printf '%s' "$RAW" | jq -r '.tool_name // ""' 2>/dev/null)"
if [ "$TOOL_NAME" != "SendMessage" ]; then
  exit 0
fi

MESSAGE="$(printf '%s' "$RAW" | jq -r '.tool_input.message // ""' 2>/dev/null)"
if [ -z "$MESSAGE" ]; then
  exit 0
fi

RESPONSE="$(jq -n --arg text "$MESSAGE" '{text: $text}' 2>/dev/null \
  | curl -sS -m 10 -X POST "${GUARDS_ENDPOINT}/v1/scan" \
      -H "Content-Type: application/json" -d @- 2>/dev/null)"

if [ -z "$RESPONSE" ]; then
  jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "sendmessage-guard: guards-unified backend unreachable, denying by default (fail-closed — an unsent message is recoverable, a sent one is not)"}}'
  exit 0
fi

SECRET_FOUND="$(echo "$RESPONSE" | jq -r '.findings[] | select(.type=="secret") | .verdict' 2>/dev/null)"
PII_FOUND="$(echo "$RESPONSE" | jq -r '.findings[] | select(.type=="pii") | .verdict' 2>/dev/null)"

if [ "$SECRET_FOUND" = "found" ] || [ "$PII_FOUND" = "found" ]; then
  REASON_CODES="$(echo "$RESPONSE" | jq -r '[.findings[] | select(.type=="secret" or .type=="pii") | select(.verdict=="found") | .type] | join(", ")' 2>/dev/null)"
  jq -n --arg reason "sendmessage-guard: outgoing message contains ${REASON_CODES} — denied before send. Remove the flagged content and retry, or confirm with the user if this is intentional." \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
fi

exit 0
