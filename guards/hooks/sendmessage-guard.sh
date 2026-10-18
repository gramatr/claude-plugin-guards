#!/usr/bin/env bash
# guards/hooks/sendmessage-guard.sh — PreToolUse hook on SendMessage.
#
# REDACTS and informs, rather than blocking outright — matching
# secret-guard/pii-guard's own posture everywhere else in this stack
# (exact-span redaction, not a whole-call denial), now that
# guards-unified's redacted_text gives us the same exact-span
# information for an outgoing message that it already gives for
# incoming tool output. Only the fail-closed backend-unreachable case
# still denies outright — there's nothing to redact against if the
# scan itself couldn't run.
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
# Redacts every text-bearing copy of the message, not just the field
# named "message" — tool_input carries at least `message`, `summary`,
# and `content` as overlapping copies of the same text (confirmed by
# harvesting a real payload), and `summary` is documented as "not
# transmitted" to the recipient but can still land in local logs/
# transcripts. Patching only `message` while leaving a secret sitting
# in `content` or `summary` would be an incomplete fix with false
# confidence — worse than doing nothing, because it would look safe.
#
# Both secret and PII findings get redacted here — a different policy
# than a user's own prompt to their own agent (where PII isn't acted
# on, because it's the user's own data in their own conversation): the
# recipient of a SendMessage call is a different agent, possibly a
# different party entirely. The injection finding is ignored for this
# decision — the message is authored by the sending agent itself, not
# forwarded untrusted content.

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
  jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "sendmessage-guard: guards-unified backend unreachable, denying by default (fail-closed — nothing can be safely redacted without a scan result, and an unsent message is recoverable while a sent one is not)"}}'
  exit 0
fi

SECRET_FOUND="$(echo "$RESPONSE" | jq -r '.findings[] | select(.type=="secret") | .verdict' 2>/dev/null)"
PII_FOUND="$(echo "$RESPONSE" | jq -r '.findings[] | select(.type=="pii") | .verdict' 2>/dev/null)"

if [ "$SECRET_FOUND" != "found" ] && [ "$PII_FOUND" != "found" ]; then
  exit 0
fi

REDACTED_TEXT="$(echo "$RESPONSE" | jq -r '.redacted_text')"
REASON_CODES="$(echo "$RESPONSE" | jq -r '[.findings[] | select(.type=="secret" or .type=="pii") | select(.verdict=="found") | .type] | join(", ")' 2>/dev/null)"
ORIGINAL_INPUT="$(printf '%s' "$RAW" | jq -c '.tool_input')"

# additionalContext is written as a plain factual statement, not an
# imperative instruction, per Claude Code's own hooks docs: imperative
# phrasing in a field designed to inject context back into the model
# is exactly the shape a prompt-injection defense watches for, and
# this hook has no business tripping that itself.
jq -n \
  --argjson orig "$ORIGINAL_INPUT" \
  --arg redacted "$REDACTED_TEXT" \
  --arg reason "sendmessage-guard: redacted ${REASON_CODES} from the outgoing message before send" \
  --arg ctx "sendmessage-guard found and redacted ${REASON_CODES} in this outgoing message before it was sent. The recipient will see the redacted version, not the original." \
  '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: $reason,
      updatedInput: ($orig + {message: $redacted, summary: $redacted, content: $redacted}),
      additionalContext: $ctx
    }
  }'
exit 0
