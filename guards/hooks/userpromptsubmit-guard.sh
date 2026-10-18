#!/usr/bin/env bash
# guards/hooks/userpromptsubmit-guard.sh — UserPromptSubmit hook.
#
# Blocks a user's own prompt before it reaches the model if it
# contains a secret. See docs/scope/ship-private-marketplace-plugin-2026-10-18.md,
# Unit U4 for the full design discussion; summarized here:
#
# SECRET FINDINGS ONLY — PII is explicitly out of scope. It's the
# user's own data in their own conversation; blocking on PII here
# would be noise, not protection. The injection finding is also out of
# scope: this is the user's own direct instruction to their own
# agent, not forwarded untrusted content, so "is this an injection
# attempt" isn't a meaningful question for a user's own prompt.
#
# BLOCK, NOT REDACT. Unlike sendmessage-guard.sh's PreToolUse hook,
# UserPromptSubmit's hook protocol is binary — confirmed directly
# against Claude Code's own hooks docs before building this: the only
# value for `decision` is "block"; there is no "ask"/"allow" and no
# updatedInput-style rewrite for this event. Block is the only
# available control for a detected secret here, not a softer policy
# choice this project made on its own.
#
# BLOCKING IS NOT A COMPLETE SECRECY GUARANTEE — confirmed from the
# same docs: even with suppressOriginalPrompt:true (set below), the
# blocked prompt's text can still land in the session transcript and
# prompt history on disk. This hook prevents the secret from reaching
# the model/API call, which is real and worth having; it does not
# prevent local disk exposure, and must not be described as if it did.
#
# FAILS OPEN on backend-unreachable — resolved deliberately, the
# opposite of sendmessage-guard.sh's fail-closed stance. Fail-closed
# there costs one occasional agent-to-agent send during an outage.
# Fail-closed here would block every single prompt the user types for
# as long as guards-unified is down, turning a safety net into a
# single point of failure for using Claude Code at all.

set -uo pipefail

GUARDS_ENDPOINT="${GUARDS_ENDPOINT:-http://127.0.0.1:8700}"

RAW="$(cat)"

PROMPT="$(printf '%s' "$RAW" | jq -r '.prompt // ""' 2>/dev/null)"
if [ -z "$PROMPT" ]; then
  exit 0
fi

RESPONSE="$(jq -n --arg text "$PROMPT" '{text: $text}' 2>/dev/null \
  | curl -sS -m 10 -X POST "${GUARDS_ENDPOINT}/v1/scan" \
      -H "Content-Type: application/json" -d @- 2>/dev/null)"

if [ -z "$RESPONSE" ]; then
  # Backend unreachable: fail OPEN, deliberately (see module comment
  # above for why this is the one hook in this stack that doesn't
  # fail closed on an unreachable backend).
  exit 0
fi

SECRET_FOUND="$(echo "$RESPONSE" | jq -r '.findings[] | select(.type=="secret") | .verdict' 2>/dev/null)"

if [ "$SECRET_FOUND" != "found" ]; then
  exit 0
fi

jq -n '{
  decision: "block",
  reason: "userpromptsubmit-guard: this prompt contains what looks like a live secret. Remove it and resubmit, or confirm with a human if this is intentional. Note: blocking keeps this out of the model/API call, but the text may still be present in your local session transcript/prompt history on disk.",
  hookSpecificOutput: {
    hookEventName: "UserPromptSubmit",
    suppressOriginalPrompt: true
  }
}'
exit 0
