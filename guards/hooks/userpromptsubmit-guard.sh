#!/usr/bin/env bash
# guards/hooks/userpromptsubmit-guard.sh — UserPromptSubmit hook.
#
# ADVISORY ONLY — does NOT prevent a detected secret from reaching the
# model/API. This was a deliberate change from the original design
# (which blocked outright): confirmed directly against Claude Code's
# own hooks docs that UserPromptSubmit has no way to rewrite or remove
# part of the prompt — "can't replace the prompt; it only injects
# additionalContext alongside it," unchanged. So the real choice for
# this event is binary: block the WHOLE prompt, or let it through
# unchanged with a note. This file does the latter, on purpose, not
# because redaction was attempted and failed.
#
# Chosen explicitly over blocking, knowingly: a detected secret still
# gets submitted and sent to the API exactly as typed. The
# additionalContext note only makes the agent (and transitively, via
# the agent's own response, the user) AWARE that a secret-shaped value
# was present — it does not stop the exposure, which already happened
# the moment the prompt was submitted. If the secret is real, treat it
# as potentially logged by this point and rotate it; the hook
# producing a note after the fact doesn't undo that.
#
# SECRET FINDINGS ONLY — PII is still explicitly out of scope: it's
# the user's own data in their own conversation, so flagging it would
# be noise, not protection. The injection finding is also out of
# scope: this is the user's own direct instruction to their own agent,
# not forwarded untrusted content.
#
# FAILS OPEN on backend-unreachable — same as before, now simpler to
# reason about: this hook never blocks anything regardless of the
# backend, so unreachable just means no note gets added. Nothing to
# fail open FROM in the blocking sense anymore.

set -uo pipefail

# Own deadline below the hook timeout in hooks.json: Claude Code fails open when
# a hook outlives it. Re-runs this script bounded; see deadline-lib.sh.
# shellcheck source=guards/hooks/deadline-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/deadline-lib.sh" && guards_deadline silent 10

GUARDS_ENDPOINT="${GUARDS_ENDPOINT:-http://127.0.0.1:8700}"

RAW="$(cat)"

PROMPT="$(printf '%s' "$RAW" | jq -r '.prompt // ""' 2>/dev/null)"
if [ -z "$PROMPT" ]; then
  exit 0
fi

# Secrets only, so the cheap secret-only route (about 55 ms, no models) scans the
# prompt; the full route would run the PII and injection models for a finding
# this hook throws away, and refuses bodies over 64 KiB. The text goes to jq on
# stdin, never as an argument, because one argument cannot exceed about 128 KB.
# The route's own cap is 1 MiB, so the prompt is cut at 900000 bytes (the head
# is what a person types or pastes first).
RESPONSE="$(printf '%s' "$PROMPT" | head -c 900000 | jq -Rs '{text: .}' 2>/dev/null \
  | curl -sS --connect-timeout 3 -m 8 -X POST "${GUARDS_ENDPOINT}/v1/scan/secret" \
      -H "Content-Type: application/json" -d @- 2>/dev/null)"

# A non-empty RESPONSE isn't enough on its own -- a truncated body or
# a well-formed error JSON missing "findings" would otherwise make the
# jq extraction below silently return "", indistinguishable from
# "scanned, nothing found." This hook already fails open on empty
# response (advisory-only, no local fallback exists); malformed gets
# the same treatment, not a silent false-clean.
if [ -z "$RESPONSE" ] || ! echo "$RESPONSE" | jq -e '.findings | type == "array"' >/dev/null 2>&1; then
  exit 0
fi

SECRET_FOUND="$(echo "$RESPONSE" | jq -r '.findings[] | select(.type=="secret") | .verdict' 2>/dev/null)"

if [ "$SECRET_FOUND" != "found" ]; then
  exit 0
fi

# Factual statement, not an imperative instruction — additionalContext
# feeds back into the model's own context, and imperative phrasing
# there is exactly the shape a prompt-injection defense watches for.
# This hook has no business tripping that itself.
jq -n '{
  hookSpecificOutput: {
    hookEventName: "UserPromptSubmit",
    additionalContext: "userpromptsubmit-guard detected a secret-shaped value in this prompt. The prompt was submitted unchanged -- this note does not prevent or undo that. If the value is a real, live credential, it should be treated as exposed and rotated."
  }
}'
exit 0
