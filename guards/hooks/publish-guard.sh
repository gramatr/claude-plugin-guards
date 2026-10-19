#!/usr/bin/env bash
# guards/hooks/publish-guard.sh — PreToolUse hook on Bash (and GitHub MCP
# write tools): BLOCKS commands that would publish credential material.
#
# WHY: a live secret key was quoted in the body of a public GitHub issue
# (guards-unified#18, since deleted); nothing in the plugin looked at
# outbound text. Redaction after the fact cannot help once something is
# published, and GitHub push protection only knows vendor token formats
# and does not scan issue bodies at all.
#
# WHAT IT SCANS, when the command publishes something:
#   gh issue|pr|release|gist create|comment|edit|review
#   gh api with a body (-f/-F/--field/--raw-field/--input)
#   git commit  (the -m/-F message AND the staged diff's added lines)
# Scanned text is the full command (heredoc bodies included) PLUS the
# contents of files the command names (--body-file/-F/--notes-file/
# --input, `cat FILE`, gist files) -- otherwise `--body-file x.md` would
# be a trivial bypass. For GitHub MCP write tools the whole tool_input.
#
# HOW: the plugin's vendored scan.sh, run locally. Not the guards-unified
# service: it is slow on large text (its injection model is CPU-bound),
# and a publish check must not depend on a network daemon being up. That
# scan.sh includes the gitleaks pass, the private-key pass and the
# context-aware pass (secret-word lead-ins, URL passwords, Authorization
# headers).
#
# ON A FINDING: DENY (never silently redact: a mangled post still
# publishes and hides the mistake). The message names the rule IDs, never
# a value, and tells the agent to describe the SHAPE only.
#
# FAIL CLOSED: if the scanner cannot run at all (script missing, crashed,
# timed out) the publish is denied. If only gitleaks is missing the pure
# bash passes still run; that degraded mode is allowed with a notice.
#
# MARKER: a line containing `guards:synthetic` is dropped from the staged
# diff before scanning. It exists for deliberately fake test fixtures and
# makes the intent visible in review. It does NOT apply to command text,
# issue/PR bodies or files named by the command.
#
# OVERRIDE: GUARDS_ALLOW_PUBLISH_SECRETS=1 in the environment Claude Code
# started from, for a reviewed false positive. Deliberate and visible.
#
# LIMITS: only commands that name a publish verb are inspected; a script
# that publishes indirectly is not. Covers Claude Code sessions with the
# plugin, not the GitHub web UI or a terminal outside Claude Code. Will
# occasionally block a post that merely sits near a secret-ish key name.
#
# Never returns updatedInput, so it can coexist with other PreToolUse
# hooks (see sendmessage-guard.sh's header for why that matters).

set -uo pipefail

[ "${GUARDS_ALLOW_PUBLISH_SECRETS:-0}" = "1" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_SCAN="${GUARDS_SECRET_SCAN:-$(dirname "$SCRIPT_DIR")/vendor/secret-guard-core/scan.sh}"
MAX_BYTES="${PUBLISH_GUARD_MAX_BYTES:-524288}"

RAW="$(cat)"
TOOL_NAME="$(printf '%s' "$RAW" | jq -r '.tool_name // ""' 2>/dev/null)" || exit 0
CWD="$(printf '%s' "$RAW" | jq -r '.cwd // ""' 2>/dev/null)"
[ -n "$CWD" ] || CWD="$PWD"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SCAN_INPUT="$WORK/input.txt"
: > "$SCAN_INPUT"

deny() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

# ask: hand the decision to the HUMAN through Claude Code's built-in permission
# prompt. The agent cannot answer it, so it is not a bypass the agent can type
# for itself. What Claude Code does with an ask when no human is attached (a
# non-interactive run) is not something this plugin controls or has verified;
# set GUARDS_PUBLISH_ASK=0 / GUARDS_CRED_ASK=0 to make those runs hard blocks.
ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

notice() {
  jq -n --arg ctx "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", additionalContext: $ctx}}'
}

append_file() { # append_file PATH LABEL -- readable regular files only, size capped
  local f="$1"
  [ -f "$f" ] && [ -r "$f" ] || return 0
  { printf '\n'; head -c "$MAX_BYTES" -- "$f"; printf '\n'; } >> "$SCAN_INPUT"
}

case "$TOOL_NAME" in
  Bash)
    CMD="$(printf '%s' "$RAW" | jq -r '.tool_input.command // ""' 2>/dev/null)"
    [ -n "$CMD" ] || exit 0

    PUBLISH_RE='(^|[^A-Za-z0-9_-])gh[[:space:]]+(issue|pr|release|gist)[[:space:]]+(create|comment|edit|review)([^A-Za-z0-9_-]|$)'
    API_RE='(^|[^A-Za-z0-9_-])gh[[:space:]]+api[[:space:]]'
    API_BODY_RE='(^|[[:space:]])(-f|-F|--field|--raw-field|--input)([[:space:]=]|$)'
    COMMIT_RE='(^|[^A-Za-z0-9_-])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+commit([^A-Za-z0-9_-]|$)'

    IS_COMMIT=0
    if [[ "$CMD" =~ $PUBLISH_RE ]]; then
      :
    elif [[ "$CMD" =~ $API_RE ]] && [[ "$CMD" =~ $API_BODY_RE ]]; then
      :
    elif [[ "$CMD" =~ $COMMIT_RE ]]; then
      IS_COMMIT=1
    else
      exit 0
    fi

    printf '%s\n' "$CMD" >> "$SCAN_INPUT"

    # Files the command names: --body-file X, -F X, --notes-file X,
    # --input X, `cat X`, plus gist file arguments.
    FILE_FLAG_RE='(--body-file|--notes-file|--input|-F|-f)[[:space:]=]+@?([^[:space:];|&)"'"'"']+)'
    CAT_RE='cat[[:space:]]+([^[:space:];|&)"'"'"'<>]+)'
    rest="$CMD"
    while [[ "$rest" =~ $FILE_FLAG_RE ]]; do
      f="${BASH_REMATCH[2]}"; m="${BASH_REMATCH[0]}"
      [[ "$f" == *=@* ]] && f="${f#*=@}"
      case "$f" in -|/dev/stdin) ;; *) [ -d "$CWD" ] && f="$(cd "$CWD" && realpath -m -- "$f" 2>/dev/null || printf '%s' "$f")"; append_file "$f" ;; esac
      rest="${rest#*"$m"}"
    done
    rest="$CMD"
    while [[ "$rest" =~ $CAT_RE ]]; do
      f="${BASH_REMATCH[1]}"; m="${BASH_REMATCH[0]}"
      [ -d "$CWD" ] && f="$(cd "$CWD" && realpath -m -- "$f" 2>/dev/null || printf '%s' "$f")"
      append_file "$f"
      rest="${rest#*"$m"}"
    done
    if [[ "$CMD" =~ gh[[:space:]]+gist[[:space:]]+create ]]; then
      for tok in $CMD; do
        case "$tok" in -*|gh|gist|create) continue ;; esac
        f="$tok"; [ -d "$CWD" ] && f="$(cd "$CWD" && realpath -m -- "$tok" 2>/dev/null || printf '%s' "$tok")"
        append_file "$f"
      done
    fi

    # git commit: the added lines of the staged diff (and of the working
    # tree for -a/--all), minus lines carrying the synthetic marker.
    if [ "$IS_COMMIT" -eq 1 ]; then
      GITDIR="$CWD"
      if [[ "$CMD" =~ cd[[:space:]]+([^[:space:];\&]+) ]]; then
        c="${BASH_REMATCH[1]}"; [ -d "$c" ] && GITDIR="$c"
      fi
      if [[ "$CMD" =~ git[[:space:]]+-C[[:space:]]+([^[:space:]]+) ]]; then
        GITDIR="${BASH_REMATCH[1]}"
      fi
      DIFF_ARGS=(--cached)
      if [[ "$CMD" =~ [[:space:]](-[A-Za-z]*a[A-Za-z]*|--all)([[:space:]]|$) ]]; then
        DIFF_ARGS=(HEAD)
      fi
      git -C "$GITDIR" diff "${DIFF_ARGS[@]}" -U0 --no-color 2>/dev/null \
        | grep -E '^\+' | grep -vE '^\+\+\+ ' | grep -v 'guards:synthetic' \
        | head -c "$MAX_BYTES" >> "$SCAN_INPUT"
    fi
    LABEL="this command"
    ;;
  mcp__*)
    case "$TOOL_NAME" in
      *create*|*update*|*add_*|*comment*|*push*|*merge*|*review*|*edit*|*post*|*send*|*write*) ;;
      *) exit 0 ;;
    esac
    printf '%s' "$RAW" | jq -r '.tool_input | tostring' >> "$SCAN_INPUT" 2>/dev/null
    LABEL="this $TOOL_NAME call"
    ;;
  *) exit 0 ;;
esac

[ -s "$SCAN_INPUT" ] || exit 0

# Secrets only, fast: the warm service's secret-only route plus the local-
# environment passes, falling back to the full local scan.sh if the service is
# unavailable (see secret-scan-lib.sh). If NO scanner can run, we cannot vouch
# for the text, so deny: a publish cannot be un-done.
SS_WORK="$WORK"
# shellcheck source=guards/hooks/secret-scan-lib.sh
. "$SCRIPT_DIR/secret-scan-lib.sh"
if ! secret_scan "$SCAN_INPUT"; then
  deny "Blocked by guards publish-guard: no secret scanner could run (the guards-unified service is unreachable and the local scanner at $SECRET_SCAN is missing or failed), so ${LABEL} cannot be checked for credentials before it is published. Fail-closed: a publish cannot be un-done. Reinstall the plugin, or the user can set GUARDS_ALLOW_PUBLISH_SECRETS=1 to bypass."
fi

RULES="$(printf '%s' "$SS_RULES" | tr ' ' ',')"

# Sure things are blocked outright: a private key, a vendor token format
# gitleaks recognises, a value from this session's own environment. Matches
# that come from a key name or URL shape next to a value (they also fire on
# text that merely DOCUMENTS such things) go to the human instead. Setting
# GUARDS_PUBLISH_ASK=0 makes every match a hard block, as before.
AMBIGUOUS=" secret-lead-in url-password url-query-secret auth-header cookie-header cli-password-flag netrc-password pgpass-password k8s-env-value json-key-value azure-client-secret gcloud-oauth-token bcrypt-hash generic-api-key "
HARD=0
for r in $SS_RULES; do
  case "$AMBIGUOUS" in *" $r "*) ;; *) HARD=1 ;; esac
done
if [ -n "$RULES" ] && [ "$HARD" -eq 0 ] && [ "${GUARDS_PUBLISH_ASK:-1}" = "1" ]; then
  ask "guards publish-guard: ${LABEL} may contain a credential (detector rule(s): ${RULES}). Approve only if it shows a SHAPE or a documented example. If it contains a real value, deny it and rewrite the text to describe the shape only (length, character classes, which tool produced it); nothing real belongs in a public repo, issue, PR, comment or commit, not even a rotated one."
fi

if [ -n "$RULES" ]; then
  deny "Blocked by guards publish-guard: ${LABEL} would publish text that looks like it contains a credential (detector rule(s): ${RULES}). Do not include the value, not even a prefix, a partial, or a rotated/dead one. Describe the SHAPE only: length, character classes, which tool or command produced it. Put real material nowhere in a public repo, issue, PR, comment or commit. If this is a reviewed false positive, the user can set GUARDS_ALLOW_PUBLISH_SECRETS=1 in the environment Claude Code starts from; for deliberately fake fixtures in a commit, put 'guards:synthetic' on the same line."
fi

if [ "$SS_SOURCE" = "local" ] && grep -q 'gitleaks not found' "$WORK/ss.err" 2>/dev/null; then
  notice "publish-guard: gitleaks is not installed, so only the built-in private-key and context checks ran on ${LABEL}. Vendor-token formats were not checked."
fi
exit 0
