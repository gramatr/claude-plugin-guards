#!/usr/bin/env bash
# guards/hooks/credfile-guard.sh — PreToolUse hook on Read, Grep and Bash.
#
# DENIES reads of credential files BEFORE any content is produced. This
# is the control for "an agent printed a private key into the session":
# redaction after the fact (combined-hook.sh) is a backstop, not a
# guarantee — it only sees Bash output, it can miss keys in odd shapes
# (escaped newlines, truncated PEM), and
# it cannot see Read or Grep output at all.
#
# WHY PRE-TOOL DENY AND NOT POST-TOOL REWRITE FOR Read/Grep: Claude
# Code's docs say updatedToolOutput "must match the tool's output
# shape" and "a value that doesn't match the tool's output schema is
# ignored and the original output is used", and publish no schema for
# Read or Grep (only Bash). A rewrite hook there would look protected
# and silently leak. A PreToolUse deny needs no output schema, only the
# tool_input field names: Read.file_path, Grep.path / Grep.glob,
# Bash.command.
#
# WHAT IS DENIED
#   1. Known credential locations / names: ~/.ssh private keys (not
#      *.pub, known_hosts, config, authorized_keys), ~/.aws/credentials,
#      kubeconfigs, gcloud credential files, docker config.json, .netrc,
#      .pgpass, .git-credentials, .npmrc, .pypirc, .env and .env.* (but
#      not .env.example/.sample/.template/.dist), *.p12/*.pfx/*.jks/
#      *.keystore/*.kdbx, *.tfstate, service-account / client-secret
#      JSON files, id_rsa/id_dsa/id_ecdsa/id_ed25519.
#   2. ANY readable file, whatever its name, whose content contains a
#      PEM/OpenSSH private-key header. The sniff uses grep -q, so the
#      content is never printed.
#   For Bash, only commands that PRINT file content (cat, head, tail,
#   less, sed, awk, grep, base64, xxd, strings, python ... ) AND name a
#   sensitive path are denied. `ssh -i ~/.ssh/id_ed25519 host` or
#   `ssh-keygen -l -f key` use the key without printing it and are
#   allowed.
#
# KNOWN LIMITS (documented, not hidden)
#   - A Grep over a DIRECTORY is only checked by directory and glob name;
#     a broad pattern over a tree that contains a key file under an
#     unremarkable name is not caught here.
#   - A Bash command that reads a key indirectly (script that cats it,
#     env var holding a path, eval of a built string) is not caught.
#   - Fails OPEN if the payload is unparseable by jq: a broken hook must
#     not wedge every Read/Grep/Bash call. Redaction (combined-hook.sh)
#     remains the backstop for Bash.
#   - Without jq the guard still decides: a small awk parser reads the few
#     fields it needs. If even that cannot find the tool name it DENIES
#     (it cannot tell what the call is), with a reason that says what to fix.
#
# OVERRIDE: set GUARDS_ALLOW_CRED_READ=1 in the environment Claude Code
# was started from. Deliberate and visible; there is no per-call bypass.
#
# Deny output format per Claude Code's hooks docs:
#   {"hookSpecificOutput":{"hookEventName":"PreToolUse",
#     "permissionDecision":"deny","permissionDecisionReason":"..."}}
#
# Registered as its own PreToolUse entry whose matcher does NOT include
# SendMessage: sendmessage-guard.sh must stay the only PreToolUse hook
# on that tool (see its header). This hook never returns updatedInput.

set -uo pipefail

# Own deadline below the hook timeout in hooks.json: Claude Code fails open when
# a hook outlives it. Re-runs this script bounded; see deadline-lib.sh.
# shellcheck source=guards/hooks/deadline-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/deadline-lib.sh" && guards_deadline deny 6

[ "${GUARDS_ALLOW_CRED_READ:-0}" = "1" ] && exit 0

RAW="$(cat)"
# shellcheck source=guards/hooks/json-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/json-lib.sh"   # HAVE_JQ, jfield, emit_pre

TOOL_NAME="$(jfield tool_name)" || exit 0
CWD="$(jfield cwd)"
PERM_MODE="$(jfield permission_mode)"
[ -n "$CWD" ] || CWD="$PWD"

SNIFF_MAX_BYTES="${CREDFILE_SNIFF_MAX_BYTES:-10485760}"
PRIVATE_KEY_RE='-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----'

emit() { emit_pre "$@"; }

deny() {
  emit deny "$1"
  exit 0
}

# resolve_path, sensitive_reason, sensitive_dir_reason, is_ask_class. Without
# it nothing can be classified, so refuse rather than let the call through.
# shellcheck source=guards/hooks/credclass-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/credclass-lib.sh" 2>/dev/null || deny "Blocked by guards credfile-guard: its classification library credclass-lib.sh is missing or unreadable next to the hook ($(dirname "${BASH_SOURCE[0]}")/credclass-lib.sh), so this call cannot be checked and is denied. Reinstall or update the guards plugin."

# The payload could not be read at all and there is no jq to say why: the guard
# cannot tell what the call is, so it refuses rather than guess.
if [ "$HAVE_JQ" -eq 0 ] && [ -z "$TOOL_NAME" ]; then
  deny "Blocked by guards credfile-guard: jq is not installed and the hook payload could not be read without it, so this call cannot be checked. Install jq (apt install jq, brew install jq) and retry. If the user really wants the call to go through unchecked, they must start Claude Code with GUARDS_ALLOW_CRED_READ=1."
fi

# ask: hand the decision to the HUMAN via Claude Code's built-in permission
# prompt. Used for files that are credential-adjacent but routinely needed
# for ordinary debugging (.env, kubeconfig, .npmrc, terraform state). The
# agent cannot answer it, so it is not a bypass the agent can type for
# itself. But an ask only protects anything if a PERSON answers it: in auto,
# bypassPermissions and dontAsk modes (or any mode this hook does not
# recognise) Claude Code resolves it without one (verified live in auto mode,
# where the read went through). Same rule as publish-guard.sh: ask only in
# default, acceptEdits and plan; deny elsewhere. GUARDS_CRED_ASK set to "force" asks
# regardless of mode; set to 0 it denies in every mode.
ask() {
  emit ask "$1"
  exit 0
}

HUMAN=0
case "$PERM_MODE" in default|acceptEdits|plan) HUMAN=1 ;; esac
[ "${GUARDS_CRED_ASK:-1}" = "force" ] && HUMAN=1

ASK_MSG=""
block() {
  if { [ "${GUARDS_CRED_ASK:-1}" = "1" ] || [ "${GUARDS_CRED_ASK:-1}" = "force" ]; } && [ "$HUMAN" -eq 1 ] && is_ask_class "$1"; then
    # Remember it and keep checking: a later deny-class path must still win.
    [ -n "$ASK_MSG" ] || ASK_MSG="guards credfile-guard: this would put the contents of $2 ($1) into the session transcript, where the model can read it. Approve only if you need Claude to see it. To check a key exists or works without printing it, use e.g. test -f, ssh-keygen -l -f <key>, or ssh -i <key>."
    return 0
  fi
  local note=""
  if is_ask_class "$1" && [ "$HUMAN" -eq 0 ] && [ "${GUARDS_CRED_ASK:-1}" != "0" ]; then
    note=" [permission mode '${PERM_MODE:-unknown}' has no person to answer an approval prompt, so this is blocked instead of asked]"
  fi
  deny "Blocked by guards credfile-guard: this would print credential material ($1: $2) into the session transcript${note}. Do not read it. To check a key exists or works without printing it, use e.g. test -f, ssh-keygen -l -f <key>, or ssh -i <key>. If the user really wants it read, they must start Claude Code with GUARDS_ALLOW_CRED_READ=1."
}

check_path() {
  local raw="$1" p why
  [ -n "$raw" ] || return 0
  p="$(resolve_path "$raw")"
  [ -n "$p" ] || return 0
  if why="$(sensitive_reason "$p")"; then block "$why" "$raw"; fi
  if [ -d "$p" ] && why="$(sensitive_dir_reason "$p")"; then block "$why" "$raw"; fi
  return 0
}

case "$TOOL_NAME" in
  Read)
    check_path "$(jfield file_path)"
    ;;
  Grep)
    check_path "$(jfield path)"
    GLOB="$(jfield glob)"
    if [ -n "$GLOB" ]; then
      case "$(printf '%s' "$GLOB" | tr '[:upper:]' '[:lower:]')" in
        *.env*|*.pem|*.key|*.p12|*.pfx|*.jks|*.keystore|*id_rsa*|*id_ed25519*|*id_ecdsa*|*id_dsa*|*credentials*|*.netrc*|*.pgpass*|*.npmrc*|*.pypirc*|*.tfstate*|*.ssh*|*client_secret*|*service-account*)
          case "$(printf '%s' "$GLOB" | tr '[:upper:]' '[:lower:]')" in
            *.env.example*|*.env.sample*|*.env.template*) ;;
            *.pem*|*.key*|*.p12*|*.pfx*|*.jks*|*id_*|*credentials*|*.netrc*|*.pgpass*|*.npmrc*|*.pypirc*|*.tfstate*|*.ssh*|*client_secret*|*service-account*)
              block "glob targets credential files" "$GLOB" ;;
            *) block "glob targets .env files" "$GLOB" ;;
          esac ;;
      esac
    fi
    ;;
  Bash)
    CMD="$(jfield command)"
    [ -n "$CMD" ] || exit 0
    # Only commands that print file content are in scope.
    READERS='(^|[^A-Za-z0-9_./-])(cat|tac|nl|head|tail|less|more|bat|batcat|sed|awk|gawk|grep|egrep|fgrep|rg|ag|xxd|od|hexdump|strings|base64|cut|paste|diff|cmp|python3?|perl|ruby|node)([^A-Za-z0-9_-]|$)'
    printf '%s' "$CMD" | grep -qE -e "$READERS" || exit 0
    # Tokenise on whitespace and shell metacharacters, then check each
    # path-looking token (globs expanded, capped to keep this fast).
    n=0
    while IFS= read -r tok || [ -n "$tok" ]; do
      [ -n "$tok" ] || continue
      case "$tok" in -*) continue ;; esac
      n=$((n + 1)); [ "$n" -le 60 ] || break
      case "$tok" in
        *'*'*|*'?'*|*'['*)
          expanded="$(cd "$CWD" 2>/dev/null && compgen -G "$tok" | LC_ALL=C sort | head -n 20)"
          if [ -z "$expanded" ] && [ "${tok#\~}" != "$tok" ]; then
            expanded="$(compgen -G "${HOME}/${tok#\~/}" | LC_ALL=C sort | head -n 20)"
          fi
          while IFS= read -r e; do [ -n "$e" ] && check_path "$e"; done <<< "$expanded" ;;
        *) check_path "$tok" ;;
      esac
    done < <(printf '%s' "$CMD" | tr ';|&<>()"`'"'"'\t\n=' '          ' | tr ' ' '\n')
    ;;
esac

[ -n "$ASK_MSG" ] && ask "$ASK_MSG"

exit 0
