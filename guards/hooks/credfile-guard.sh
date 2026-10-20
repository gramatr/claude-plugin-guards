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
#   - Fails OPEN if jq is missing or the payload is unparseable: a
#     broken hook must not wedge every Read/Grep/Bash call. Redaction
#     (combined-hook.sh) remains the backstop for Bash.
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

[ "${GUARDS_ALLOW_CRED_READ:-0}" = "1" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

RAW="$(cat)"
TOOL_NAME="$(printf '%s' "$RAW" | jq -r '.tool_name // ""' 2>/dev/null)" || exit 0
CWD="$(printf '%s' "$RAW" | jq -r '.cwd // ""' 2>/dev/null)"
[ -n "$CWD" ] || CWD="$PWD"

SNIFF_MAX_BYTES="${CREDFILE_SNIFF_MAX_BYTES:-10485760}"
PRIVATE_KEY_RE='-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----'

deny() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

# ask: hand the decision to the HUMAN via Claude Code's built-in permission
# prompt. Used for files that are credential-adjacent but routinely needed
# for ordinary debugging (.env, kubeconfig, .npmrc, terraform state). The
# agent cannot answer it, so it is not a bypass the agent can type for
# itself; what Claude Code does with an ask when no human is attached (a
# non-interactive run) is not something this plugin controls or has verified;
# set GUARDS_CRED_ASK=0 to make those runs hard denies.
ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

# resolve PATH -> absolute, ~ and $HOME expanded, symlinks followed if
# the target exists. Prints nothing for an empty argument.
resolve_path() {
  local p="$1"
  [ -n "$p" ] || return 0
  case "$p" in
    \~) p="$HOME" ;;
    \~/*) p="$HOME/${p#\~/}" ;;
    '$HOME'|'${HOME}') p="$HOME" ;;
    '$HOME/'*) p="$HOME/${p#'$HOME/'}" ;;
    '${HOME}/'*) p="$HOME/${p#'${HOME}/'}" ;;
  esac
  case "$p" in
    /*) ;;
    *) p="$CWD/$p" ;;
  esac
  realpath -m -- "$p" 2>/dev/null || printf '%s' "$p"
}

# sensitive_reason PATH -> prints a short reason and returns 0 if PATH
# is credential material, else returns 1. PATH must already be resolved.
sensitive_reason() {
  local p="$1" base lower
  base="${p##*/}"
  lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"

  case "$p" in
    */.ssh/*)
      case "$lower" in
        *.pub|known_hosts|known_hosts.old|config|authorized_keys|authorized_keys2) ;;
        *) printf 'SSH key material under ~/.ssh'; return 0 ;;
      esac ;;
    */.aws/credentials) printf 'AWS credentials file'; return 0 ;;
    */.kube/config|*/.kube/*.kubeconfig) printf 'kubeconfig'; return 0 ;;
    */.config/gcloud/*credentials*|*/.config/gcloud/*.json) printf 'gcloud credentials'; return 0 ;;
    */.docker/config.json) printf 'docker registry auth'; return 0 ;;
    */.gnupg/private-keys-v1.d/*|*/.gnupg/secring.*) printf 'GPG private keyring'; return 0 ;;
  esac

  case "$lower" in
    .netrc|_netrc) printf '.netrc credentials'; return 0 ;;
    .pgpass) printf '.pgpass credentials'; return 0 ;;
    .git-credentials) printf 'git credential store'; return 0 ;;
    .npmrc|.pypirc) printf 'package-registry token file'; return 0 ;;
    kubeconfig|*.kubeconfig) printf 'kubeconfig'; return 0 ;;
    .env.example|.env.sample|.env.template|.env.dist|*.env.example|*.env.sample|*.env.template) ;;
    .env|.env.*|*.env) printf 'environment file (.env)'; return 0 ;;
    id_rsa|id_dsa|id_ecdsa|id_ed25519) printf 'SSH private key'; return 0 ;;
    *.p12|*.pfx|*.jks|*.keystore|*.kdbx) printf 'keystore / password database'; return 0 ;;
    *.tfstate|*.tfstate.backup) printf 'terraform state (contains secrets)'; return 0 ;;
    *service-account*.json|*serviceaccount*.json|*credentials*.json|*client_secret*.json)
      printf 'service-account / client-secret JSON'; return 0 ;;
  esac

  # Content sniff, any name. grep -q: nothing is printed.
  if [ -f "$p" ] && [ -r "$p" ]; then
    if head -c "$SNIFF_MAX_BYTES" -- "$p" 2>/dev/null | grep -qaE -e "$PRIVATE_KEY_RE"; then
      printf 'file contains a private key'; return 0
    fi
  fi
  return 1
}

# sensitive_dir_reason DIR -> for Grep/Bash over a whole credential dir.
sensitive_dir_reason() {
  case "$1/" in
    */.ssh/|*/.aws/|*/.kube/|*/.gnupg/|*/.config/gcloud/|*/.docker/)
      printf 'credential directory'; return 0 ;;
  esac
  return 1
}

# Private keys and credential stores are never worth reading: DENY. Config
# files that merely CONTAIN credentials (a .env you are debugging) are ASK.
# GUARDS_CRED_ASK=0 makes everything a hard deny, as before.
ASK_MSG=""
is_ask_class() {
  case "$1" in
    "environment file (.env)"|"kubeconfig"|"package-registry token file"|"terraform state (contains secrets)"|"glob targets .env files") return 0 ;;
  esac
  return 1
}

block() {
  if [ "${GUARDS_CRED_ASK:-1}" = "1" ] && is_ask_class "$1"; then
    # Remember it and keep checking: a later deny-class path must still win.
    [ -n "$ASK_MSG" ] || ASK_MSG="guards credfile-guard: this would put the contents of $2 ($1) into the session transcript, where the model can read it. Approve only if you need Claude to see it. To check a key exists or works without printing it, use e.g. test -f, ssh-keygen -l -f <key>, or ssh -i <key>."
    return 0
  fi
  deny "Blocked by guards credfile-guard: this would print credential material ($1: $2) into the session transcript. Do not read it. To check a key exists or works without printing it, use e.g. test -f, ssh-keygen -l -f <key>, or ssh -i <key>. If the user really wants it read, they must start Claude Code with GUARDS_ALLOW_CRED_READ=1."
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
    check_path "$(printf '%s' "$RAW" | jq -r '.tool_input.file_path // ""' 2>/dev/null)"
    ;;
  Grep)
    check_path "$(printf '%s' "$RAW" | jq -r '.tool_input.path // ""' 2>/dev/null)"
    GLOB="$(printf '%s' "$RAW" | jq -r '.tool_input.glob // ""' 2>/dev/null)"
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
    CMD="$(printf '%s' "$RAW" | jq -r '.tool_input.command // ""' 2>/dev/null)"
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
          expanded="$(cd "$CWD" 2>/dev/null && compgen -G "$tok" | head -n 20)"
          if [ -z "$expanded" ] && [ "${tok#\~}" != "$tok" ]; then
            expanded="$(compgen -G "${HOME}/${tok#\~/}" | head -n 20)"
          fi
          while IFS= read -r e; do [ -n "$e" ] && check_path "$e"; done <<< "$expanded" ;;
        *) check_path "$tok" ;;
      esac
    done < <(printf '%s' "$CMD" | tr ';|&<>()"`'"'"'\t\n=' '          ' | tr ' ' '\n')
    ;;
esac

[ -n "$ASK_MSG" ] && ask "$ASK_MSG"

exit 0
