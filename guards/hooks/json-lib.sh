#!/usr/bin/env bash
# guards/hooks/json-lib.sh -- sourced by the hooks; not run directly.
#
# WHY: every hook used to need `jq` just to read its payload and, when jq was
# missing, quietly passed everything through. This file is the shared way to
# read the payload and answer without jq, and to say so out loud when a hook
# genuinely cannot do its job without it.
#
# Needs from the caller: RAW (the hook payload text) before jfield is used.
# Sets: HAVE_JQ (1/0).

HAVE_JQ=1
command -v jq >/dev/null 2>&1 || HAVE_JQ=0

# jfield NAME -> the string value of NAME from the hook payload: tool_name, cwd
# and permission_mode are top-level, everything else is under tool_input. With
# jq that is a one-liner. Without it, awk walks the JSON string tokens (so an
# escaped quote inside a command cannot end a value early and a key name that
# only appears inside another string is never mistaken for a key) and decodes
# the usual escapes; a \uXXXX escape becomes '?', which cannot matter for the
# ASCII file names this guard looks at.
jfield() {
  if [ "$HAVE_JQ" -eq 1 ]; then
    case "$1" in
      tool_name|cwd|permission_mode) printf '%s' "$RAW" | jq -r ".$1 // \"\"" 2>/dev/null ;;
      *) printf '%s' "$RAW" | jq -r ".tool_input.$1 // \"\"" 2>/dev/null ;;
    esac
    return
  fi
  printf '%s' "$RAW" | awk -v key="$1" '
    BEGIN { RS = "\001" }
    {
      s = $0; n = length(s); i = 1; want = 0
      while (i <= n) {
        c = substr(s, i, 1)
        if (c != "\"") {
          if (want && c !~ /[ \t\r\n:]/) want = 0
          i++; continue
        }
        val = ""; j = i + 1
        while (j <= n) {
          d = substr(s, j, 1)
          if (d == "\\") {
            e = substr(s, j + 1, 1)
            if (e == "n") val = val "\n"
            else if (e == "t") val = val "\t"
            else if (e == "r") val = val "\r"
            else if (e == "b" || e == "f") val = val " "
            else if (e == "u") { val = val "?"; j += 4 }
            else val = val e
            j += 2; continue
          }
          if (d == "\"") break
          val = val d; j++
        }
        if (want) { printf "%s", val; exit }
        k = j + 1
        while (substr(s, k, 1) ~ /[ \t\r\n]/) k++
        if (substr(s, k, 1) == ":" && val == key) want = 1
        i = j + 1
      }
    }'
}

# json_escape -- stdin to a JSON string body (no surrounding quotes).
json_escape() {
  awk 'BEGIN { ORS = "" } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r"); print sep $0; sep = "\\n" }'
}

# emit_pre KIND REASON -> a PreToolUse decision (deny|ask) as JSON, with or
# without jq.
emit_pre() {
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -n --arg kind "$1" --arg reason "$2" \
      '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: $kind, permissionDecisionReason: $reason}}'
  else
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' \
      "$1" "$(printf '%s' "$2" | json_escape)"
  fi
}

# emit_context EVENT TEXT -> a note for the model (no decision), PreToolUse or PostToolUse.
emit_context() {
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -n --arg ev "$1" --arg ctx "$2" '{hookSpecificOutput: {hookEventName: $ev, additionalContext: $ctx}}'
  else
    printf '{"hookSpecificOutput":{"hookEventName":"%s","additionalContext":"%s"}}\n' "$1" "$(printf '%s' "$2" | json_escape)"
  fi
}

NOJQ_INSTALL="Install jq (apt install jq, brew install jq) and retry."

# nojq_scan SCAN_SH -> exit status 0 clean, 1 text changed (a secret was found),
# 2 the scan could not run or ran out of time. Scans the whole payload with the
# built-in passes only (private key, key-name context, session environment
# values); vendor token formats need gitleaks, which scan.sh runs only with jq.
nojq_scan() {
  local scan="$1" in out rc
  [ -f "$scan" ] || return 2
  in="$(mktemp)" || return 2; out="$(mktemp)" || { rm -f "$in"; return 2; }
  printf '%s' "$RAW" > "$in"
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 1 "${NOJQ_SCAN_TIMEOUT:-6}" bash "$scan" < "$in" > "$out" 2>/dev/null; rc=$?
  else
    bash "$scan" < "$in" > "$out" 2>/dev/null; rc=$?
  fi
  if [ "$rc" -ne 0 ]; then rm -f "$in" "$out"; return 2; fi
  # scan.sh reads with $(...), so compare without trailing newlines.
  if [ "$(cat "$in")" = "$(cat "$out")" ]; then rc=0; else rc=1; fi
  rm -f "$in" "$out"
  return "$rc"
}

# nojq_post_guard NAME KIND SCAN_SH -- PostToolUse hooks (KIND bash|mcp) without
# jq. A result that cannot be redacted without jq is WITHHELD with a reason that
# says to install it; a result the built-in passes find clean is passed through
# with a note that the check was partial. Always exits.
nojq_post_guard() {
  local name="$1" kind="$2" scan="$3" rc msg
  nojq_scan "$scan"; rc=$?
  if [ "$rc" -eq 0 ]; then
    emit_context PostToolUse "guards ${name}: jq is not installed, so only the built-in checks (private keys, key-name context, values from this session's environment) ran on this result; vendor token formats, PII and injection were not checked. ${NOJQ_INSTALL}"
    exit 0
  fi
  if [ "$rc" -eq 1 ]; then
    msg="guards ${name}: this result was withheld because it contains credential material and jq is not installed, so it cannot be redacted. ${NOJQ_INSTALL}"
  else
    msg="guards ${name}: this result was withheld because jq is not installed and the built-in scan could not finish, so it could not be checked for secrets. ${NOJQ_INSTALL}"
  fi
  msg="$(printf '%s' "$msg" | json_escape)"
  if [ "$kind" = "bash" ]; then
    printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"stdout":"%s","stderr":"","interrupted":false,"isImage":false}}}\n' "$msg"
  else
    printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":[{"type":"text","text":"%s"}]}}\n' "$msg"
  fi
  exit 0
}

# nojq_pre_guard NAME SCAN_SH -- a PreToolUse hook that rewrites input (SendMessage)
# without jq: it cannot rewrite, so a payload with credential material is denied
# and a clean one is allowed with a note. Always exits.
nojq_pre_guard() {
  local name="$1" scan="$2" rc
  nojq_scan "$scan"; rc=$?
  case "$rc" in
    0) emit_context PreToolUse "guards ${name}: jq is not installed, so only the built-in checks (private keys, key-name context, values from this session's environment) ran on this message; vendor token formats and PII were not checked. ${NOJQ_INSTALL}" ;;
    1) emit_pre deny "Blocked by guards ${name}: this message contains credential material and jq is not installed, so it cannot be redacted. Remove the value (describe its shape) or ${NOJQ_INSTALL}" ;;
    *) emit_pre deny "Blocked by guards ${name}: jq is not installed and the built-in scan could not finish, so this message cannot be checked for credentials. ${NOJQ_INSTALL}" ;;
  esac
  exit 0
}
