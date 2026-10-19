#!/usr/bin/env bash
# guards/hooks/mcp-output-guard.sh — PostToolUse hook on MCP tools:
# redacts secrets in an MCP tool's RESULT before the model sees it.
#
# combined-hook.sh only handles Bash. Read/Grep results cannot be rewritten
# (no documented output schema, a wrong shape is silently ignored), so those
# are covered by credfile-guard.sh denying the read up front. MCP is the
# third path: Claude Code's docs say an MCP tool's replacement output is
# passed through WITHOUT schema validation, so what this hook returns IS the
# result. That cuts both ways, so it is deliberately conservative:
#
#   * Only recognised shapes are rewritten, and the same shape is returned:
#       - an array of content blocks   [{"type":"text","text":"..."}]
#         (the shape of a real MCP result in the session transcript)
#       - an object with such an array {"content":[...], ...}
#       - a bare string
#     Anything else (images, resources, an unknown wrapper) passes through
#     untouched. A wrong guess therefore cannot corrupt a result; at worst
#     the result is left unredacted, which is the status quo.
#   * Only `text` fields of text blocks are scanned and replaced.
#   * Secrets only, via the vendored scan.sh run locally (no network, fast).
#     PII / injection stay with combined-hook's service path for Bash;
#     adding a per-MCP-call service round trip would slow every tool call.
#   * Fails OPEN on any error (jq missing, scanner failing): a broken hook
#     must not break MCP tools.
#
# GUARDS_MCP_SKIP (extended regex on the tool name) excludes tools whose
# results legitimately contain credentials the session needs. Default skips
# grāmatr's own server, which returns session tokens by design.
# GUARDS_MCP_SCAN=0 disables the hook.
#
# NOTE: the payload shape is taken from the transcript, not from a
# documented hook example. Verify live after enabling: call any MCP tool
# whose result you can safely seed with a fabricated secret.

set -uo pipefail

[ "${GUARDS_MCP_SCAN:-1}" = "0" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_SCAN="${GUARDS_SECRET_SCAN:-$(dirname "$SCRIPT_DIR")/vendor/secret-guard-core/scan.sh}"
SKIP_RE="${GUARDS_MCP_SKIP:-^mcp__plugin_gramatr_}"
MAX_BYTES="${MCP_GUARD_MAX_BYTES:-524288}"

RAW="$(cat)"
TOOL_NAME="$(printf '%s' "$RAW" | jq -r '.tool_name // ""' 2>/dev/null)" || exit 0
case "$TOOL_NAME" in mcp__*) ;; *) exit 0 ;; esac
[[ "$TOOL_NAME" =~ $SKIP_RE ]] && exit 0
[ -f "$SECRET_SCAN" ] || exit 0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# scan_file FILE -> writes FILE.out; returns 0 only if secrets were found and
# the text changed. Secrets only, fast: the warm service's secret-only route
# plus the local-environment passes, falling back to the full local scan.sh
# (see secret-scan-lib.sh). Any failure means "leave this block alone".
SS_WORK="$WORK"
# shellcheck source=guards/hooks/secret-scan-lib.sh
. "$SCRIPT_DIR/secret-scan-lib.sh"
scan_file() {
  local in="$1"
  [ "$(wc -c < "$in")" -le "$MAX_BYTES" ] || return 1
  secret_scan "$in" || return 1
  [ -n "$SS_RULES" ] && [ "$SS_CHANGED" -eq 1 ] || return 1
  cp "$SS_OUT" "$in.out"
  RULES="$RULES $SS_RULES"
  return 0
}

RESP="$WORK/resp.json"
printf '%s' "$RAW" | jq -c '.tool_response' > "$RESP" 2>/dev/null || exit 0
KIND="$(jq -r 'if type=="array" then "array" elif type=="string" then "string" elif (type=="object" and (.content|type)=="array") then "object" else "other" end' "$RESP" 2>/dev/null)"

RULES=""
CHANGED=0
NEW="$WORK/new.json"

case "$KIND" in
  string)
    jq -j '.' "$RESP" > "$WORK/s.txt"
    if scan_file "$WORK/s.txt"; then
      jq -Rs '.' < "$WORK/s.txt.out" > "$NEW"; CHANGED=1
    fi
    ;;
  array|object)
    cp "$RESP" "$NEW"
    if [ "$KIND" = "array" ]; then BASE='.'; else BASE='.content'; fi
    N="$(jq "$BASE | length" "$RESP" 2>/dev/null)"
    i=0
    while [ "$i" -lt "${N:-0}" ]; do
      if [ "$(jq -r "${BASE}[$i] | if type==\"object\" and .type==\"text\" and (.text|type)==\"string\" then \"y\" else \"n\" end" "$RESP")" = "y" ]; then
        jq -j "${BASE}[$i].text" "$RESP" > "$WORK/b$i.txt"
        if [ -s "$WORK/b$i.txt" ] && scan_file "$WORK/b$i.txt"; then
          jq --rawfile t "$WORK/b$i.txt.out" "${BASE}[$i].text = \$t" "$NEW" > "$NEW.tmp" && mv "$NEW.tmp" "$NEW"
          CHANGED=1
        fi
      fi
      i=$((i + 1))
    done
    ;;
  *) exit 0 ;;
esac

[ "$CHANGED" -eq 1 ] || exit 0

RULE_LIST="$(printf '%s' "$RULES" | tr ' ' '\n' | sort -u | grep -v '^$' | paste -sd, -)"
jq -n --slurpfile out "$NEW" --arg note "guards mcp-output-guard: redacted credential material in the result of ${TOOL_NAME} (detector rule(s): ${RULE_LIST:-unknown}). Treat the redaction markers as intentional." \
  '{hookSpecificOutput: {hookEventName: "PostToolUse", updatedToolOutput: $out[0], additionalContext: $note}}'
