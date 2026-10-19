#!/usr/bin/env bash
# guards/tests/mcp-output-guard.test.sh — tests for hooks/mcp-output-guard.sh.
# All credential-shaped values are fabricated. Needs bash, jq.

set -uo pipefail
# Hermetic: never talk to a real guards-unified service from a test.
export GUARDS_ENDPOINT="http://127.0.0.1:1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HERE/../hooks/mcp-output-guard.sh"
PW="Tq7vN2xLm9Kd4RzP8wYb"
pass=0 fail=0

hook() { # hook TOOL RESPONSE_JSON [ENV...] -> raw hook stdout
  jq -n --arg t "$1" --argjson r "$2" '{tool_name:$t, tool_input:{}, tool_response:$r}' | env "${@:3}" bash "$HOOK"
}
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

# 1. array of content blocks with a secret -> same shape, secret gone
out="$(hook mcp__x__get '[{"type":"text","text":"DB_PASSWORD='"$PW"'"}]')"
new="$(printf '%s' "$out" | jq -c '.hookSpecificOutput.updatedToolOutput' 2>/dev/null)"
if [ "$(printf '%s' "$new" | jq -r 'type')" = "array" ] && [ "$(printf '%s' "$new" | jq -r '.[0].type')" = "text" ] \
   && [[ "$new" != *"$PW"* ]] && [[ "$new" == *REDACTED* ]]; then ok; else bad "array of text blocks redacted, shape kept ($new)"; fi

# 2. {content:[...]} object keeps its other fields
out="$(hook mcp__x__get '{"content":[{"type":"text","text":"token: '"$PW"'"}],"isError":false}')"
new="$(printf '%s' "$out" | jq -c '.hookSpecificOutput.updatedToolOutput' 2>/dev/null)"
if [ "$(printf '%s' "$new" | jq -r '.isError')" = "false" ] && [[ "$new" != *"$PW"* ]]; then ok; else bad "object form keeps fields ($new)"; fi

# 3. bare string
out="$(hook mcp__x__get '"password: '"$PW"'"')"
new="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.updatedToolOutput' 2>/dev/null)"
if [ -n "$new" ] && [[ "$new" != *"$PW"* ]]; then ok; else bad "string form redacted"; fi

# 4. only the secret block changes; a clean block is left byte-identical
out="$(hook mcp__x__get '[{"type":"text","text":"hello"},{"type":"text","text":"secret_key='"$PW"'"}]')"
if [ "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.updatedToolOutput[0].text')" = "hello" ] \
   && [[ "$(printf '%s' "$out" | jq -c '.hookSpecificOutput.updatedToolOutput')" != *"$PW"* ]]; then ok; else bad "clean block untouched"; fi

# 5. nothing to redact -> no output at all
[ -z "$(hook mcp__x__get '[{"type":"text","text":"all good here"}]')" ] && ok || bad "clean result produces no output"

# 6. unknown shapes pass through untouched (never guess)
[ -z "$(hook mcp__x__get '{"weird":{"text":"password='"$PW"'"}}')" ] && ok || bad "unknown object shape untouched"
[ -z "$(hook mcp__x__get '[{"type":"image","data":"password='"$PW"'"}]')" ] && ok || bad "non-text block untouched"
[ -z "$(hook mcp__x__get '42')" ] && ok || bad "number untouched"

# 7. non-MCP tool ignored; grāmatr's own server skipped by default
[ -z "$(hook Bash '[{"type":"text","text":"password='"$PW"'"}]')" ] && ok || bad "non-MCP tool ignored"
[ -z "$(hook mcp__plugin_gramatr_gramatr__session_bootstrap '[{"type":"text","text":"rest_token='"$PW"'"}]')" ] && ok || bad "gramatr server skipped by default"
out="$(hook mcp__plugin_gramatr_gramatr__x '[{"type":"text","text":"password='"$PW"'"}]' GUARDS_MCP_SKIP='^nothing$')"
[ -n "$out" ] && ok || bad "GUARDS_MCP_SKIP override applies"

# 8. disabled; fails open when the scanner is missing
[ -z "$(hook mcp__x__get '[{"type":"text","text":"password='"$PW"'"}]' GUARDS_MCP_SCAN=0)" ] && ok || bad "GUARDS_MCP_SCAN=0 disables"
[ -z "$(hook mcp__x__get '[{"type":"text","text":"password='"$PW"'"}]' GUARDS_SECRET_SCAN=/nonexistent.sh)" ] && ok || bad "missing scanner fails open"

echo "mcp-output-guard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
