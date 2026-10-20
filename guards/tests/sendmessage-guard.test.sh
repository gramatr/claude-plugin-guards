#!/usr/bin/env bash
# guards/tests/sendmessage-guard.test.sh — the SendMessage PreToolUse hook
# (hooks/sendmessage-guard.sh).
#
# Pins what the hook is documented to do: redact secrets in each of
# message/summary/content independently, flag (not redact) PII by default,
# cap summary at 200 chars, disclose a scan cut by SCAN_MAX_BYTES, and degrade
# to a local secret-only scan when the service is down. A stub service stands
# in for guards-unified and a stub scan.sh for the gitleaks fallback. All
# values are fabricated. Needs: bash, jq, python3.
#
# HOOK_SRC=/path/to/other/sendmessage-guard.sh runs the same cases against a
# different copy of the hook (used for the negative controls in the PR).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_SRC="${HOOK_SRC:-$HERE/../hooks/sendmessage-guard.sh}"
T="$(mktemp -d)"
PID=""
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"

# The hook finds scan.sh relative to itself, so run a copy in a throwaway tree
# whose scan.sh is a stub that redacts the same fabricated marker.
mkdir -p "$T/p/guards/hooks" "$T/p/guards/vendor/secret-guard-core" "$T/svc"
cp "$HOOK_SRC" "$T/p/guards/hooks/sendmessage-guard.sh"
HOOK="$T/p/guards/hooks/sendmessage-guard.sh"
SCAN="$T/p/guards/vendor/secret-guard-core/scan.sh"
cat > "$SCAN" <<'SH'
#!/usr/bin/env bash
sed 's/LOCALSECRET456/***REDACTED:SECRET***/g'
SH
chmod +x "$SCAN"

python3 -I "$HERE/stub-service.py" "$T/svc" >/dev/null 2>&1 &
PID=$!
for _ in $(seq 1 50); do [ -s "$T/svc/port" ] && break; sleep 0.1; done
UP="http://127.0.0.1:$(cat "$T/svc/port")"
DOWN="http://127.0.0.1:1"

pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

hook() { # hook ENDPOINT INPUT_JSON [ENV...] -> raw hook stdout
  jq -nc --argjson i "$2" '{tool_name:"SendMessage", tool_input:$i}' \
    | env "GUARDS_ENDPOINT=$1" "${@:3}" bash "$HOOK"
}
jqo() { printf '%s' "$1" | jq -r "$2" 2>/dev/null; }
sent() { wc -l < "$T/svc/requests" 2>/dev/null || echo 0; }

SEC="STUBSECRET123"
R="***REDACTED:SECRET***"

# 1. clean message: no output, input untouched
out="$(hook "$UP" '{"to":"a","message":"all good","summary":"fine"}')"
[ -z "$out" ] && ok || bad "clean input produces no rewrite (got: $out)"

# 2. other tools and empty payloads are ignored
out="$(jq -nc '{tool_name:"Bash",tool_input:{command:"x"}}' | GUARDS_ENDPOINT="$UP" bash "$HOOK")"
[ -z "$out" ] && ok || bad "a non-SendMessage call is ignored"
out="$(hook "$UP" '{"to":"a","message":"","summary":"","content":""}')"
[ -z "$out" ] && ok || bad "all-empty fields produce no output"

# 3. secret in message: allowed with the redacted input and a disclosure
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"key $SEC end\"}")"
[ "$(jqo "$out" '.hookSpecificOutput.permissionDecision')" = allow ] && ok || bad "secret: decision is allow (never deny)"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "key $R end" ] && ok || bad "secret in message is redacted"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.to')" = a ] && ok || bad "other input fields are preserved"
jqo "$out" '.hookSpecificOutput.additionalContext' | grep -q "secret was found and redacted" && ok || bad "secret: context discloses the redaction"
case "$out" in *"$SEC"*) bad "the original secret value must not appear anywhere in the output" ;; *) ok ;; esac

# 4. each field is scanned from its own content, independently
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"clean body\",\"summary\":\"s $SEC\",\"content\":\"c $SEC\"}")"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "clean body" ] && ok || bad "a clean message is not overwritten by another field's result"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.summary')" = "s $R" ] && ok || bad "secret in summary alone is redacted"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.content')" = "c $R" ] && ok || bad "secret in content alone is redacted"
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"\",\"summary\":\"s\",\"content\":\"c $SEC\"}")"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.content')" = "c $R" ] && ok || bad "empty message must not stop content from being scanned"
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"m $SEC\",\"summary\":\"short label\",\"content\":\"c\"}")"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.summary')" = "short label" ] && ok || bad "an independent summary is not replaced by the message's text"

# 5. summary is capped at 200 characters on the redaction path
long="$(printf 'x%.0s' $(seq 1 300))"
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"m $SEC\",\"summary\":\"$long $SEC\"}")"
n="$(jqo "$out" '.hookSpecificOutput.updatedInput.summary | length')"
[ "$n" = 200 ] && ok || bad "summary is truncated to 200 chars (got $n)"

# 6. PII: flagged by default, values intact; redacted only with PII_GUARD_MODE=redact
out="$(hook "$UP" '{"to":"a","message":"ask STUBPII about it"}')"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "ask STUBPII about it" ] && ok || bad "PII flag mode leaves the message intact"
jqo "$out" '.hookSpecificOutput.additionalContext' | grep -q "PERSON" && ok || bad "PII flag mode names the entity type"
out="$(hook "$UP" '{"to":"a","message":"ask STUBPII about it"}' PII_GUARD_MODE=redact)"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "ask <PERSON> about it" ] && ok || bad "PII_GUARD_MODE=redact replaces the value"

# 7. size cap: only the first SCAN_MAX_BYTES of a field are sent; the rest is
# reattached untouched and the cut is disclosed.
: > "$T/svc/requests"
body="$(printf 'a%.0s' $(seq 1 60))"
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"$body $SEC tail-marker\"}" SCAN_MAX_BYTES=40)"
sz="$(awk '{print $2}' "$T/svc/requests" | head -1)"
[ "$sz" = 40 ] && ok || bad "only SCAN_MAX_BYTES bytes are sent to the scanner (sent $sz)"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "$body $SEC tail-marker" ] && ok || bad "the unscanned remainder is reattached unchanged"
jqo "$out" '.hookSpecificOutput.additionalContext' | grep -q "40-byte scan limit" && ok || bad "a truncated scan is disclosed"
: > "$T/svc/requests"
out="$(hook "$UP" "{\"to\":\"a\",\"message\":\"$body\"}" SCAN_MAX_BYTES=40)"
[ "$(jqo "$out" '.hookSpecificOutput.permissionDecision')" = allow ] && ok || bad "a clean but truncated field still produces the disclosure"

# 8. service down: degrade to the local secret-only scan, still allow, say so
out="$(hook "$DOWN" '{"to":"a","message":"m LOCALSECRET456","summary":"s","content":"c LOCALSECRET456"}')"
[ "$(jqo "$out" '.hookSpecificOutput.permissionDecision')" = allow ] && ok || bad "service down: still allow (not a blanket deny)"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "m $R" ] && ok || bad "service down: message redacted by the local scan"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.content')" = "c $R" ] && ok || bad "service down: content redacted by the local scan"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.summary')" = "s" ] && ok || bad "service down: a clean summary is unchanged"
jqo "$out" '.hookSpecificOutput.additionalContext' | grep -q "PII scanning could not run" && ok || bad "service down: PII coverage is disclosed as unavailable"
out="$(hook "$DOWN" '{"to":"a","message":"nothing here"}')"
[ "$(jqo "$out" '.hookSpecificOutput.permissionDecision')" = allow ] && ok || bad "service down + clean text still returns allow with the note"
out="$(hook "$DOWN" '{"to":"a","message":"clean","content":"c LOCALSECRET456"}')"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.content')" = "c $R" ] && ok || bad "service down: a secret only in content is redacted"

# 9. service down AND no usable scanner: fields pass through unchanged (open),
# the hook still answers allow and does not crash
chmod -x "$SCAN"
out="$(hook "$DOWN" '{"to":"a","message":"m LOCALSECRET456"}')"
[ "$(jqo "$out" '.hookSpecificOutput.permissionDecision')" = allow ] && ok || bad "no scanner: still answers allow"
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "m LOCALSECRET456" ] && ok || bad "no scanner: text passes unchanged (documented open)"
chmod +x "$SCAN"

# 10. a malformed 200 from the service counts as down, not as clean
cat > "$T/bad.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        b = b'{"detail":"oops"}'
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
s = HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()
PY
python3 -I "$T/bad.py" "$T/bad.port" >/dev/null 2>&1 &
BADPID=$!
for _ in $(seq 1 50); do [ -s "$T/bad.port" ] && break; sleep 0.1; done
out="$(hook "http://127.0.0.1:$(cat "$T/bad.port")" '{"to":"a","message":"m LOCALSECRET456"}')"
kill "$BADPID" 2>/dev/null
[ "$(jqo "$out" '.hookSpecificOutput.updatedInput.message')" = "m $R" ] && ok || bad "a 200 without findings falls back to the local scan"

echo "sendmessage-guard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
