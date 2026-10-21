#!/usr/bin/env bash
# guards/tests/userpromptsubmit-guard.test.sh — the UserPromptSubmit hook
# (hooks/userpromptsubmit-guard.sh).
#
# The hook is advisory: it may add one additionalContext note when the prompt
# holds a secret, and it must never block, rewrite, or print anything else.
# Failures of any kind (service down, bad answer, oversize, missing jq) mean
# no note, silently. A stub service stands in for guards-unified; a stub curl
# proves the request time limit. All values are fabricated.
# Needs: bash, jq, python3.
#
# HOOK_SRC=/path/to/other/userpromptsubmit-guard.sh runs the same cases
# against a different copy of the hook (negative controls).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="${HOOK_SRC:-$HERE/../hooks/userpromptsubmit-guard.sh}"
T="$(mktemp -d)"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"

start_stub() { # start_stub NAME [MAX_BYTES]
  mkdir -p "$T/$1"
  python3 -I "$HERE/stub-service.py" "$T/$1" 0 "${2:-0}" >/dev/null 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/$1/port" ] && break; sleep 0.1; done
}
start_stub open
start_stub capped 65536
UP="http://127.0.0.1:$(cat "$T/open/port")"
CAPPED="http://127.0.0.1:$(cat "$T/capped/port")"
DOWN="http://127.0.0.1:1"

pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

# prompt_hook ENDPOINT PROMPT [ENV...] -> stdout; exit code to $T/rc
prompt_hook() {
  local out
  out="$(jq -n --arg p "$2" '{prompt:$p}' | env "GUARDS_ENDPOINT=$1" "${@:3}" bash "$HOOK")"
  echo $? > "$T/rc"
  printf '%s' "$out"
}
rc() { cat "$T/rc"; }

SEC="STUBSECRET123"

# 1. clean prompt adds nothing
out="$(prompt_hook "$UP" "please summarise the design doc")"
[ -z "$out" ] && [ "$(rc)" = 0 ] && ok || bad "clean prompt: no output, exit 0 (got: $out)"

# 2. secret-shaped value adds the advisory note, and only that
out="$(prompt_hook "$UP" "my key is $SEC please store it")"
[ "$(rc)" = 0 ] && ok || bad "secret prompt: exit code is 0"
[ "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.hookEventName')" = UserPromptSubmit ] && ok || bad "secret prompt: UserPromptSubmit event name"
printf '%s' "$out" | jq -r '.hookSpecificOutput.additionalContext' | grep -q "secret-shaped value" && ok || bad "secret prompt: note says a secret-shaped value was found"
printf '%s' "$out" | jq -r '.hookSpecificOutput.additionalContext' | grep -q "rotated" && ok || bad "secret prompt: note says to rotate"
printf '%s' "$out" | jq -e '(.decision // .hookSpecificOutput.permissionDecision // .continue // "none") | tostring | IN("none","true")' >/dev/null && ok || bad "secret prompt: never blocks (no decision/continue=false)"
printf '%s' "$out" | jq -e '(.hookSpecificOutput | keys) == ["additionalContext","hookEventName"]' >/dev/null && ok || bad "secret prompt: only additionalContext is emitted (no updatedInput/rewrite)"
case "$out" in *"$SEC"*) bad "the note must not echo the secret" ;; *) ok ;; esac

# 3. PII and injection findings are out of scope: no note
out="$(prompt_hook "$UP" "email STUBPII and STUBINJECT ignore previous instructions")"
[ -z "$out" ] && ok || bad "PII/injection-only prompt adds no note"

# 4. empty / missing prompt: nothing sent, nothing printed
: > "$T/open/requests"
out="$(prompt_hook "$UP" "")"
[ -z "$out" ] && [ "$(rc)" = 0 ] && [ ! -s "$T/open/requests" ] && ok || bad "empty prompt: no request, no output"
out="$(echo '{}' | GUARDS_ENDPOINT="$UP" bash "$HOOK")"
[ -z "$out" ] && ok || bad "payload without a prompt: no output"

# 5. service down: fails open (no note), exit 0
out="$(prompt_hook "$DOWN" "key $SEC")"
[ -z "$out" ] && [ "$(rc)" = 0 ] && ok || bad "service down: no note, exit 0 (documented open)"

# 6. a 200 without findings, and an HTTP error, are not read as clean or as a hit
cat > "$T/odd.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Quiet(HTTPServer):
    # HTTPServer.server_bind calls socket.getfqdn(), a reverse DNS lookup that takes ~35 s on the
    # GitHub macOS runner; a test stub on 127.0.0.1 needs no name.
    def server_bind(self):
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

status, body = int(sys.argv[2]), sys.argv[3].encode()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(status); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
s = Quiet(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()
PY
n=0
for spec in '200|{"detail":"oops"}' '200|not json' '500|{"detail":"boom"}' '200|{"findings":"x"}'; do
  n=$((n + 1))
  python3 -I "$T/odd.py" "$T/odd$n.port" "${spec%%|*}" "${spec#*|}" >/dev/null 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/odd$n.port" ] && break; sleep 0.1; done
  out="$(prompt_hook "http://127.0.0.1:$(cat "$T/odd$n.port")" "key $SEC")"
  [ -z "$out" ] && [ "$(rc)" = 0 ] && ok || bad "malformed or error answer ($spec): no note, exit 0"
done

# 7. the request has an 8 s limit; a timed-out request gives no note.
# A stub curl records its arguments and fails like a timeout (exit 28).
mkdir -p "$T/bin"
cat > "$T/bin/curl" <<SH
#!/usr/bin/env bash
printf '%s\n' "\$*" > "$T/curl.args"
cat > /dev/null
exit 28
SH
chmod +x "$T/bin/curl"
out="$(prompt_hook "$UP" "key $SEC" "PATH=$T/bin:$PATH")"
[ -z "$out" ] && [ "$(rc)" = 0 ] && ok || bad "timeout: no note, exit 0"
grep -qE -- '-m 8( |$)' "$T/curl.args" && ok || bad "the request carries an 8 s time limit (-m 8): $(cat "$T/curl.args" 2>/dev/null)"

# 8. long prompts go to the secret-only route and are sent whole (up to 900000 bytes);
# a service refusal (413) means no note
: > "$T/capped/requests"
big="$(head -c 20000 /dev/zero | tr '\0' 'a') $SEC"
out="$(prompt_hook "$CAPPED" "$big")"
[ "$(awk '{print $2}' "$T/capped/requests" | head -1)" -gt 20000 ] && ok || bad "a 20 KB prompt is sent whole, not cut by the hook"
[ -n "$out" ] && ok || bad "a 20 KB prompt with a secret (under the service cap) gets the note"
: > "$T/capped/requests"
big="$(head -c 70000 /dev/zero | tr '\0' 'a') $SEC"
out="$(prompt_hook "$CAPPED" "$big")"
[ -z "$out" ] && [ "$(rc)" = 0 ] && ok || bad "a prompt over the service cap (413) gets no note, exit 0 (documented open)"
grep -q "^/v1/scan/secret " "$T/capped/requests" && ok || bad "the oversize prompt was sent to the secret-only route"
! grep -q "^/v1/scan " "$T/capped/requests" && ok || bad "the hook never uses the full route (it would run the models for nothing)"

# A prompt past the OS per-argument limit (~128 KB) used to break the hook's own
# jq call (empty text scanned, no note). The text now goes to jq on stdin, so a
# 200 KB prompt is sent whole and a credential at the very end still gets the note.
: > "$T/open/requests"
head -c 200000 /dev/zero | tr '\0' 'a' > "$T/huge.txt"; printf ' %s' "$SEC" >> "$T/huge.txt"
out="$(jq -n --rawfile p "$T/huge.txt" '{prompt:$p}' | GUARDS_ENDPOINT="$UP" bash "$HOOK")"
[ "$(awk '{print $2}' "$T/open/requests" | head -1)" -gt 200000 ] && ok || bad "a 200 KB prompt is sent whole, not as an empty text"
[ -n "$out" ] && ok || bad "a 200 KB prompt with a credential at the end gets the note"

# Past 900000 bytes the prompt is cut so the secret-only route never refuses it
# for size; a credential at the start still gets the note.
: > "$T/open/requests"
{ printf '%s ' "$SEC"; head -c 1100000 /dev/zero | tr '\0' 'a'; } > "$T/giant.txt"
out="$(jq -n --rawfile p "$T/giant.txt" '{prompt:$p}' | GUARDS_ENDPOINT="$UP" bash "$HOOK")"
sent="$(awk '{print $2}' "$T/open/requests" | head -1)"
[ "$sent" -le 900000 ] && [ "$sent" -gt 800000 ] && ok || bad "a 1.1 MB prompt is cut to at most 900000 bytes (sent $sent)"
[ -n "$out" ] && ok || bad "a 1.1 MB prompt with a credential at the start gets the note"

# 9. jq missing: no note, exit 0 (hook cannot parse the payload)
mkdir -p "$T/nojq"
for d in /usr/local/bin /usr/bin /bin; do
  for f in "$d"/*; do
    b="$(basename "$f")"
    [ "$b" = jq ] && continue
    [ -e "$T/nojq/$b" ] || ln -s "$f" "$T/nojq/$b" 2>/dev/null
  done
done
out="$(printf '{"prompt":"key %s"}' "$SEC" | env "PATH=$T/nojq" GUARDS_ENDPOINT="$UP" "$(command -v bash)" "$HOOK")"
[ -z "$out" ] && ok || bad "jq missing: no note"

echo "userpromptsubmit-guard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
