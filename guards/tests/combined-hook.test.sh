#!/usr/bin/env bash
# guards/tests/combined-hook.test.sh — the Bash output hook (combined-hook.sh).
#
# This hook runs on EVERY Bash call, so these tests pin the things that must
# not regress: secrets are redacted via the fast secret-only route and never
# wait on the slow PII/injection models; flags are best effort within a
# budget; any failure falls back to the previous behavior; and
# GUARDS_FAST_BASH=0 restores the previous single /v1/scan path exactly.
# A stub service stands in for guards-unified. All values are fabricated.
# Needs: bash, jq, python3.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HERE/../hooks/combined-hook.sh"
T="$(mktemp -d)"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"

start_stub() { # start_stub NAME FLAG_DELAY_SECONDS
  python3 -I - "$1" "$2" "$T" >/dev/null 2>&1 <<'PY' &
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Quiet(ThreadingHTTPServer):
    # HTTPServer.server_bind calls socket.getfqdn(), a reverse DNS lookup that takes ~35 s on the
    # GitHub macOS runner; a test stub on 127.0.0.1 needs no name.
    def server_bind(self):
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

name, delay, t = sys.argv[1], float(sys.argv[2]), sys.argv[3]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        text = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}").get("text", "")
        open(f"{t}/{name}.requests", "a").write(self.path + "\n")
        open(f"{t}/{name}.lens", "a").write(self.path + " " + str(len(text.encode())) + "\n")
        secret = {"type": "secret", "verdict": "clean", "reason_code": None, "detail": {}}
        red = text
        if "STUBSECRET123" in text:
            red = text.replace("STUBSECRET123", "***REDACTED:SECRET***")
            secret = {"type": "secret", "verdict": "found", "reason_code": ["SECRET_SECRET-LEAD-IN"], "detail": {"redacted_text": red}}
        if self.path == "/v1/scan/secret":
            out = {"findings": [secret], "redacted_text": red}
        else:
            time.sleep(delay)
            pii = {"type": "pii", "verdict": "found" if "STUBPII" in text else "clean", "reason_code": None,
                   "detail": {"entities": [{"entity_type": "PERSON"}] if "STUBPII" in text else []}}
            ig = {"type": "injection", "verdict": "malicious" if "STUBINJECT" in text else "clean", "reason_code": None,
                  "detail": {"score": 0.99}}
            out = {"findings": [secret, pii, ig], "redacted_text": red}
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
s = Quiet(("127.0.0.1", 0), H)
open(f"{t}/{name}.port", "w").write(str(s.server_address[1]))
s.serve_forever()
PY
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/$1.port" ] && break; sleep 0.1; done
}
# Timing budgets are multiplied by GUARDS_TEST_BUDGET_FACTOR (default 1). Only the shared macOS CI runner
# sets it (2): the same checks pass at 1 on a real Mac, and correctness is asserted regardless.
BF="${GUARDS_TEST_BUDGET_FACTOR:-1}"
start_stub fast 0
start_stub slow 6
FAST="http://127.0.0.1:$(cat "$T/fast.port")"
SLOW="http://127.0.0.1:$(cat "$T/slow.port")"
DOWN="http://127.0.0.1:1"

pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

now_ms() { # BSD date has no %N (it prints a literal N); python3 is already required
  local n; n="$(date +%s%N 2>/dev/null)"
  case "$n" in *N|"") python3 -c 'import time; print(int(time.time() * 1000))' ;; *) echo $((n / 1000000)) ;; esac
}
hook() { # hook STDOUT STDERR ENDPOINT [ENV...] -> raw hook stdout; writes elapsed ms to $T/ms
  local s e out
  printf '%s' "$1" > "$T/h.out"; printf '%s' "$2" > "$T/h.err"
  s=$(now_ms)
  out="$(jq -n --rawfile o "$T/h.out" --rawfile e "$T/h.err" '{tool_name:"Bash",tool_input:{command:"x"},tool_response:{stdout:$o,stderr:$e,interrupted:false,isImage:false}}' \
    | env GUARDS_ENDPOINT="$3" "${@:4}" bash "$HOOK")"
  e=$(now_ms); echo $((e - s)) > "$T/ms"
  printf '%s' "$out"
}
field() { printf '%s' "$1" | jq -r ".hookSpecificOutput.updatedToolOutput.$2 // empty" 2>/dev/null; }

# 1. clean output: no rewrite at all
out="$(hook "all good here" "" "$FAST")"; [ -z "$out" ] && ok || bad "clean output produces no rewrite"

# 2. a secret is redacted through the secret-only route
out="$(hook "x STUBSECRET123 y" "" "$FAST")"
so="$(field "$out" stdout)"
[[ -n "$so" && "$so" != *STUBSECRET123* && "$so" == *REDACTED* ]] && ok || bad "secret redacted ($so)"
grep -q '^/v1/scan/secret$' "$T/fast.requests" && ok || bad "the secret-only route was used"

# 3. stderr is scanned too
out="$(hook "fine" "err STUBSECRET123" "$FAST")"
[[ "$(field "$out" stderr)" != *STUBSECRET123* && -n "$(field "$out" stderr)" ]] && ok || bad "stderr redacted"

# 4. PII and injection flags still appear (from the first 2 KB)
out="$(hook "hello STUBPII there" "" "$FAST")"; [[ "$(field "$out" stdout)" == *"possible PII"* ]] && ok || bad "PII flag note"
out="$(hook "hello STUBINJECT there" "" "$FAST")"; [[ "$(field "$out" stdout)" == *"prompt-injection"* ]] && ok || bad "injection warning"

# 5. THE hot-path guarantee: slow PII/injection models never delay the secret scan
out="$(hook "x STUBSECRET123 y STUBPII" "" "$SLOW")"
so="$(field "$out" stdout)"
[[ -n "$out" && "$so" != *STUBSECRET123* ]] && ok || bad "secret redacted even though the model scan is slow"
[[ "$so" != *"possible PII"* ]] && ok || bad "slow flags are dropped silently, not waited for"
MS="$(cat "$T/ms")"; [ "$MS" -le $((2000 * BF)) ] && ok || bad "slow models held the hook for ${MS} ms (budget $((2000 * BF)))"

# 5b. the flag prefix is capped at 2 KB however large the output is
: > "$T/fast.lens"
hook "$(python3 -I -c "print('word ' * 2000)")" "" "$FAST" >/dev/null
awk '$1=="/v1/scan" && $2>2048 {bad=1} END{exit bad}' "$T/fast.lens" && grep -q '^/v1/scan 2048$' "$T/fast.lens" && ok || bad "flag prefix capped at 2048 bytes ($(grep '^/v1/scan ' "$T/fast.lens" | tr '\n' ' '))"

# 6. big output (the old 24 KB cap would have missed this), secret at the end
big="$(python3 -I -c "print('log line number one two three four five six seven\n' * 4000)")"
out="$(hook "${big}STUBSECRET123" "" "$FAST")"
[[ -n "$out" && "$(field "$out" stdout)" != *STUBSECRET123* ]] && ok || bad "secret past 24 KB is redacted (output empty: ${#out} bytes)"
MS="$(cat "$T/ms")"; [ "$MS" -le $((2000 * BF)) ] && ok || bad "190 KB output took ${MS} ms (budget $((2000 * BF)))"

# 7. service down: full local scan still redacts
out="$(hook "DB_PASSWORD=Tq7vN2xLm9Kd4RzP8wYb" "" "$DOWN")"
[[ -n "$out" && "$(field "$out" stdout)" != *Tq7vN2xLm9Kd4RzP8wYb* ]] && ok || bad "service down: local fallback redacts"

# 8. off switch and redact mode use the previous single /v1/scan path
: > "$T/fast.requests"
out="$(hook "x STUBSECRET123 y" "" "$FAST" GUARDS_FAST_BASH=0)"
[[ "$(field "$out" stdout)" != *STUBSECRET123* ]] && ok || bad "GUARDS_FAST_BASH=0 still redacts"
grep -qx '/v1/scan' "$T/fast.requests" && ! grep -qx '/v1/scan/secret' "$T/fast.requests" && ok || bad "GUARDS_FAST_BASH=0 used only /v1/scan ($(cat "$T/fast.requests" | tr '\n' ' '))"
: > "$T/fast.requests"
hook "x STUBSECRET123 y" "" "$FAST" PII_GUARD_MODE=redact >/dev/null
! grep -qx '/v1/scan/secret' "$T/fast.requests" && ok || bad "PII_GUARD_MODE=redact uses the previous path"

# 9. a missing secret-scan library falls back to the previous path, never to "no scanning"
cp -r "$HERE/../hooks" "$T/hooks-nolib" && rm -f "$T/hooks-nolib/secret-scan-lib.sh" && mkdir -p "$T/vendor" && cp -r "$HERE/../vendor/secret-guard-core" "$T/vendor/"
out="$(jq -n '{tool_name:"Bash",tool_input:{command:"x"},tool_response:{stdout:"x STUBSECRET123 y",stderr:"",interrupted:false,isImage:false}}' | GUARDS_ENDPOINT="$FAST" bash "$T/hooks-nolib/combined-hook.sh" 2>/dev/null)"
[[ -n "$out" && "$(field "$out" stdout)" != *STUBSECRET123* ]] && ok || bad "missing library falls back and still redacts"

# 10. non-Bash tools are ignored
out="$(jq -n '{tool_name:"Read",tool_response:{stdout:"x STUBSECRET123"}}' | GUARDS_ENDPOINT="$FAST" bash "$HOOK")"; [ -z "$out" ] && ok || bad "non-Bash tool ignored"

echo "combined-hook: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
