#!/usr/bin/env bash
# guards/tests/fast-secret-scan.test.sh — the shared fast secret-scan path
# (hooks/secret-scan-lib.sh) as used by publish-guard.sh and
# mcp-output-guard.sh.
#
# A tiny stub stands in for the guards-unified service so this test needs no
# real service. Proves: when the service answers, its secret-only route is
# used and the local scan runs WITHOUT gitleaks; and when the service is
# down, slow, too old (404), or answers garbage, the full local scan runs
# instead, so protection never depends on the service. All values fabricated.
# Needs: bash, jq, python3.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUB="$HERE/../hooks/publish-guard.sh"
MCP="$HERE/../hooks/mcp-output-guard.sh"
REAL_SCAN="$HERE/../vendor/secret-guard-core/scan.sh"

T="$(mktemp -d)"
cleanup() { kill "${PIDS[@]}" 2>/dev/null; rm -rf "$T"; }
PIDS=()
trap cleanup EXIT
export HOME="$T/home"; mkdir -p "$HOME"

# Wrapper that records how the local scanner was invoked, then delegates.
cat > "$T/scan-wrapper.sh" <<WRAP
#!/usr/bin/env bash
echo "skip_gitleaks=\${SECRET_GUARD_SKIP_GITLEAKS:-0} env_values=\${SECRET_GUARD_ENV_VALUES:-0}" >> "$T/invocations.log"
exec bash "$REAL_SCAN"
WRAP
chmod +x "$T/scan-wrapper.sh"

start_stub() { # start_stub MODE -> prints port
  # Detached from this shell's stdout/stderr: a backgrounded child that keeps
  # them open would hang any $(...) that wraps this function.
  python3 -I - "$1" "$T/port.$1" >/dev/null 2>&1 <<'PY' &
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
mode, portfile = sys.argv[1], sys.argv[2]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        text = body.get("text", "")
        if mode == "hang":
            time.sleep(8)
        if mode == "404":
            out, code = {"detail": "Not Found"}, 404
        elif mode == "garbage":
            out, code = {"unexpected": True}, 200
        elif mode == "error-verdict":
            out, code = {"findings": [{"type": "secret", "verdict": "error", "reason_code": None, "detail": {}}], "redacted_text": text}, 200
        elif "STUBSECRET" in text:
            out, code = {"findings": [{"type": "secret", "verdict": "found", "reason_code": ["SECRET_SECRET-LEAD-IN"], "detail": {}}],
                         "redacted_text": text.replace("STUBSECRET123", "***REDACTED:SECRET***")}, 200
        else:
            out, code = {"findings": [{"type": "secret", "verdict": "clean", "reason_code": None, "detail": {}}], "redacted_text": text}, 200
        data = json.dumps(out).encode()
        self.send_response(code); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
s = HTTPServer(("127.0.0.1", 0), H)
open(portfile, "w").write(str(s.server_address[1]))
s.serve_forever()
PY
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/port.$1" ] && break; sleep 0.1; done
}

pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

pub() { # pub COMMAND ENDPOINT -> "deny"/"allow"
  local out
  out="$(jq -n --arg c "$1" --arg cwd "$T" '{tool_name:"Bash",tool_input:{command:$c},cwd:$cwd}' \
    | GUARDS_ENDPOINT="$2" GUARDS_SECRET_SCAN="$T/scan-wrapper.sh" SS_SERVICE_TIMEOUT="${3:-2}" bash "$PUB")"
  # "deny" here means the publish was stopped: a hard deny or a hand-off to the human.
  case "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2>/dev/null)" in deny|ask) echo deny ;; *) echo allow ;; esac
}

for m in ok 404 garbage error-verdict hang; do start_stub "$m"; done
OKP="$(cat "$T/port.ok")"; P404="$(cat "$T/port.404")"; PGARB="$(cat "$T/port.garbage")"
PERR="$(cat "$T/port.error-verdict")"; PHANG="$(cat "$T/port.hang")"
GOOD="http://127.0.0.1:$OKP"
CMD_SECRET="gh issue create --title t --body 'note STUBSECRET123 here'"
CMD_CLEAN="gh issue create --title t --body 'nothing sensitive'"

# 1. service up: its verdict is used, local scan runs WITHOUT gitleaks
: > "$T/invocations.log"
[ "$(pub "$CMD_SECRET" "$GOOD")" = "deny" ] && ok || bad "service finding blocks the publish"
grep -q 'skip_gitleaks=1 env_values=1' "$T/invocations.log" && ok || bad "local scan ran with SKIP_GITLEAKS=1 and ENV_VALUES=1 ($(cat "$T/invocations.log"))"
grep -q 'skip_gitleaks=0' "$T/invocations.log" && bad "gitleaks was not skipped although the service answered" || ok
: > "$T/invocations.log"
[ "$(pub "$CMD_CLEAN" "$GOOD")" = "allow" ] && ok || bad "clean text allowed via service"

# 2. service unavailable in every way: full local scan (no SKIP), still protects
for name in "down|http://127.0.0.1:1" "404|http://127.0.0.1:$P404" "garbage|http://127.0.0.1:$PGARB" "error-verdict|http://127.0.0.1:$PERR"; do
  label="${name%%|*}"; url="${name#*|}"
  : > "$T/invocations.log"
  [ "$(pub "DB_PASSWORD=Tq7vN2xLm9Kd4RzP8wYb; $CMD_CLEAN" "$url")" = "deny" ] && ok || bad "service $label: local scan still blocks a secret"
  grep -q 'skip_gitleaks=0' "$T/invocations.log" && ok || bad "service $label: full local scan (gitleaks) ran ($(cat "$T/invocations.log"))"
done

# 3. a hanging service costs at most the timeout, then the local scan runs
start=$SECONDS
r="$(pub "gh issue create --body 'DB_PASSWORD=Tq7vN2xLm9Kd4RzP8wYb'" "http://127.0.0.1:$PHANG" 1)"
took=$((SECONDS - start))
[ "$r" = "deny" ] && [ "$took" -le 5 ] && ok || bad "hanging service: $r in ${took}s (want deny, <= 5s)"

# 4. speed budget on the fast path (stub answers instantly)
now_ms() { # BSD date has no %N (it prints a literal N); python3 is already required
  local n; n="$(date +%s%N 2>/dev/null)"
  case "$n" in *N|"") python3 -c 'import time; print(int(time.time() * 1000))' ;; *) echo $((n / 1000000)) ;; esac
}
start=$(now_ms)
pub "$CMD_CLEAN" "$GOOD" >/dev/null
ms=$(( $(now_ms) - start ))
[ "$ms" -le 1500 ] && ok || bad "fast path took ${ms} ms (budget 1500 ms incl. process starts)"

# 5. MCP guard uses the same path
out="$(jq -n --argjson r '[{"type":"text","text":"x STUBSECRET123 y"}]' '{tool_name:"mcp__x__get",tool_input:{},tool_response:$r}' \
  | GUARDS_ENDPOINT="$GOOD" GUARDS_SECRET_SCAN="$T/scan-wrapper.sh" bash "$MCP")"
new="$(printf '%s' "$out" | jq -c '.hookSpecificOutput.updatedToolOutput' 2>/dev/null)"
[[ -n "$new" && "$new" != *STUBSECRET123* ]] && ok || bad "MCP guard redacts via the service result ($new)"

echo "fast-secret-scan: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
