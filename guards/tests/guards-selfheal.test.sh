#!/usr/bin/env bash
# guards/tests/guards-selfheal.test.sh — the SessionStart self-heal script
# (bin/guards-selfheal.sh).
#
# Runs the script in a throwaway plugin tree with stub `docker`, `curl`, `git`,
# `timeout`, `sleep`, `gitleaks` and `systemctl` first on PATH, so no real
# container, network or sleep is involved. Pins: it always exits 0; when the
# service is healthy it still runs the idempotent pull and `up -d` and removes
# nothing; when the service is missing it starts it; without docker it only
# logs; a missing compose file, a pull timeout and a service that never
# answers each warn and carry on; foreign containers on :8700 are left alone.
# All values are fabricated. Needs: bash, jq.
#
# SCRIPT_SRC=/path/to/other/guards-selfheal.sh runs the same cases against a
# different copy of the script (negative controls).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_SRC="${SCRIPT_SRC:-$HERE/../bin/guards-selfheal.sh}"
BASH_BIN="$(command -v bash)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

mkdir -p "$T/p/guards/bin" "$T/p/guards/docker" "$T/shim" "$T/dockerbin" "$T/sys"
cp "$SCRIPT_SRC" "$T/p/guards/bin/guards-selfheal.sh"
SCRIPT="$T/p/guards/bin/guards-selfheal.sh"
COMPOSE="$T/p/guards/docker/docker-compose.yml"
echo "services: {}" > "$COMPOSE"

# The system PATH minus everything the cases need to control.
for d in /usr/local/bin /usr/bin /bin; do
  for f in "$d"/*; do
    n="$(basename "$f")"
    case "$n" in docker|gitleaks|curl|git|timeout|sleep|systemctl) continue ;; esac
    [ -e "$T/sys/$n" ] || ln -s "$f" "$T/sys/$n" 2>/dev/null
  done
done

mk() { printf '%s\n' "$2" > "$1"; chmod +x "$1"; }
mk "$T/shim/gitleaks" '#!/usr/bin/env bash
exit 0'
mk "$T/shim/systemctl" '#!/usr/bin/env bash
exit 1'
mk "$T/shim/sleep" '#!/usr/bin/env bash
exit 0'
mk "$T/shim/git" '#!/usr/bin/env bash
[ -f "$GH_STATE/remote_head" ] && printf "%s\trefs/heads/main\n" "$(cat "$GH_STATE/remote_head")"
exit 0'
mk "$T/shim/timeout" '#!/usr/bin/env bash
echo "timeout $1" >> "$GH_STATE/timeout.log"
secs="$1"; shift
if [ "$1" = docker ] && [ "$3" = -f ] && [ "$5" = pull ] && [ -f "$GH_STATE/pull_timeout" ]; then exit 124; fi
exec "$@"'
mk "$T/shim/curl" '#!/usr/bin/env bash
url=""; for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
echo "curl $url" >> "$GH_STATE/curl.log"
case "$url" in
  */health)
    if [ -f "$GH_STATE/healthy" ] || { [ -f "$GH_STATE/up_called" ] && [ ! -f "$GH_STATE/never_healthy" ]; }; then echo "{\"status\":\"ok\"}"; exit 0; fi
    exit 7 ;;
  */about)
    if [ -f "$GH_STATE/up_called" ] && [ -f "$GH_STATE/version_after" ]; then printf "{\"version\":\"%s\"}" "$(cat "$GH_STATE/version_after")"; exit 0; fi
    if [ -f "$GH_STATE/version_before" ]; then printf "{\"version\":\"%s\"}" "$(cat "$GH_STATE/version_before")"; exit 0; fi
    exit 7 ;;
  *) exit 6 ;;
esac'
mk "$T/dockerbin/docker" '#!/usr/bin/env bash
echo "$*" >> "$GH_STATE/docker.log"
case "$1" in
  info) [ -f "$GH_STATE/info_fail" ] && exit 1; exit 0 ;;
  compose)
    case "$2" in
      version) exit 0 ;;
      -f)
        [ -f "$GH_STATE/${4}_fail" ] && exit 1
        if [ "$4" = up ]; then
          [ -f "$3" ] || { echo "no such file: $3" >&2; exit 1; }
          touch "$GH_STATE/up_called"
        fi
        exit 0 ;;
    esac ;;
  ps)
    case "$*" in
      *publish=8730*) [ -f "$GH_STATE/old_containers" ] && cat "$GH_STATE/old_containers" ;;
      *publish=8700*) [ -f "$GH_STATE/holders" ] && cat "$GH_STATE/holders" ;;
    esac
    exit 0 ;;
  inspect)
    case "$*" in
      *config_files*) cat "$GH_STATE/cfg" 2>/dev/null ;;
      *.Name*) echo "/holder" ;;
      *.Config.Image*) cat "$GH_STATE/image" 2>/dev/null ;;
    esac
    exit 0 ;;
esac
exit 0'

pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

new_state() { S="$T/state.$RANDOM"; mkdir -p "$S"; : > "$S/docker.log"; : > "$S/curl.log"; : > "$S/timeout.log"; }
# run_heal [docker|nodocker] -> $S/out, $S/err, $S/rc
run_heal() {
  local path="$T/shim:$T/sys"
  [ "$1" = docker ] && path="$T/dockerbin:$path"
  env "PATH=$path" "HOME=$T/home" "GH_STATE=$S" "$BASH_BIN" "$SCRIPT" >"$S/out" 2>"$S/err"
  echo $? > "$S/rc"
}
rcof() { cat "$S/rc"; }
called() { grep -q -- "$1" "$S/docker.log"; }

ENV_FILE="$T/home/.config/gramatr-guards/injection-guard.env"
mkdir -p "$(dirname "$ENV_FILE")"; : > "$ENV_FILE"; chmod 600 "$ENV_FILE"

# 1. service healthy: still the idempotent pull + up -d, nothing removed, silent
new_state; touch "$S/healthy"; echo 0.2.4 > "$S/version_before"; echo 0.2.4 > "$S/version_after"
run_heal docker
[ "$(rcof)" = 0 ] && ok || bad "healthy: exit 0"
called "compose -f $COMPOSE pull" && called "compose -f $COMPOSE up -d" && ok || bad "healthy: pull and up -d run (idempotent)"
! called " rm " && ok || bad "healthy: nothing is removed"
[ ! -s "$S/out" ] && ok || bad "healthy, same version: no additionalContext (got: $(cat "$S/out"))"
grep -q "Ensuring guards-unified is up" "$S/err" && ok || bad "healthy: logs what it is doing"
! grep -q "WARNING" "$S/err" && ok || bad "healthy: no warnings ($(grep WARNING "$S/err" | head -1))"

# 2. service missing: it is started, and the health poll then succeeds
new_state
run_heal docker
[ "$(rcof)" = 0 ] && [ -f "$S/up_called" ] && ok || bad "missing: up -d starts the service, exit 0"
! grep -q "not answering" "$S/err" && ok || bad "missing: healthy after start, no 'not answering' warning"

# 3. version changed by the pull: one SessionStart note on stdout
new_state; echo 0.2.3 > "$S/version_before"; echo 0.2.4 > "$S/version_after"
run_heal docker
[ "$(jq -r '.hookSpecificOutput.hookEventName' "$S/out" 2>/dev/null)" = SessionStart ] && ok || bad "update: SessionStart output"
jq -r '.hookSpecificOutput.additionalContext' "$S/out" 2>/dev/null | grep -q "0.2.3 to 0.2.4" && ok || bad "update: note names old and new version"

# 4. plugin behind upstream: note on stdout
new_state; touch "$S/healthy"; echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef > "$S/remote_head"
run_heal docker
jq -r '.hookSpecificOutput.additionalContext' "$S/out" 2>/dev/null | grep -q "newer version of the guards plugin" && ok || bad "plugin update note when upstream differs"

# 5. docker missing: logs, never touches docker, exit 0
new_state
run_heal nodocker
[ "$(rcof)" = 0 ] && ok || bad "docker missing: exit 0"
grep -q "Docker not usable" "$S/err" && ok || bad "docker missing: says PII/injection are unavailable"
[ ! -s "$S/docker.log" ] && ok || bad "docker missing: no docker call"

# 6. docker installed but the daemon is down: same fallback
new_state; touch "$S/info_fail"
run_heal docker
[ "$(rcof)" = 0 ] && grep -q "Docker not usable" "$S/err" && ok || bad "daemon down: fallback message, exit 0"
! called "up -d" && ok || bad "daemon down: no up -d attempt"

# 7. compose file missing: up fails, warns, exit 0, no health poll
new_state; mv "$COMPOSE" "$COMPOSE.gone"
run_heal docker
mv "$COMPOSE.gone" "$COMPOSE"
[ "$(rcof)" = 0 ] && ok || bad "compose file missing: exit 0"
grep -q "docker compose up failed" "$S/err" && ok || bad "compose file missing: warns that up failed"
! grep -q "/health" "$S/curl.log" && ok || bad "compose file missing: gives up before polling health"

# 8. pull times out: warns, carries on to up -d with the cached image
new_state; touch "$S/pull_timeout"
run_heal docker
[ "$(rcof)" = 0 ] && ok || bad "pull timeout: exit 0"
grep -q "pull failed or timed out" "$S/err" && ok || bad "pull timeout: warns the image may be stale"
called "up -d" && ok || bad "pull timeout: still runs up -d"
grep -q "^timeout 240$" "$S/timeout.log" && ok || bad "the pull is bounded at 240 s"

# 9. service never answers after start: warns after the bounded poll, exit 0
new_state; touch "$S/never_healthy"
run_heal docker
[ "$(rcof)" = 0 ] && ok || bad "never healthy: exit 0"
grep -q "not answering on 127.0.0.1:8700/health" "$S/err" && ok || bad "never healthy: warns"
[ "$(grep -c '/health' "$S/curl.log")" -le 20 ] && ok || bad "never healthy: the health poll is bounded ($(grep -c '/health' "$S/curl.log") polls)"

# 10. a failed pull command (not a timeout) is also non-fatal
new_state; touch "$S/pull_fail"
run_heal docker
[ "$(rcof)" = 0 ] && called "up -d" && ok || bad "pull failure: exit 0 and still starts the stack"

# 11. old three-container stack (ports 8730-8732) is removed
new_state; touch "$S/healthy"; echo oldcontainer1 > "$S/old_containers"
run_heal docker
called "rm -f oldcontainer1" && ok || bad "old three-container stack is removed"

# 12. :8700 holders: a foreign container is left alone with a warning ...
new_state; touch "$S/healthy"; echo foreign1 > "$S/holders"; echo "docker.io/library/nginx:1" > "$S/image"; echo "" > "$S/cfg"
run_heal docker
! called "rm -f foreign1" && ok || bad "a foreign container on :8700 is not removed"
grep -q "NOT a guards-unified container" "$S/err" && ok || bad "a foreign container on :8700 is reported"
# ... a guards-unified image outside this user's plugin cache is left alone ...
new_state; touch "$S/healthy"; echo guards1 > "$S/holders"; echo "ghcr.io/gramatr/guards-unified:cpu" > "$S/image"; echo "/tmp/elsewhere/guards/x/docker/docker-compose.yml" > "$S/cfg"
run_heal docker
! called "rm -f guards1" && ok || bad "a guards-unified container outside the plugin cache is not removed"
# ... and a stale one from this user's plugin cache is replaced.
new_state; touch "$S/healthy"; echo stale1 > "$S/holders"; echo "ghcr.io/gramatr/guards-unified:cpu" > "$S/image"
echo "$T/home/.claude/plugins/cache/mkt/guards/oldsha/docker/docker-compose.yml" > "$S/cfg"
run_heal docker
called "rm -f stale1" && ok || bad "a stale guards-unified container from the plugin cache is removed"

# 13. env file: created empty and private when absent; loosened perms are fixed
new_state; touch "$S/healthy"; rm -f "$ENV_FILE"
run_heal docker
[ -f "$ENV_FILE" ] && [ "$(stat -c %a "$ENV_FILE")" = 600 ] && grep -q "HF_TOKEN" "$S/err" && ok || bad "missing env file is created with mode 600 and the HF_TOKEN gap is reported"
chmod 644 "$ENV_FILE"; new_state; touch "$S/healthy"
run_heal docker
[ "$(stat -c %a "$ENV_FILE")" = 600 ] && ok || bad "an env file with loose permissions is set back to 600"

echo "guards-selfheal: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
