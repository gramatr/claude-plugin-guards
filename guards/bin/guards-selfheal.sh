#!/usr/bin/env bash
# guards/bin/guards-selfheal.sh — SessionStart hook.
#
# Pattern copied from gramatr/claude-plugin's statusline-selfheal.js:
# idempotent "check state, fix if needed" run every session start, not
# a one-shot installer the user has to remember to run.
#
# Ensures: secret-guard's runtime deps (gitleaks, jq) are present (just
# checked, not installed — no package-manager assumptions made for a
# system binary); injection-guard-daemon and pii-guard-daemon are
# installed via `uv tool install` and running as an always-on
# background service (systemd --user on Linux, launchd on macOS — see
# guards/systemd/ and guards/launchd/). Does nothing on Windows, logs
# why, per README "Known limitations."
#
# Exits 0 always — a self-heal failure must never block a Claude Code
# session from starting. Failures are logged to stderr, which Claude
# Code surfaces to the user per its own hook error-handling, not raised
# as a hook error.

set -uo pipefail

log() { echo "guards-selfheal: $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDS_ROOT="$(dirname "$SCRIPT_DIR")"

OS="$(uname -s)"

# --- secret-guard deps: check only, never auto-install a system package ---
for bin in gitleaks jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "WARNING: $bin not found on PATH — secret-guard's redaction stage will fail open (pass through unscanned). Install $bin and restart your session."
  fi
done

ensure_uv_tool() {
  local tool_name="$1" source_url="$2"
  if ! uv tool list 2>/dev/null | grep -q "^${tool_name} "; then
    log "Installing ${tool_name} via uv tool install (first run)..."
    if ! uv tool install "$source_url" >&2; then
      log "WARNING: failed to install ${tool_name} — its guard stage will fail open until this is fixed manually."
      return 1
    fi
  fi
  return 0
}

ensure_systemd_service() {
  local service_name="$1" unit_file="$2"
  local target_dir="$HOME/.config/systemd/user"
  mkdir -p "$target_dir"
  local target="$target_dir/${service_name}.service"

  if [ ! -f "$target" ] || ! diff -q "$unit_file" "$target" >/dev/null 2>&1; then
    cp "$unit_file" "$target"
    systemctl --user daemon-reload 2>&1 | while read -r line; do log "$line"; done
  fi

  if ! systemctl --user is-active --quiet "$service_name" 2>/dev/null; then
    log "Starting ${service_name} (systemd --user)..."
    systemctl --user enable --now "$service_name" 2>&1 | while read -r line; do log "$line"; done
  fi
}

# Checked once per session, not per service — the result is the same
# for both. Found by actually testing (not assumed): this build's own
# sandboxed dev environment has NO cgroup controllers delegated at all
# (cgroup.controllers empty at every level), meaning the unit files'
# MemoryMax/CPUQuota directives are accepted by systemd but silently
# NOT enforced. Warn once rather than let that be invisible.
check_cgroup_delegation() {
  local controllers
  controllers="$(cat /sys/fs/cgroup/user.slice/cgroup.controllers 2>/dev/null || cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "")"
  if [ -z "$controllers" ] || ! echo "$controllers" | grep -q memory; then
    log "WARNING: the memory cgroup controller does not appear to be delegated to your user systemd instance — injection-guard-daemon.service/pii-guard-daemon.service declare MemoryMax limits that will be ACCEPTED but NOT ENFORCED. Not a functional problem, but means a bug/leak in either daemon has no resource ceiling on this machine. Common on WSL2 and some nested-container environments; verify with: cat /sys/fs/cgroup/user.slice/cgroup.controllers"
  fi
}

case "$OS" in
  Linux)
    if ! command -v systemctl >/dev/null 2>&1 || [ -z "${XDG_RUNTIME_DIR:-}" ]; then
      log "WARNING: systemd --user not available in this environment — injection-guard/pii-guard daemons will not be auto-started. Run them manually (see each repo's README) or set up systemd --user."
    else
      check_cgroup_delegation

      ENV_FILE="$HOME/.config/gramatr-guards/injection-guard.env"
      if [ ! -f "$ENV_FILE" ]; then
        log "WARNING: $ENV_FILE not found — injection-guard-daemon needs HF_TOKEN=<your Hugging Face token, with the Llama Prompt Guard 2 gated license accepted> in that file. This cannot be automated (accepting someone else's license requires your own HF account). Create that file and restart your session, or the injection-guard stage will fail open."
      else
        # Enforce, not just assume, that a file holding a real credential
        # isn't group/world-readable. Fixed automatically (chmod is cheap
        # and unambiguous here — unlike auto-installing a system package,
        # there's no judgment call in tightening permissions on your own file).
        PERMS="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null)"
        if [ "$PERMS" != "600" ]; then
          log "WARNING: $ENV_FILE had permissions $PERMS (not 600) — it holds a real credential. Fixing to 600 now."
          chmod 600 "$ENV_FILE"
        fi
      fi

      ensure_uv_tool "injection-guard" "git+https://github.com/gramatr/injection-guard" && \
        ensure_systemd_service "injection-guard-daemon" "$GUARDS_ROOT/systemd/injection-guard-daemon.service"
      ensure_uv_tool "pii-guard" "git+https://github.com/gramatr/pii-guard" && \
        ensure_systemd_service "pii-guard-daemon" "$GUARDS_ROOT/systemd/pii-guard-daemon.service"

      # Bind-address assertion: the bare/systemd path should NEVER bind
      # 0.0.0.0 — that's only correct inside Docker's isolated network
      # namespace (see each repo's Dockerfile comment). A bare process
      # bound to 0.0.0.0 on this path would expose it to the whole
      # network, not just this machine. Checked after start, not assumed
      # from the unit file text — the unit file's Environment= could be
      # overridden by something else on a real machine.
      for pair in "injection-guard-daemon:8730" "pii-guard-daemon:8731"; do
        name="${pair%%:*}"; port="${pair##*:}"
        if systemctl --user is-active --quiet "$name" 2>/dev/null; then
          if ss -ltn 2>/dev/null | grep -q "0.0.0.0:${port} "; then
            log "WARNING: ${name} appears to be bound to 0.0.0.0:${port}, not 127.0.0.1 — this exposes it to the whole network on a bare/systemd deployment. Check its Environment=*_HOST setting."
          fi
        fi
      done
    fi
    ;;
  Darwin)
    log "macOS launchd self-heal not yet implemented in this script — see guards/launchd/ for unit templates and install them manually for now. See README 'Known limitations.'"
    ;;
  *)
    log "Unsupported OS ($OS) for daemon self-heal — Windows is explicitly out of scope for v1, see README. secret-guard's hook stage still works (no daemon needed); injection-guard/pii-guard stages will fail open."
    ;;
esac

exit 0
