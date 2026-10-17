#!/usr/bin/env bash
# guards/bin/guards-selfheal.sh — SessionStart hook.
#
# Docker-first: manages secret-guard/pii-guard/injection-guard as a
# single `docker compose` stack (guards/docker/docker-compose.yml).
# Falls back to the old uv-tool-install + systemd/launchd path (see
# guards/systemd/, guards/launchd/) only when Docker isn't usable on
# this machine — not removed, because that path still works on hosts
# where Docker itself isn't an option.
#
# Idempotent "check state, fix if needed" run every session start —
# same pattern as grāmatr's own statusline-selfheal.js and the original
# version of this script.
#
# Exits 0 always — a self-heal failure must never block a Claude Code
# session from starting. Failures are logged to stderr.

set -uo pipefail

log() { echo "guards-selfheal: $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDS_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$GUARDS_ROOT/docker/docker-compose.yml"
ENV_FILE="$HOME/.config/gramatr-guards/injection-guard.env"

# --- secret-guard's own system deps still checked either way: the
# Docker build pulls its own gitleaks/jq, but the bare-metal fallback
# hook stage (combined-hook.sh's SECRET_SCAN path) needs them on PATH. ---
for bin in gitleaks jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "WARNING: $bin not found on PATH — secret-guard's bare-metal fallback stage will fail open if the Docker container is ever down. Install $bin."
  fi
done

docker_usable() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1
}

# Stop the OLD bare-metal daemons before bringing up the Docker stack —
# found by testing, not assumed: both bind the same ports (8730/8731)
# the Docker containers publish, so leaving the systemd units running
# makes `docker compose up` fail to bind and silently leaves the
# container's port-publish unset (confirmed: `docker compose ps` showed
# an empty PORTS column on a container created during a failed bind,
# which then kept answering nothing on that port even after the
# conflicting process went away — a plain `up -d` does not retry the
# bind, only `--force-recreate` does). One-time migration, not a
# per-session check: once the systemd units are disabled they stay
# disabled.
migrate_off_systemd() {
  local any_disabled=0
  for svc in injection-guard-daemon pii-guard-daemon; do
    if systemctl --user is-enabled --quiet "$svc" 2>/dev/null || systemctl --user is-active --quiet "$svc" 2>/dev/null; then
      log "Migrating off bare-metal ${svc} (stopping + disabling in favor of the Docker stack)..."
      systemctl --user disable --now "$svc" 2>&1 | while read -r line; do log "$line"; done
      any_disabled=1
    fi
  done
  if [ "$any_disabled" -eq 1 ]; then
    # Give the kernel a moment to actually release the port before compose tries to bind it.
    sleep 1
  fi
}

ensure_docker_stack() {
  if [ ! -f "$ENV_FILE" ]; then
    # `docker compose up` validates every service's env_file up front —
    # found by testing: a missing env_file (even for one service)
    # refuses to bring up the WHOLE stack, including secret-guard and
    # pii-guard, which don't need it at all. Create it empty (0600) so
    # compose can start; injection-guard itself then fails at runtime
    # with its own clear missing-HF_TOKEN error, which is the correct
    # "fail visibly, don't block everything else" shape.
    log "WARNING: $ENV_FILE not found — injection-guard needs HF_TOKEN=<your Hugging Face token, with the Llama Prompt Guard 2 gated license accepted> in that file. This cannot be automated. Creating it empty so the rest of the stack can still start; the injection-guard container will fail open until you add a real token and restart."
    mkdir -p "$(dirname "$ENV_FILE")"
    touch "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  else
    local perms
    perms="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null)"
    if [ "$perms" != "600" ]; then
      log "WARNING: $ENV_FILE had permissions $perms (not 600) — it holds a real credential. Fixing to 600 now."
      chmod 600 "$ENV_FILE"
    fi
  fi

  migrate_off_systemd

  log "Ensuring Docker Compose guard stack is up ($COMPOSE_FILE)..."
  if ! docker compose -f "$COMPOSE_FILE" up -d --build 2>&1 | while read -r line; do log "$line"; done; then
    log "WARNING: docker compose up failed — guard stages will fail open until this is fixed manually (try: docker compose -f $COMPOSE_FILE up -d --build)."
    return 1
  fi

  # Verify each service answers on 127.0.0.1, not just "container
  # running" — a container can be Up with its health check unconfigured
  # or its port-publish silently missing (see migrate_off_systemd's
  # comment on the failed-bind case this guards against recurring).
  for pair in "secret-guard:8732:/health" "pii-guard:8731:/health" "injection-guard:8730:/health"; do
    local name rest port path
    name="${pair%%:*}"
    rest="${pair#*:}"
    port="${rest%%:*}"
    path="${rest#*:}"
    if ! curl -sS -m 3 "http://127.0.0.1:${port}${path}" >/dev/null 2>&1; then
      log "WARNING: ${name} not answering on 127.0.0.1:${port}${path} yet — it may still be starting (injection-guard's model load takes longer), or it failed to start. Check: docker compose -f $COMPOSE_FILE logs ${name}"
    fi
  done
  return 0
}

# --- Non-Docker fallback: the original uv-tool-install + systemd/launchd path ---
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

fallback_non_docker() {
  log "Docker not usable on this machine — falling back to bare-metal (uv tool + systemd/launchd). See README for the Docker path, which is preferred when available."
  OS="$(uname -s)"
  case "$OS" in
    Linux)
      if ! command -v systemctl >/dev/null 2>&1 || [ -z "${XDG_RUNTIME_DIR:-}" ]; then
        log "WARNING: systemd --user not available either — injection-guard/pii-guard will not be auto-started. Run them manually (see each repo's README)."
        return
      fi
      if [ ! -f "$ENV_FILE" ]; then
        log "WARNING: $ENV_FILE not found — injection-guard-daemon needs HF_TOKEN=... in that file (see README). It will fail open until this exists."
      fi
      ensure_uv_tool "injection-guard" "git+https://github.com/gramatr/injection-guard" && \
        ensure_systemd_service "injection-guard-daemon" "$GUARDS_ROOT/systemd/injection-guard-daemon.service"
      ensure_uv_tool "pii-guard" "git+https://github.com/gramatr/pii-guard" && \
        ensure_systemd_service "pii-guard-daemon" "$GUARDS_ROOT/systemd/pii-guard-daemon.service"
      for pair in "injection-guard-daemon:8730" "pii-guard-daemon:8731"; do
        name="${pair%%:*}"; port="${pair##*:}"
        if systemctl --user is-active --quiet "$name" 2>/dev/null; then
          if ss -ltn 2>/dev/null | grep -q "0.0.0.0:${port} "; then
            log "WARNING: ${name} appears to be bound to 0.0.0.0:${port}, not 127.0.0.1 — check its Environment=*_HOST setting."
          fi
        fi
      done
      ;;
    Darwin)
      log "macOS non-Docker self-heal not implemented — see guards/launchd/ for unit templates and install them manually."
      ;;
    *)
      log "Unsupported OS ($OS) for non-Docker daemon self-heal."
      ;;
  esac
}

if docker_usable; then
  ensure_docker_stack
else
  fallback_non_docker
fi

exit 0
