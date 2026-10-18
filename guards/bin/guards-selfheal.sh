#!/usr/bin/env bash
# guards/bin/guards-selfheal.sh — SessionStart hook.
#
# Docker-first: manages guards-unified as a single-service
# `docker compose` stack (guards/docker/docker-compose.yml) — one
# container, one API (:8700), replacing the old three-container
# secret-guard/pii-guard/injection-guard stack. Same consolidation
# already shipped and CI-verified in gramatr/platform-guards#1.
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

# --- gitleaks/jq still checked either way: combined-hook.sh's secret
# axis keeps a local scan.sh fallback for when guards-unified itself is
# unreachable (the one case this stack still gives secret detection an
# independent path, decided deliberately — see
# docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U1).
# PII and injection detection have no equivalent fallback: both need
# their actual loaded models to produce a result at all, so there's no
# cheap local path for them the way gitleaks gives secrets. ---
for bin in gitleaks jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "WARNING: $bin not found on PATH — combined-hook.sh's secret-axis fallback will fail open if guards-unified is ever down. Install $bin."
  fi
done

docker_usable() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1
}

# One-time migration, not a per-session check: tear down anything left
# over from BEFORE this consolidation, on whichever path it was running.
# Two prior states to clean up, not one:
#   1. Bare-metal systemd units (injection-guard-daemon, pii-guard-daemon)
#      — the original pre-Docker install path.
#   2. The old three-container Docker stack (secret-guard/pii-guard/
#      injection-guard on 8732/8731/8730) — found by testing, not
#      assumed: a machine that already ran that stack still has those
#      three containers bound to their old ports, which does NOT
#      conflict with guards-unified's :8700 bind, so `docker compose up`
#      for the NEW stack would succeed while three stale containers sit
#      alongside it, still running, still reachable, still the old
#      three-daemon architecture nothing points at anymore. The old
#      migration code only handled (1), never (2) — this is the fix.
migrate_from_previous_architecture() {
  local any_migrated=0

  for svc in injection-guard-daemon pii-guard-daemon; do
    if systemctl --user is-enabled --quiet "$svc" 2>/dev/null || systemctl --user is-active --quiet "$svc" 2>/dev/null; then
      log "Migrating off bare-metal ${svc} (stopping + disabling — PII/injection detection now require guards-unified, which has no non-Docker equivalent; see 'No-Docker machines' below)..."
      systemctl --user disable --now "$svc" 2>&1 | while read -r line; do log "$line"; done
      any_migrated=1
    fi
  done

  # Old three-container Docker stack — matched by container name, not
  # by the new compose file (the old one no longer exists in this repo
  # to -f against; match by name instead).
  local old_containers
  old_containers="$(docker ps -aq --filter "name=^gramatr-guards-secret-guard-1$" --filter "name=^gramatr-guards-pii-guard-1$" --filter "name=^gramatr-guards-injection-guard-1$" 2>/dev/null)"
  if [ -n "$old_containers" ]; then
    log "Migrating off the old three-container stack (secret-guard/pii-guard/injection-guard on 8732/8731/8730) in favor of guards-unified on :8700..."
    echo "$old_containers" | xargs -r docker rm -f 2>&1 | while read -r line; do log "$line"; done
    any_migrated=1
  fi

  if [ "$any_migrated" -eq 1 ]; then
    # Give the kernel a moment to actually release any freed ports.
    sleep 1
  fi
}

ensure_docker_stack() {
  if [ ! -f "$ENV_FILE" ]; then
    # guards-unified's injection finding needs HF_TOKEN to load its
    # model; the secret/PII findings don't. Create the file empty
    # (0600) so the stack can still start — injection classification
    # fails at runtime with its own clear missing-token error, which is
    # the correct "fail visibly, don't block everything else" shape.
    log "WARNING: $ENV_FILE not found — injection detection needs HF_TOKEN=<your Hugging Face token, with the Llama Prompt Guard 2 gated license accepted> in that file. This cannot be automated. Creating it empty so the rest of the stack can still start; injection classification will fail open until you add a real token and restart."
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

  migrate_from_previous_architecture

  log "Ensuring guards-unified is up ($COMPOSE_FILE)..."
  if ! docker compose -f "$COMPOSE_FILE" up -d 2>&1 | while read -r line; do log "$line"; done; then
    log "WARNING: docker compose up failed — guard stages will fail open until this is fixed manually (try: docker compose -f $COMPOSE_FILE up -d)."
    return 1
  fi

  if ! curl -sS -m 3 "http://127.0.0.1:8700/health" >/dev/null 2>&1; then
    log "WARNING: guards-unified not answering on 127.0.0.1:8700/health yet — it may still be starting (model load takes longer on first run), or it failed to start. Check: docker compose -f $COMPOSE_FILE logs guards-unified"
  fi
  return 0
}

# --- No-Docker machines: secret detection only, via combined-hook.sh's
# own local scan.sh fallback (no daemon, no network dependency — just
# a gitleaks invocation). PII and injection detection require
# guards-unified's loaded models, which have no non-Docker equivalent
# (the old bare-metal path ran pii-guard-daemon/injection-guard-daemon
# as standalone systemd services; that path is retired along with the
# old three-container Docker stack it paralleled — see
# docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U1/U2
# for why PII/injection don't get an equivalent fallback). ---
fallback_non_docker() {
  log "Docker not usable on this machine — guards-unified (and with it, PII and injection detection) cannot run here. Secret detection still works via combined-hook.sh's local scan.sh fallback, as long as gitleaks/jq are on PATH (checked above). Install Docker for full coverage — see README."
}

if docker_usable; then
  ensure_docker_stack
else
  fallback_non_docker
fi

exit 0
