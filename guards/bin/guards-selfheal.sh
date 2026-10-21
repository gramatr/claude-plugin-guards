#!/usr/bin/env bash
# guards/bin/guards-selfheal.sh — SessionStart hook.
#
# Docker-first: manages guards-unified as a single-service
# `docker compose` stack (guards/docker/docker-compose.yml) — one
# container, one API (:8700), replacing the old three-container
# secret-guard/pii-guard/injection-guard stack.
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
METRICS_DIR="$HOME/.local/share/gramatr-guards/metrics"

# Set by check_plugin_update() / ensure_docker_stack() below, read at
# the very end of the script to build one additionalContext note.
# Empty means "nothing to report" -- most sessions, most of the time.
# This exists because a stale pull or a behind-latest plugin used to
# be visible only in stderr nobody reads (or not at all, when the
# fail-open fallback silently kept a stale cached image). Surfacing it
# in-session is what actually lets the agent tell the user, or act.
PLUGIN_UPDATE_NOTE=""
IMAGE_UPDATE_NOTE=""

# --- gitleaks/jq still checked either way: combined-hook.sh's secret
# axis keeps a local scan.sh fallback for when guards-unified itself is
# unreachable (the one case this stack still gives secret detection an
# independent path, decided deliberately — see
# docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U1).
# PII and injection detection have no equivalent fallback: both need
# their actual loaded models to produce a result at all, so there's no
# cheap local path for them the way gitleaks gives secrets.
#
# gitleaks gets an actual auto-install attempt, not just a warning —
# this was leaving the secret-axis fallback silently unavailable on a
# machine that never happened to have gitleaks already. jq is left warn-only: it's a hard dependency of THIS
# script too (every call below pipes through jq), so a machine
# actually missing it would already be failing loudly elsewhere, not
# just in the fallback path. ---
GITLEAKS_VERSION="8.30.1"

# The patched build (issue #55). guards-unified publishes standalone gitleaks binaries built
# from the same recipe as the image's gitleaks (patched Go modules; the upstream release binary
# bundles modules with known HIGH CVEs). The binary is checked against SHA-256 values THIS
# repository carries (vendor/secret-guard-core/gitleaks-assets.sha256, kept equal to
# guards-unified's docs/gitleaks-assets.sha256 by a CI check), not against a checksum served
# beside the download, so a tampered release page cannot pass. Any failure returns non-zero
# and the caller falls back to the upstream binary with a warning.
GITLEAKS_ASSETS_URL="${GUARDS_GITLEAKS_ASSETS_URL:-https://github.com/gramatr/guards-unified/releases/latest/download}"
GITLEAKS_ASSETS_SHA="${GUARDS_GITLEAKS_ASSETS_SHA:-$GUARDS_ROOT/vendor/secret-guard-core/gitleaks-assets.sha256}"

file_sha256() { # file_sha256 FILE -> hash on stdout (macOS has no sha256sum by default)
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  fi
}

# _install_patched_in TMP OS ARCH INSTALL_DIR -- no traps, so the caller removes TMP.
_install_patched_in() {
  local tmp="$1" os="$2" arch="$3" install_dir="$4" want got name
  if [ ! -r "$GITLEAKS_ASSETS_SHA" ]; then
    log "patched gitleaks: hash file $GITLEAKS_ASSETS_SHA is missing"
    return 1
  fi
  want="$(grep -v '^[[:space:]]*#' "$GITLEAKS_ASSETS_SHA" | awk -v k="${os}_${arch}" '$2 == k {print $1}')"
  if [ -z "$want" ]; then
    log "patched gitleaks: no recorded hash for ${os}_${arch}"
    return 1
  fi
  name="gitleaks-patched_${GITLEAKS_VERSION}_${os}_${arch}.tar.gz"
  if ! curl -fsSL -m 60 -o "$tmp/$name" "${GITLEAKS_ASSETS_URL}/${name}" 2>/dev/null; then
    log "patched gitleaks: ${name} is not available from ${GITLEAKS_ASSETS_URL}"
    return 1
  fi
  if ! tar -xzf "$tmp/$name" -C "$tmp" gitleaks 2>/dev/null || [ ! -f "$tmp/gitleaks" ] || [ -L "$tmp/gitleaks" ]; then
    log "patched gitleaks: ${name} did not contain a plain gitleaks file"
    return 1
  fi
  got="$(file_sha256 "$tmp/gitleaks")"
  if [ "$got" != "$want" ]; then
    log "WARNING: patched gitleaks ${os}_${arch} does not match the hash this plugin carries (expected ${want}, got '${got}') — not installing it."
    return 1
  fi
  mkdir -p "$install_dir" && mv "$tmp/gitleaks" "$install_dir/gitleaks" && chmod +x "$install_dir/gitleaks" || return 1
  return 0
}

install_patched_gitleaks() { # install_patched_gitleaks OS ARCH INSTALL_DIR
  local tmp rc
  tmp="$(mktemp -d)" || return 1
  _install_patched_in "$tmp" "$1" "$2" "$3"
  rc=$?
  rm -rf "$tmp"
  return "$rc"
}

ensure_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1; then
    return 0
  fi

  local os arch
  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) log "WARNING: gitleaks not found on PATH and auto-install isn't supported on $(uname -s) — combined-hook.sh's secret-axis fallback will fail open if guards-unified is ever down. Install manually: https://github.com/gitleaks/gitleaks#installing"; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) log "WARNING: gitleaks not found on PATH and auto-install doesn't recognize this machine's arch ($(uname -m)) — combined-hook.sh's secret-axis fallback will fail open if guards-unified is ever down. Install manually: https://github.com/gitleaks/gitleaks#installing"; return 1 ;;
  esac

  local install_dir="$HOME/.local/bin"
  if install_patched_gitleaks "$os" "$arch" "$install_dir"; then
    if command -v gitleaks >/dev/null 2>&1; then
      log "Installed patched gitleaks v${GITLEAKS_VERSION} to $install_dir/gitleaks."
    else
      log "Installed patched gitleaks v${GITLEAKS_VERSION} to $install_dir/gitleaks, but $install_dir isn't on this shell's PATH yet — add it (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\" in your shell profile) for combined-hook.sh's fallback scan to actually find it."
    fi
    return 0
  fi
  log "WARNING: the patched gitleaks could not be installed; falling back to the upstream v${GITLEAKS_VERSION} release, which bundles Go modules with known HIGH CVEs."
  local base="gitleaks_${GITLEAKS_VERSION}_${os}_${arch}"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  local release_url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
  if ! curl -sSL -m 30 -o "$tmp/${base}.tar.gz" "${release_url}/${base}.tar.gz" 2>/dev/null \
    || ! curl -sSL -m 30 -o "$tmp/checksums.txt" "${release_url}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" 2>/dev/null; then
    log "WARNING: failed to download gitleaks v${GITLEAKS_VERSION} — combined-hook.sh's secret-axis fallback will fail open if guards-unified is ever down. Install manually: https://github.com/gitleaks/gitleaks#installing"
    return 1
  fi

  # Verify against the release's own published checksums before
  # extracting anything — this is a binary we're about to put on PATH
  # and execute, not just data.
  local expected actual
  expected="$(grep " ${base}.tar.gz\$" "$tmp/checksums.txt" | awk '{print $1}')"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/${base}.tar.gz" 2>/dev/null | awk '{print $1}')"
  else
    # macOS has no sha256sum by default.
    actual="$(shasum -a 256 "$tmp/${base}.tar.gz" 2>/dev/null | awk '{print $1}')"
  fi
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    log "WARNING: gitleaks v${GITLEAKS_VERSION} download failed checksum verification (expected '${expected:-none found}', got '$actual') — not installing it. Install manually: https://github.com/gitleaks/gitleaks#installing"
    return 1
  fi

  if ! tar -xzf "$tmp/${base}.tar.gz" -C "$tmp" gitleaks 2>/dev/null; then
    log "WARNING: gitleaks v${GITLEAKS_VERSION} archive failed to extract — install manually: https://github.com/gitleaks/gitleaks#installing"
    return 1
  fi

  mkdir -p "$install_dir"
  mv "$tmp/gitleaks" "$install_dir/gitleaks"
  chmod +x "$install_dir/gitleaks"

  if command -v gitleaks >/dev/null 2>&1; then
    log "Installed UPSTREAM (unpatched) gitleaks v${GITLEAKS_VERSION} to $install_dir/gitleaks."
  else
    log "Installed UPSTREAM (unpatched) gitleaks v${GITLEAKS_VERSION} to $install_dir/gitleaks, but $install_dir isn't on this shell's PATH yet — add it (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\" in your shell profile) for combined-hook.sh's fallback scan to actually find it."
  fi
}

ensure_gitleaks

if ! command -v jq >/dev/null 2>&1; then
  log "WARNING: jq not found on PATH — combined-hook.sh's secret-axis fallback will fail open if guards-unified is ever down. Install jq."
fi

check_plugin_update() {
  # GUARDS_ROOT's own basename is this installed plugin's commit --
  # Claude Code resolves ${CLAUDE_PLUGIN_ROOT} to exactly this path
  # (.../guards/<commit>/...) before invoking this script, confirmed
  # from the session's own debug log (see README). Compare against
  # the marketplace repo's current main, bounded so an unreachable
  # network can't hang SessionStart -- same fail-open posture as
  # everything else here: no network, no verdict, not an error.
  local installed_commit latest_commit
  installed_commit="$(basename "$GUARDS_ROOT")"
  latest_commit="$(timeout 5 git ls-remote https://github.com/gramatr/claude-plugin-guards.git main 2>/dev/null | awk '{print $1}')"
  if [ -z "$latest_commit" ]; then
    return 0
  fi
  case "$latest_commit" in
    "$installed_commit"*) return 0 ;;
  esac
  PLUGIN_UPDATE_NOTE="A newer version of the guards plugin is available upstream (installed: ${installed_commit}; latest on main: ${latest_commit:0:12}). This session is running the installed one -- \`claude plugin marketplace update gramatr-guards && claude plugin update guards\`, then a restart, applies the newer one."
}

check_plugin_update

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

  # Old three-container Docker stack — matched by the ports it
  # publishes (8730-8732), not by container name. Matching by name
  # assumed the old stack's compose project was always named
  # "gramatr-guards" — confirmed wrong on a real machine (#9): a
  # differently-named old deployment left those three containers
  # running indefinitely, never migrated, because the name filter
  # simply never matched. The ports are the durable signal: whatever
  # else changed, the old stack is defined by binding exactly those
  # three ports, regardless of what its compose project happened to be
  # called when it was set up.
  local old_containers
  old_containers="$(docker ps -aq --filter "publish=8730" --filter "publish=8731" --filter "publish=8732" 2>/dev/null)"
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

# Found by hitting this directly, not hypothetical: $COMPOSE_FILE's
# path includes the plugin cache's commit hash
# (.../guards/<commit>/docker/docker-compose.yml), which changes on
# every `claude plugin update guards`. The compose project tied to the
# PREVIOUS commit's cache path is invisible to a fresh
# `docker compose -f $COMPOSE_FILE up -d` targeting the new one, so if
# that old project's container (or any unmanaged container at all,
# e.g. a bare `docker run`) is still holding :8700, the new `up -d`
# fails to bind the port -- silently, from this script's perspective,
# since that failure path already just logs a warning and returns 1.
# Confirmed on a shared Linux host: a bare `docker run --name guards-unified`
# container (zero compose labels) held the port for hours while the
# actually-current compose project sat in `Created` state, never
# started, serving nothing.
#
# Reconcile unconditionally before every `up -d`: anything bound to
# :8700 that isn't THIS exact compose file's own container gets
# removed first, whether it's unmanaged or belongs to a stale prior
# commit's project. This briefly takes the port down for whatever
# moment it takes `up -d` to bring the current stack back -- expected
# and acceptable (guard stages fail open/degrade during that gap, per
# the sendmessage-guard and combined-hook.sh fallbacks), not something
# to avoid at the cost of leaving a stale container in charge.
reconcile_port_8700() {
  local holders id name config_files image
  holders="$(docker ps -aq --filter "publish=8700" 2>/dev/null)"
  [ -z "$holders" ] && return 0

  for id in $holders; do
    config_files="$(docker inspect "$id" --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' 2>/dev/null)"
    if [ "$config_files" = "$COMPOSE_FILE" ]; then
      continue  # already this stack's own container -- `up -d` manages it normally
    fi
    name="$(docker inspect "$id" --format '{{.Name}}' 2>/dev/null | sed 's#^/##')"

    # Only remove a container we can PROVE is a stale prior-version
    # instance of this same plugin -- not anything else that happens
    # to be on :8700. Confirmed by hitting the alternative directly:
    # an earlier version of this check removed ANYTHING not matching
    # this exact compose file path, with no further check, and a
    # concurrency test running this same script from an isolated /tmp
    # sandbox copy removed the real production container as a side
    # effect, because its compose path trivially never matches a
    # sandbox's. Two conditions must BOTH hold: the image must be this
    # plugin's own guards-unified image, and the compose config_files
    # path must sit under THIS user's actual plugin cache root
    # (~/.claude/plugins/cache/*/guards/*/docker/docker-compose.yml) --
    # not just any path that happens to share the same relative shape.
    # Anchoring to the real cache root specifically (not just the
    # .../guards/<x>/docker/... shape alone) matters: a sandbox copy
    # that preserves the same relative subdirectory layout under a
    # different root (e.g. a /tmp copy of the whole cache tree, which
    # is exactly what the incident's concurrency test did) would still
    # match a shape-only check. A container failing either check is
    # left alone, loudly.
    image="$(docker inspect "$id" --format '{{.Config.Image}}' 2>/dev/null)"
    case "$image" in
      ghcr.io/gramatr/guards-unified:*) ;;
      *)
        log "WARNING: :8700 is held by '${name:-$id}' (image='${image:-unknown}'), which is NOT a guards-unified container -- leaving it alone. The upcoming docker compose up -d will likely fail to bind :8700 until this is resolved manually."
        continue
        ;;
    esac
    case "$config_files" in
      "$HOME"/.claude/plugins/cache/*/guards/*/docker/docker-compose.yml) ;;
      *)
        log "WARNING: :8700 is held by '${name:-$id}' (guards-unified image, but compose config_files='${config_files:-none, unmanaged}' isn't under this user's own plugin cache root) -- leaving it alone rather than guessing it's safe to remove."
        continue
        ;;
    esac

    log "Reconciling :8700 -- removing '${name:-$id}' (stale prior-version guards-unified container, compose config_files='${config_files}', current stack is $COMPOSE_FILE). Port will be briefly down until the current stack starts."
    docker rm -f "$id" >/dev/null 2>&1 || log "WARNING: failed to remove '${name:-$id}' -- the upcoming docker compose up -d may fail to bind :8700 because of it."
  done
}

ensure_docker_stack() {
  # guards-unified runs as a non-root user (fixed UID/GID 1000) as of
  # that repo's own fix for this exact problem -- a bind-mounted directory Docker
  # auto-creates on first run comes back owned by root, which silently
  # breaks every metrics write (confirmed by testing there: the scan
  # itself still succeeds, fail-open, but zero lines land, no loud
  # error). chmod 777 rather than trying to match the container's UID
  # exactly -- host-portable, and costs nothing real since this
  # directory only ever holds metrics with no scanned text.
  # Confirmed by testing, not hypothetical: a machine that ran the OLD
  # root-based guards-unified image before that fix has
  # the WHOLE $GRAMATR_GUARDS_DIR chain owned by root, not just the
  # metrics leaf -- Docker's own `mkdir -p` for the bind mount ran as
  # root and created every missing path component as root. mkdir -p as
  # the invoking (non-root) user then fails outright ("Permission
  # denied") if even one ancestor is root-owned and not
  # world-writable, silently with set -e off. One chown -R on the
  # whole top-level directory fixes every level under it in one shot,
  # so the guidance targets that, not just the leaf.
  GRAMATR_GUARDS_DIR="$HOME/.local/share/gramatr-guards"
  if ! mkdir -p "$METRICS_DIR" 2>/dev/null || ! chmod 777 "$METRICS_DIR" 2>/dev/null; then
    log "WARNING: $GRAMATR_GUARDS_DIR (or a parent of it) isn't owned by this user — likely left over from an older guards-unified image that ran as root. Metrics will silently fail to write until you fix this. Run: sudo chown -R \$(whoami) $GRAMATR_GUARDS_DIR"
  fi

  if [ ! -f "$ENV_FILE" ]; then
    # guards-unified loads its injection model at startup and exits if it
    # cannot (a 401 without HF_TOKEN), so without a token the service
    # does not run and PII and injection detection are unavailable;
    # secret detection continues through the hooks' local fallback.
    # Create the file empty (0600) so the compose file has something to
    # read, and say so plainly.
    log "WARNING: $ENV_FILE not found — without HF_TOKEN=<your Hugging Face token, with the Llama Prompt Guard 2 gated license accepted> in that file the guards-unified service cannot start (it loads the injection model at startup), so PII and injection detection are unavailable; secret detection continues through the local fallback. This cannot be automated. Creating the file empty (0600); add a real token and re-run self-heal or restart the container."
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
  reconcile_port_8700

  # Captured BEFORE the pull below, from whatever's already running --
  # empty on a fresh install (nothing running yet), which is correct:
  # a first-ever start isn't "an update" worth flagging the same way a
  # real version change is.
  local old_version
  old_version="$(curl -sS -m 3 "http://127.0.0.1:8700/about" 2>/dev/null | jq -r '.version // empty' 2>/dev/null)"

  # `docker compose up -d` alone never checks the registry for a newer
  # image -- it just reuses whatever's cached locally under this tag,
  # silently, forever. Confirmed by testing this gap directly: a
  # machine's guards-unified could be several fixes behind what's
  # actually published and this script would never know, since `up`
  # was never telling it to look. `timeout` bounds this so a slow or
  # unreachable registry can't hang SessionStart -- failure here is
  # non-fatal, same fail-open posture as everything else that isn't
  # the detection result itself: proceed with whatever's cached rather
  # than block the session.
  #
  # 15s was never enough and this isn't theoretical: reproduced it
  # directly (2026-10-19) against a real v0.1.1 publish -- guards-
  # unified:cpu is 3.43GB, and a Dockerfile change early in the layer
  # chain (e.g. an `apt-get upgrade`) invalidates the cache for every
  # layer after it, turning what should be a small diff into a near-
  # full re-pull. 15s killed the pull mid-download of a single ~700MB
  # layer; the script logged its warning and silently kept serving a
  # stale, vulnerable image. Raised to 240s -- still bounded (an
  # unreachable registry fails in seconds either way, not minutes),
  # but long enough for a real update on an ordinary connection. Keep
  # this in sync with hooks.json's SessionStart timeout, which must
  # stay ahead of this value plus `up -d` and the health curl below.
  if ! timeout 240 docker compose -f "$COMPOSE_FILE" pull 2>&1 | while read -r line; do log "$line"; done; then
    log "WARNING: docker compose pull failed or timed out — proceeding with whatever image is already cached locally (may be stale)."
  fi

  log "Ensuring guards-unified is up ($COMPOSE_FILE)..."
  if ! docker compose -f "$COMPOSE_FILE" up -d 2>&1 | while read -r line; do log "$line"; done; then
    log "WARNING: docker compose up failed — guard stages will fail open until this is fixed manually (try: docker compose -f $COMPOSE_FILE up -d)."
    return 1
  fi

  # Polls, doesn't single-shot -- confirmed by testing (2026-10-19)
  # that a single 3s check isn't enough: FastAPI's lifespan loads the
  # injection model BEFORE the ASGI server accepts any connections at
  # all, including /health, so a cold start (exactly when an image
  # actually changed, which is exactly when this note matters most)
  # routinely takes longer than 3s. Bounded at 30s total so a genuinely
  # failed start still reaches the existing warning below in
  # reasonable time, not the full 240s pull budget's worth of waiting.
  local waited=0 healthy=""
  while [ "$waited" -lt 30 ]; do
    if curl -sS -m 3 "http://127.0.0.1:8700/health" >/dev/null 2>&1; then
      healthy=1
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done

  if [ -z "$healthy" ]; then
    log "WARNING: guards-unified not answering on 127.0.0.1:8700/health yet — it may still be starting (model load takes longer on first run), or it failed to start. Check: docker compose -f $COMPOSE_FILE logs guards-unified"
  else
    local new_version
    new_version="$(curl -sS -m 3 "http://127.0.0.1:8700/about" 2>/dev/null | jq -r '.version // empty' 2>/dev/null)"
    if [ -n "$old_version" ] && [ -n "$new_version" ] && [ "$old_version" != "$new_version" ]; then
      IMAGE_UPDATE_NOTE="guards-unified was just updated from version ${old_version} to ${new_version} as part of this session starting (self-heal pulls on every SessionStart)."
    fi
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
  # ensure_docker_stack has no mutual-exclusion primitive of its own
  # (migrate_from_previous_architecture + reconcile_port_8700 + docker
  # compose up all act on shared Docker state), and this script runs
  # unconditionally on every SessionStart -- two Claude Code windows
  # starting at the same moment can both decide :8700 needs
  # reconciling and both act on it concurrently. This is the exact
  # mechanism behind a real incident this session (a deliberate
  # concurrency test raced this function against itself); it's
  # reachable from ordinary concurrent use too, not just a test.
  #
  # flock around the whole call: a second concurrent session start
  # waits for the first to finish instead of racing it. Bounded wait
  # (60s, generous relative to a normal run's few seconds) rather than
  # unbounded, consistent with this script's own fail-open posture
  # elsewhere -- a stuck lock-holder must not be able to block every
  # future session start forever.
  if command -v flock >/dev/null 2>&1; then
    GUARDS_SELFHEAL_LOCK="$HOME/.local/share/gramatr-guards/selfheal.lock"
    mkdir -p "$(dirname "$GUARDS_SELFHEAL_LOCK")" 2>/dev/null
    exec 9>"$GUARDS_SELFHEAL_LOCK"
    if ! flock -w 60 9; then
      log "WARNING: couldn't acquire the self-heal lock within 60s (another session-start may be running long, or stuck) -- proceeding without it rather than blocking this session indefinitely. If guards-unified ends up in a bad state, re-run this script."
    fi
  else
    # flock is util-linux, not available on macOS by default -- fail
    # open on locking the same way the rest of this script fails open
    # on everything else that isn't the detection result itself.
    log "WARNING: flock not found on PATH -- running without the concurrency lock. Install util-linux's flock for protection against concurrent SessionStart races."
  fi
  ensure_docker_stack
  command -v flock >/dev/null 2>&1 && flock -u 9 2>/dev/null
else
  fallback_non_docker
fi

# Factual statements, not imperative instructions — additionalContext
# feeds back into the model's own context, and imperative phrasing
# there is exactly the shape a prompt-injection defense watches for.
# This hook has no business tripping that itself (same reasoning as
# userpromptsubmit-guard.sh's own additionalContext). Combines both
# notes into one so a session with both an image update AND a plugin
# update pending doesn't need two separate reminders.
if [ -n "$IMAGE_UPDATE_NOTE" ] || [ -n "$PLUGIN_UPDATE_NOTE" ]; then
  if command -v jq >/dev/null 2>&1; then
    combined="$(printf '%s %s' "$IMAGE_UPDATE_NOTE" "$PLUGIN_UPDATE_NOTE" | sed 's/^ *//;s/ *$//')"
    jq -n --arg ctx "$combined" '{
      hookSpecificOutput: {
        hookEventName: "SessionStart",
        additionalContext: $ctx
      }
    }'
  else
    log "$IMAGE_UPDATE_NOTE $PLUGIN_UPDATE_NOTE"
  fi
fi

exit 0
