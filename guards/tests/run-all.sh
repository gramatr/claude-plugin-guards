#!/usr/bin/env bash
# guards/tests/run-all.sh — run every test the way CI will, before pushing.
#
# The recurring mistake this exists to stop: a test passes on a developer
# machine that has gitleaks installed and fails in CI, which does not. So every
# suite runs with gitleaks hidden from PATH (what the CI jobs see), and the
# suites that can use it run a second time with it.
#
#   bash guards/tests/run-all.sh      # exit non-zero on any failure

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/../.." || exit 1

SHADOW="$(mktemp -d)"
OUT="$(mktemp)"
trap 'rm -rf "$SHADOW" "$OUT"' EXIT
for d in /usr/local/bin /usr/bin; do
  for f in "$d"/*; do
    n="$(basename "$f")"
    [ "$n" = gitleaks ] && continue
    [ -e "$SHADOW/$n" ] || ln -s "$f" "$SHADOW/$n" 2>/dev/null
  done
done

fail=0
step() { # step LABEL CMD...
  local label="$1"; shift
  if "$@" >"$OUT" 2>&1; then
    printf '  ok    %-26s %s\n' "$label" "$(tail -1 "$OUT")"
  else
    printf '  FAIL  %s\n' "$label"; sed 's/^/        /' "$OUT" | tail -15; fail=1
  fi
}

SUITES=(credfile-guard publish-guard fast-secret-scan combined-hook mcp-output-guard scan-redaction scan-sh-drift dockerfile-go-drift deny-messages
        sendmessage-guard userpromptsubmit-guard guards-selfheal gitleaks-install
        cred-use-registry credfile-battery
        credclass-lib credfile-diff deadline-fallback realpath-lib outbound-guard scan-bash-compat docs-consistency glob-order build-pins guards-switch workflow-timeouts hook-deadlines-bounded approvals-report tag-version-check)
# The degraded-service suites (own line: this list is appended to by every change).
SUITES+=(degrade-lib degrade-note)

# The MCP server test is Python and needs `mcp>=2` and `httpx`. Point
# GUARDS_TEST_PYTHON at an interpreter that has them (CI installs them with
# pip); without them it prints a skip locally and fails under CI=true.
PY="${GUARDS_TEST_PYTHON:-python3}"

# The ruff CI installs is pinned in ci.yml, and a different version flags different things (0.6.9 here passed what 0.17.1
# rejected). Use the pinned one through uvx when it is available; fall back to a local ruff and say which version ran.
RUFF_PIN="$(grep -oE 'ruff==[0-9][0-9.]*' .github/workflows/ci.yml | head -1)"
RUFF=()
if [ -n "$RUFF_PIN" ] && command -v uvx >/dev/null 2>&1; then
  RUFF=(uvx --from "$RUFF_PIN" ruff)
elif command -v ruff >/dev/null 2>&1; then
  RUFF=(ruff)
  echo "note: local ruff $(ruff --version | awk '{print $2}') is not CI's ${RUFF_PIN:-pin}; install uv to run the pinned one"
fi
if [ "${#RUFF[@]}" -gt 0 ]; then
  echo "ruff"
  step "ruff check" "${RUFF[@]}" check .
  step "ruff format" "${RUFF[@]}" format --check .
fi

# CI installs shellcheck from apt on the runner image, whose version moves (0.11 flagged two old lines an older
# one let through). A pip build of 0.11 through uvx is used when available, so the local answer matches CI's.
SHELLCHECK=()
if command -v uvx >/dev/null 2>&1; then
  SHELLCHECK=(uvx --from shellcheck-py==0.11.0.1 shellcheck)
elif command -v shellcheck >/dev/null 2>&1; then
  SHELLCHECK=(shellcheck)
  echo "note: local shellcheck $(shellcheck --version | sed -n 2p | awk '{print $2}') may be older than CI's; install uv to run 0.11"
fi
if [ "${#SHELLCHECK[@]}" -gt 0 ]; then
  echo "lint"
  step "shellcheck" "${SHELLCHECK[@]}" -S warning -x guards/hooks/*.sh guards/bin/*.sh guards/tests/*.sh guards/vendor/secret-guard-core/scan.sh
fi

echo "without gitleaks (as CI sees it)"
for s in "${SUITES[@]}"; do
  step "$s" env "PATH=$SHADOW" bash "guards/tests/$s.test.sh"
done

echo "without jq"
step "no-jq" bash guards/tests/no-jq.test.sh
step "outbound-parse" bash guards/tests/outbound-parse.test.sh

echo "MCP server (HTTP client stubbed)"
step "mcp-server" "$PY" guards/tests/mcp-server.test.py
# The agent tools run the real publish-guard and scan.sh: once as CI sees it (no gitleaks), once with.
step "mcp-tools" env "PATH=$SHADOW" "$PY" -W ignore guards/tests/mcp-tools.test.py

if command -v gitleaks >/dev/null 2>&1; then
  echo "with gitleaks"
  step "mcp-tools" "$PY" -W ignore guards/tests/mcp-tools.test.py
  for s in "${SUITES[@]}"; do
    step "$s" bash "guards/tests/$s.test.sh"
  done
fi

# Hang-stub tests with real wall-clock waits (about 40 s, cases in parallel):
# once, not per PATH variant.
echo "hook deadlines"
step "hook-deadlines" bash guards/tests/hook-deadlines.test.sh
step "outbound-safeforms" bash guards/tests/outbound-safeforms.test.sh

# The cve-scan CI job runs scan-redaction INSIDE the vendored scan image, where
# paths and users differ from this machine (a $HOME-based test passed here and
# failed there). Mirror that when docker is available.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "inside the scan image (as the cve-scan CI job)"
  if docker build -q -t secret-guard-core:run-all guards/vendor/secret-guard-core >/dev/null 2>&1; then
    step "scan-redaction (SCAN_IMAGE)" env SCAN_IMAGE=secret-guard-core:run-all bash guards/tests/scan-redaction.test.sh
  else
    echo "  skip  could not build the scan image"
  fi
fi

[ "$fail" -eq 0 ] && echo "ALL OK" || echo "FAILURES"
exit "$fail"
