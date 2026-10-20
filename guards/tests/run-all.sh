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

SUITES=(credfile-guard publish-guard fast-secret-scan combined-hook mcp-output-guard scan-redaction scan-sh-drift
        sendmessage-guard userpromptsubmit-guard guards-selfheal
        credclass-lib credfile-diff deadline-fallback)

# The MCP server test is Python and needs `mcp>=2` and `httpx`. Point
# GUARDS_TEST_PYTHON at an interpreter that has them (CI installs them with
# pip); without them it prints a skip locally and fails under CI=true.
PY="${GUARDS_TEST_PYTHON:-python3}"

if command -v ruff >/dev/null 2>&1; then
  echo "ruff"
  step "ruff check" ruff check .
  step "ruff format" ruff format --check .
fi

if command -v shellcheck >/dev/null 2>&1; then
  echo "lint"
  step "shellcheck" shellcheck -S warning -x guards/hooks/*.sh guards/bin/*.sh guards/tests/*.sh guards/vendor/secret-guard-core/scan.sh
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
