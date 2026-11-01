#!/usr/bin/env bash
# Every workflow job must set timeout-minutes (the default is 360). Includes a
# negative control: a job without it must make the check fail.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/workflow-timeouts.sh"
cd "$HERE/.." || exit 1
case "$HERE" in */guards/tests) cd "$HERE/../.." || exit 1;; esac
pass=0; fail=0
ok() { pass=$((pass+1)); }
no() { fail=$((fail+1)); echo "FAIL: $1"; }

bash "$CHECK" && ok || no "a job in .github/workflows has no timeout-minutes"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf 'jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n' > "$T/bad.yml"
printf 'jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: true\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n' > "$T/bad2.yml"
printf 'jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: true\n' > "$T/good.yml"
bash "$CHECK" "$T/bad.yml" >/dev/null && no "negative control: job without timeout passed" || ok
bash "$CHECK" "$T/bad2.yml" >/dev/null && no "negative control: second job without timeout passed" || ok
bash "$CHECK" "$T/good.yml" >/dev/null && ok || no "a job with timeout-minutes failed"
echo "workflow-timeouts: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
