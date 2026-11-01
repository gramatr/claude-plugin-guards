#!/usr/bin/env bash
# Fail if a job in a workflow file has no timeout-minutes. The GitHub default is
# 360 minutes, so a hung step holds a release or a PR for hours (a hook-deadlines
# test hung for 35 minutes on 2026-11-01 and blocked a release).
#   bash PATH/workflow-timeouts.sh [FILE...]   (default: .github/workflows/*.yml)
set -uo pipefail
[ "$#" -gt 0 ] || set -- .github/workflows/*.yml
awk '
  FNR==1 { if (job != "" && !has) bad(); job=""; injobs=0 }
  /^jobs:[ \t]*$/ { injobs=1; next }
  injobs && /^[^ \t#]/ { if (job != "" && !has) bad(); job=""; injobs=0 }
  injobs && /^  [A-Za-z0-9_-]+:[ \t]*$/ { if (job != "" && !has) bad(); job=$1; sub(/:$/,"",job); has=0; file=FILENAME; next }
  injobs && /^    timeout-minutes:[ \t]*[0-9]+/ { has=1 }
  function bad() { printf "%s: job %s has no timeout-minutes\n", file, job; fails++ }
  END { if (job != "" && !has) bad(); exit fails ? 1 : 0 }
' "$@"
