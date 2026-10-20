#!/usr/bin/env bash
# guards/hooks/outbound-lib.sh -- sourced by the outbound command guard; not run directly.
#
# WHY: a Bash command that sends a credential store to the network (a file
# operand of curl, an env dump piped to nc, a literal token in a header) never
# shows up as tool output, so the output guards cannot see it. This library
# turns the command TEXT into value-free records that a classifier can judge.
# It decides nothing and prints no header, body or token text: see the record
# list at the top of outbound-tok.awk. No hook uses it yet (hooks.json is
# unchanged); guards/tests/outbound-parse.test.sh exercises it.
#
# Needs: a POSIX awk. AWKBIN picks the one to run (default `awk`).
# Provides: outbound_parse (command text on stdin, records on stdout).
# Fail-safe: it exits 0 on any input. If awk is missing or dies it prints a
# single `X awk-failed` record, so a caller can treat "cannot parse" as such
# instead of as "nothing to report".

OUTBOUND_TOK_AWK="${OUTBOUND_TOK_AWK:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/outbound-tok.awk}"

outbound_parse() {
  # Sink stderr: an awk that cannot parse the program must not leak program text to the hook output.
  local out rc
  # shellcheck disable=SC2086 # AWKBIN may carry an argument, e.g. "busybox awk"
  out="$(${AWKBIN:-awk} -f "$OUTBOUND_TOK_AWK" 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'X\tawk-failed\n'
    return 0
  fi
  [ -z "$out" ] || printf '%s\n' "$out"
  return 0
}
