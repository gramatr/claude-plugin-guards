#!/usr/bin/env bash
# guards/tests/scan-sh-drift.test.sh — the drift check itself: identical files
# pass, a one-character difference fails, a header-only change passes. Runs
# against local copies, no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/scan-sh-drift.sh"
V="$HERE/../vendor/secret-guard-core/scan.sh"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
expect() { # expect WANT_EXIT LABEL SERVER_FILE [VENDORED_FILE]
  local want="$1" label="$2" srv="$3" ven="${4:-$V}" rc
  SERVER_SCAN_SH="$srv" VENDORED_SCAN_SH="$ven" bash "$CHECK" >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq "$want" ]; then pass=$((pass + 1)); printf '  ok    %s\n' "$label"
  else fail=$((fail + 1)); printf '  FAIL  %s (exit %s, want %s)\n' "$label" "$rc" "$want"; fi
}

# The server file is the vendored one without its two header lines.
{ sed -n 1p "$V"; sed 1,3d "$V"; } > "$W/server.sh"
expect 0 "identical apart from the header passes" "$W/server.sh"

# Negative control: one character changed on one line of the server copy.
sed '60s/./X/' "$W/server.sh" > "$W/server-one-char.sh"
cmp -s "$W/server.sh" "$W/server-one-char.sh" && { echo "  FAIL  test setup: mutation changed nothing"; exit 1; }
expect 1 "one-character difference in the server copy fails" "$W/server-one-char.sh"

# ... and the same character changed in the vendored copy instead.
sed '63s/./X/' "$V" > "$W/vendored-one-char.sh"
cmp -s "$V" "$W/vendored-one-char.sh" && { echo "  FAIL  test setup: mutation changed nothing"; exit 1; }
expect 1 "one-character difference in the vendored copy fails" "$W/server.sh" "$W/vendored-one-char.sh"

# A missing trailing newline is a difference too.
printf %s "$(cat "$W/server.sh")" > "$W/server-no-eol.sh"
expect 1 "missing final newline fails" "$W/server-no-eol.sh"

# A different header text is allowed.
{ sed -n 1p "$V"; echo "# other header line one"; echo "# other header line two"; sed 1,3d "$V"; } > "$W/vendored-header.sh"
expect 0 "a different two-line header passes" "$W/server.sh" "$W/vendored-header.sh"

# A non-comment in the header slot is rejected.
{ sed -n 1p "$V"; echo "# only comment"; echo "echo not-a-comment"; sed 1,3d "$V"; } > "$W/vendored-bad-header.sh"
expect 1 "a non-comment header line fails" "$W/server.sh" "$W/vendored-bad-header.sh"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "ALL OK"
exit "$fail"
