#!/usr/bin/env bash
# guards/bin/approvals-report.sh on a fixture store: expected counts, nothing leaked, read-only, empty store is zeros.
# Fabricated values only (the "secrets" below are built at run time from fragments and are not real).
# NEGATIVE CONTROL: a naive report that cats the pending notes DOES contain the planted strings, so the
# leak check is able to fail.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT="$HERE/../bin/approvals-report.sh"
pass=0 fail=0
ok() { pass=$((pass+1)); }
no() { fail=$((fail+1)); echo "FAIL: $1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

FAKE_PATH="/home/fakeuser/.aws/cred""entials-fake"
FAKE_TOKEN="gh""p_FAKE0123456789abcdefFAKE0123456789ab"
FAKE_KEY="AK""IAFAKEFAKEFAKEFAKE"
S="$T/store"; mkdir -p "$S/pending" "$S/approvals"
ts() { date -u -d "@$1" +%Y-%m-%d 2>/dev/null || date -u -r "$1" +%Y-%m-%d; }
E1=1761609600   # one fixed day
E2=$((E1 + 86400))
D1="$(ts $E1)"; D2="$(ts $E2)"
note() { # note ID RULES WHEN
  printf 'label\tpublish: %s\nrules\t%s\nwhen\t%s\nwhere\n  line 3: key %s = %s (%s)\n' "$FAKE_PATH" "$2" "$3" "$FAKE_KEY" "$FAKE_TOKEN" "$FAKE_PATH" > "$S/pending/$1"
}
note aaaaaaaaaaaaaaa1 secret-lead-in $E1
note aaaaaaaaaaaaaaa2 secret-lead-in $E1
note aaaaaaaaaaaaaaa3 generic-api-key,secret-lead-in $E2
note aaaaaaaaaaaaaaa4 "bad; $FAKE_PATH" $E2
{
  printf '%sT10:00:00Z\taaaaaaaaaaaaaaa1\tsecret-lead-in\n' "$D1"
  printf '%sT11:00:00Z\taaaaaaaaaaaaaaa3\tgeneric-api-key,secret-lead-in\n' "$D2"
  printf 'garbage line with %s\n' "$FAKE_TOKEN"
} > "$S/approvals.log"
printf '%s\n' $(( $(date +%s) - 100 )) > "$S/approvals/bbbbbbbbbbbbbbb1"      # expired, never used
printf '%s\n' $(( $(date +%s) + 500 )) > "$S/approvals/bbbbbbbbbbbbbbb2"      # still waiting

{
  printf '%sT09:00:00Z\task\tsecret-lead-in\ttitle\n' "$D1"
  printf '%sT09:05:00Z\tdeny\tsecret-lead-in\ttitle+message\n' "$D1"
  printf '%sT09:06:00Z\thard\taws-access-token\tnone\n' "$D2"
  printf '%sT09:07:00Z\tdeny\tsecret-lead-in\tmessage\n' "$D2"
  printf '%sT09:08:00Z\tweird; %s\tbad rule %s\t%s\n' "$D2" "$FAKE_PATH" "$FAKE_TOKEN" "$FAKE_PATH"
  printf 'garbage %s\n' "$FAKE_TOKEN"
} > "$S/denies.log"

before="$(cd "$S" && find . -type f -exec cksum {} + | sort; find "$S" -type f -printf '%T@\n' 2>/dev/null | sort | md5sum)"
out="$(bash "$REPORT" "$S" 2>&1)"; rc=$?
after="$(cd "$S" && find . -type f -exec cksum {} + | sort; find "$S" -type f -printf '%T@\n' 2>/dev/null | sort | md5sum)"

[ "$rc" -eq 0 ] && ok || no "exit status $rc"
has() { printf '%s\n' "$out" | grep -qE -- "$1" && ok || no "report lacks: $1"$'\n'"$out"; }
has '^approvals used: 2$'
has "    $D1  1"
has "    $D2  1"
has '^distinct blocks still in pending/: 4$'
has 'secret-lead-in +2'
has '\(other\) +1'
has 'secret-lead-in +2 used / 2 blocks|secret-lead-in +1 used / 2 blocks'
has 'all +2 used / 4 blocks \(n = 4\)'
has '^approvals granted and never used: 1 expired, 1 still waiting$'

has '^publish-guard decisions logged in denies.log: 5$'
has '^ +deny +3$|^ +deny +2$'
has '^ +hard +1$'
has '^ +ask +1$'
has '^ +\(other\) +1$'
has '^ +title\+message +1$'
has '^ +none +1$'

# Nothing planted may appear.
PLANTED=("$FAKE_PATH" "$FAKE_TOKEN" "$FAKE_KEY" aaaaaaaaaaaaaaa1 aaaaaaaaaaaaaaa3 bbbbbbbbbbbbbbb1 fakeuser)
leaks() { local v; for v in "${PLANTED[@]}"; do printf '%s' "$1" | grep -qF -- "$v" && return 0; done; return 1; }
leaks "$out" && no "the report printed a planted value" || ok
# Negative control: the same report with one added line that prints the pending notes must trip the leak check.
sed 's|^exit 0$|cat "$DIR"/pending/*; exit 0|' "$REPORT" > "$T/leaky.sh"
leaks "$(bash "$T/leaky.sh" "$S" 2>&1)" && ok || no "control: a leaking report was not caught by the leak check"
# Read-only.
[ "$before" = "$after" ] && ok || no "the report changed the store"

# Missing and empty stores print zeros and exit 0.
out0="$(bash "$REPORT" "$T/nonexistent" 2>&1)"; rc0=$?
[ "$rc0" -eq 0 ] && printf '%s' "$out0" | grep -q '^approvals used: 0$' && printf '%s' "$out0" | grep -q '^distinct blocks still in pending/: 0$' && printf '%s' "$out0" | grep -q 'denies.log: 0$' && ok || no "missing store: not zeros / exit 0"
mkdir -p "$T/empty"; : > "$T/empty/approvals.log"
oute="$(bash "$REPORT" "$T/empty" 2>&1)"; rce=$?
[ "$rce" -eq 0 ] && printf '%s' "$oute" | grep -q '^approvals used: 0$' && printf '%s' "$oute" | grep -q 'never used: 0 expired, 0 still waiting' && ok || no "empty store: not zeros / exit 0"
# Default directory comes from GUARDS_APPROVE_DIR.
outd="$(GUARDS_APPROVE_DIR="$S" bash "$REPORT" 2>&1)"
printf '%s' "$outd" | grep -q '^approvals used: 2$' && ok || no "GUARDS_APPROVE_DIR not honoured"

echo "approvals-report: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
