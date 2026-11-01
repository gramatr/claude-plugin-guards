#!/usr/bin/env bash
# guards/bin/approvals-report.sh -- counts-only report on the approve-once store (coordination#119, process-friction P5).
#
#   bash approvals-report.sh            read $GUARDS_APPROVE_DIR (default: the plugin state directory)
#   bash approvals-report.sh DIR        read another store, e.g. a copy of one from a second machine
#
# READ-ONLY. It reads approvals.log (one line per approval used: time, id, rules), the pending/ notes (one per
# approvable block: only their `rules` and `when` lines) and the names and expiry of unused approvals/. It never
# opens the label or the `where` lines, never prints an id or any text, and only prints a rule name when it looks
# like one (letters, digits, comma, dash, underscore); anything else is counted under "(other)".
#
# denies.log (publish-guard, plugin#176: time, ask|deny|hard, rule, argument class) is counted per day, decision, rule
# and argument class; only fixed words are printed (anything else is counted under "(other)"). denies.log.1 (the file
# rotated past 1 MB) is not read.
#
# What it measures: how often the ambiguous-rule family blocks work that a person then waves through, and (denies.log)
# how often the publish guard asks, denies or hard-denies. What it cannot see: credential-file, outbound and
# sendmessage guard decisions, advisory notes, allowed calls, sessions, latency, and any other machine. Treat the numbers as one host's anecdote; n is printed beside every rate.
# pending/ is swept when a later pending note is written (older than a day), so take a snapshot daily and keep the
# counts, not the files. Approvals used within 60 s of expiry are not measurable: the log has no expiry time.

set -uo pipefail
DIR="${1:-${GUARDS_APPROVE_DIR:-${GUARDS_STATE_DIR:-$HOME/.local/share/gramatr-guards}}}"
LOG="$DIR/approvals.log"
NOW="$(date +%s)"

day_of() { # epoch -> UTC date; GNU date, then BSD date
  date -u -d "@$1" +%Y-%m-%d 2>/dev/null || date -u -r "$1" +%Y-%m-%d 2>/dev/null || echo unknown
}
clean_rules() { # a rule list that looks like one, else (other)
  if [[ "$1" =~ ^[A-Za-z0-9,_-]{1,120}$ ]]; then printf '%s' "$1"; else printf '(other)'; fi
}

# --- used: day <TAB> rules, from the log (the id column is dropped here) ------------------------------------
USED="$(mktemp)"; BLOCKS="$(mktemp)"; trap 'rm -f "$USED" "$BLOCKS"' EXIT
if [ -f "$LOG" ]; then
  while IFS=$'\t' read -r ts _id rules _rest; do
    [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] || continue
    printf '%s\t%s\n' "${ts%%T*}" "$(clean_rules "$rules")"
  done < "$LOG" > "$USED"
fi

# --- blocks: day <TAB> rules, from pending/ -----------------------------------------------------------------
if [ -d "$DIR/pending" ]; then
  for f in "$DIR"/pending/*; do
    [ -f "$f" ] || continue
    rules="$(sed -n 's/^rules\t//p' "$f" 2>/dev/null | head -n1)"
    when="$(sed -n 's/^when\t//p' "$f" 2>/dev/null | head -n1)"
    [[ "$when" =~ ^[0-9]+$ ]] || continue
    printf '%s\t%s\n' "$(day_of "$when")" "$(clean_rules "$rules")"
  done > "$BLOCKS"
fi

# --- denies.log: day <TAB> decision <TAB> rules <TAB> argclass ----------------------------------------------
DENIES="$(mktemp)"; trap 'rm -f "$USED" "$BLOCKS" "$DENIES"' EXIT
if [ -f "$DIR/denies.log" ]; then
  while IFS=$'\t' read -r ts dec rules cls _rest; do
    [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] || continue
    case "$dec" in ask|deny|hard) ;; *) dec='(other)' ;; esac
    case "$cls" in title|message|title+message|none) ;; *) cls='(other)' ;; esac
    printf '%s\t%s\t%s\t%s\n' "${ts%%T*}" "$dec" "$(clean_rules "$rules")" "$cls"
  done < "$DIR/denies.log" > "$DENIES"
fi

# --- unused approvals: expiry on the first line --------------------------------------------------------------
waiting=0; lapsed=0
if [ -d "$DIR/approvals" ]; then
  for f in "$DIR"/approvals/*; do
    [ -f "$f" ] || continue
    exp="$(head -n1 -- "$f" 2>/dev/null)"
    if [[ "$exp" =~ ^[0-9]+$ ]] && [ "$exp" -ge "$NOW" ]; then waiting=$((waiting + 1)); else lapsed=$((lapsed + 1)); fi
  done
fi

n_used="$(wc -l < "$USED" | tr -d ' ')"
n_blocks="$(wc -l < "$BLOCKS" | tr -d ' ')"
echo "approve-once store report (counts only; one host; ambiguous, approvable rules only)"
echo
echo "approvals used: $n_used"
if [ "$n_used" -gt 0 ]; then
  echo "  per day:"; cut -f1 "$USED" | sort | uniq -c | awk '{printf "    %s  %d\n", $2, $1}'
  echo "  per rule set:"; cut -f2 "$USED" | sort | uniq -c | sort -rn | awk '{printf "    %-40s %d\n", $2, $1}'
fi
echo
echo "distinct blocks still in pending/: $n_blocks"
if [ "$n_blocks" -gt 0 ]; then
  echo "  per day:"; cut -f1 "$BLOCKS" | sort | uniq -c | awk '{printf "    %s  %d\n", $2, $1}'
  echo "  per rule set:"; cut -f2 "$BLOCKS" | sort | uniq -c | sort -rn | awk '{printf "    %-40s %d\n", $2, $1}'
fi
echo
echo "approve rate (used / blocks), only over days pending/ still covers:"
if [ "$n_blocks" -gt 0 ]; then
  first="$(cut -f1 "$BLOCKS" | sort | head -n1)"
  # Same days only: a use before the earliest pending day has no block to compare with.
  awk -F'\t' -v first="$first" '
    NR == FNR { b[$2]++; tb++; next }
    $1 >= first { u[$2]++; tu++ }
    END {
      for (r in b) printf "    %-40s %d used / %d blocks\n", r, u[r] + 0, b[r]
      printf "    %-40s %d used / %d blocks (n = %d)\n", "all", tu + 0, tb, tb
    }' "$BLOCKS" "$USED" | sort
else
  echo "    none (no pending notes, so no rate)"
fi
echo
echo "approvals granted and never used: $lapsed expired, $waiting still waiting"
echo
n_den="$(wc -l < "$DENIES" | tr -d ' ')"
echo "publish-guard decisions logged in denies.log: $n_den"
if [ "$n_den" -gt 0 ]; then
  echo "  per day:"; cut -f1 "$DENIES" | sort | uniq -c | awk '{printf "    %s  %d\n", $2, $1}'
  echo "  per decision:"; cut -f2 "$DENIES" | sort | uniq -c | sort -rn | awk '{printf "    %-40s %d\n", $2, $1}'
  echo "  per rule:"; cut -f3 "$DENIES" | sort | uniq -c | sort -rn | awk '{printf "    %-40s %d\n", $2, $1}'
  echo "  per argument class:"; cut -f4 "$DENIES" | sort | uniq -c | sort -rn | awk '{printf "    %-40s %d\n", $2, $1}'
fi
echo
echo "limits: one store; only the publish guard's asks and denies are recorded (no other guard, no allowed call, no advisory note, no session); do not extrapolate."
exit 0
