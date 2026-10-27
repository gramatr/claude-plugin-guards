#!/usr/bin/env bash
# guards/bin/guards-approve.sh -- the PERSON approves one blocked publish, once (coordination#124, part B).
#
#   bash guards-approve.sh ID        approve the block with this id (printed in the block message)
#   bash guards-approve.sh --list    show the blocks waiting for an answer
#
# Run it yourself in the Claude Code session with the ! prefix, which runs a command without going
# through the hooks. publish-guard refuses an agent that tries to run it. The approval is for the
# exact text that was blocked, is used up by the first retry, and expires after GUARDS_APPROVE_TTL
# seconds (default 600). Read what it prints: that is what you are approving.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=guards/hooks/approve-lib.sh
. "$HERE/../hooks/approve-lib.sh"

pending="$GUARDS_APPROVE_DIR/pending"

case "${1:-}" in
  --list)
    n=0
    for f in "$pending"/*; do
      [ -f "$f" ] || continue
      n=$((n + 1))
      id="$(basename "$f")"
      printf '%s  %s  (rules: %s)\n' "$id" "$(sed -n 's/^label\t//p' "$f" | head -n1)" "$(sed -n 's/^rules\t//p' "$f" | head -n1)"
    done
    [ "$n" -gt 0 ] || echo "No blocks are waiting for an answer."
    exit 0
    ;;
  ""|-h|--help)
    sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

id="$1"
if ! approve_valid_id "$id"; then
  echo "guards-approve: '$id' is not an approval id (16 lowercase hex characters, printed in the block message)." >&2
  exit 2
fi
if [ ! -f "$pending/$id" ]; then
  echo "guards-approve: no block with id $id is waiting. It may have expired or the text changed; ask for the action again to get a fresh id." >&2
  exit 1
fi

approve_mkdirs || { echo "guards-approve: cannot create $GUARDS_APPROVE_DIR" >&2; exit 1; }
echo "Approving once:"
sed -n 's/^label\t/  what:  /p;s/^rules\t/  rules: /p' "$pending/$id"
echo "  lines, as the scanner shows them (the values are never printed):"
sed -n '/^where$/,$p' "$pending/$id" | sed '1d;s/^/    /'
exp=$(( $(date +%s) + GUARDS_APPROVE_TTL ))
f="$GUARDS_APPROVE_DIR/approvals/$id"
printf '%s\n' "$exp" > "$f" && chmod 600 "$f"
echo "Approved for $((GUARDS_APPROVE_TTL / 60)) minutes, one use. Tell the agent to retry the identical command."
