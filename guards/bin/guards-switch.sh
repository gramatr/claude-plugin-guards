#!/usr/bin/env bash
# guards/bin/guards-switch.sh -- turn every guards hook off for a while, and back on (coordination#133).
#
#   guards-switch off [TIME]   hooks do nothing until TIME has passed (default 60m; 30m, 2h, 90 = minutes; at most 24h)
#   guards-switch on           hooks work again now
#   guards-switch status       say whether they are on, and for how much longer if off
#
# Run it yourself in the Claude Code session with the ! prefix (it runs without the hooks), for example
#   ! guards-switch off 30m
# publish-guard refuses an agent that tries to run it. It takes effect at once, with no restart, and it turns itself
# back on when the time is up. While it is off NOTHING is scanned or redacted: a secret in tool output stays in the
# transcript, and a commit, issue or PR body is not checked. Use it to get past a block you have judged a false
# positive, and run `guards-switch on` when you are done.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=guards/hooks/disable-lib.sh
. "$HERE/../hooks/disable-lib.sh"

MAX_MIN=1440
DEFAULT_MIN=60

# parse_minutes TIME -> minutes on stdout, or non-zero. 30m, 2h, 1d, or a bare number of minutes.
parse_minutes() {
  local t="$1" n unit
  [[ "$t" =~ ^([0-9]+)([mhd]?)$ ]] || return 1
  n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]:-m}"
  case "$unit" in m) printf '%s\n' "$n" ;; h) printf '%s\n' $((n * 60)) ;; d) printf '%s\n' $((n * 1440)) ;; esac
}

stamp() { date -d "@$1" '+%H:%M' 2> /dev/null || date -r "$1" '+%H:%M' 2> /dev/null || printf '%s' "$1"; }

case "${1:-status}" in
  off)
    mins="$DEFAULT_MIN"
    if [ -n "${2:-}" ]; then
      mins="$(parse_minutes "$2")" || { echo "guards-switch: '$2' is not a time. Use 30m, 2h or a number of minutes." >&2; exit 2; }
    fi
    if [ "$mins" -lt 1 ] || [ "$mins" -gt "$MAX_MIN" ]; then
      echo "guards-switch: choose between 1 minute and 24 hours (it turns itself back on; run it again to extend)." >&2; exit 2
    fi
    mkdir -p "$GUARDS_SWITCH_DIR" 2> /dev/null && chmod 700 "$GUARDS_SWITCH_DIR" 2> /dev/null
    until=$(( $(date +%s) + mins * 60 ))
    printf '%s\n' "$until" > "$GUARDS_SWITCH_FILE" 2> /dev/null && chmod 600 "$GUARDS_SWITCH_FILE" 2> /dev/null \
      || { echo "guards-switch: cannot write $GUARDS_SWITCH_FILE" >&2; exit 1; }
    echo "Guards are OFF until $(stamp "$until") ($mins minutes). Nothing is scanned, redacted, denied or asked in the meantime."
    echo "Turn them back on sooner with: guards-switch on"
    ;;
  on)
    rm -f -- "$GUARDS_SWITCH_FILE"
    if [ "${GUARDS_DISABLE:-0}" = "1" ]; then
      echo "Guards switch is on, but GUARDS_DISABLE=1 is set in this environment, which keeps them off for the whole session. Unset it and restart."
    else
      echo "Guards are ON."
    fi
    ;;
  status)
    if [ "${GUARDS_DISABLE:-0}" = "1" ]; then echo "Guards are OFF for this whole session (GUARDS_DISABLE=1)."; exit 0; fi
    u="$(guards_disabled_until)"
    if [ -n "$u" ]; then echo "Guards are OFF until $(stamp "$u") ($(( (u - $(date +%s) + 59) / 60 )) minutes left)."; else echo "Guards are ON."; fi
    ;;
  install-launcher)
    # Used by the SessionStart self-heal: put a short `guards-switch` on PATH that runs the newest installed copy. Only
    # when ~/.local/bin exists and the name is free or already ours; never overwrites anything else.
    bin="$HOME/.local/bin"; target="$bin/guards-switch"
    [ -d "$bin" ] || exit 0
    if [ -e "$target" ] && ! grep -q "written by the guards plugin" "$target" 2> /dev/null; then exit 0; fi
    tmp="$(mktemp "$bin/.guards-switch.XXXXXX" 2> /dev/null)" || exit 0
    cat > "$tmp" << 'LAUNCHER'
#!/usr/bin/env bash
# guards-switch: written by the guards plugin's self-heal; runs the newest installed bin/guards-switch.sh.
d="$(ls -dt "$HOME"/.claude/plugins/cache/*/guards/*/bin/guards-switch.sh 2> /dev/null | head -n1)"
[ -n "$d" ] || { echo "guards-switch: the guards plugin is not installed" >&2; exit 1; }
exec bash "$d" "$@"
LAUNCHER
    chmod +x "$tmp" && mv -f "$tmp" "$target" 2> /dev/null || rm -f "$tmp"
    ;;
  -h | --help | help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) echo "usage: guards-switch off [TIME] | on | status   (see --help)" >&2; exit 2 ;;
esac
