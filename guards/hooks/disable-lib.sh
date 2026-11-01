#!/usr/bin/env bash
# guards/hooks/disable-lib.sh -- the temporary off switch for every hook (coordination#133).
#
# WHY: when a guard blocks work and the person has no way through, the only choice was to uninstall the plugin. This
# turns every hook off for a while, from a command the PERSON runs (bin/guards-switch.sh off 30m, the ! prefix),
# and turns it back on by itself when the time is up, so protection cannot stay off by accident.
#
# HOW: a flag file under the state directory holds the time it stops being valid. Every hook script sources this
# file first and exits 0 when guards_disabled succeeds. Exiting 0 with no output means "allow" for a PreToolUse
# hook and "leave the output as it is" for a PostToolUse hook. An expired file is removed by the first hook that
# sees it. GUARDS_DISABLE=1 in the environment Claude Code started from does the same for a whole session.
#
# WHAT IT MEANS: while it is off nothing is scanned, redacted, denied or asked. Secrets in tool output are not
# redacted and a commit or issue body is not checked. publish-guard refuses an agent command that names the switch
# or the flag file, but like the approve-once store this is a text match: it stops an agent that is not trying to
# get around it, nothing more (docs/THREAT-MODEL.md).
#
# Sourced, not run.

GUARDS_SWITCH_DIR="${GUARDS_STATE_DIR:-$HOME/.local/share/gramatr-guards}"
GUARDS_SWITCH_FILE="$GUARDS_SWITCH_DIR/disabled"

# guards_disabled: succeeds while the guards are switched off. A file that cannot be read, or holds no number, counts
# as "on": a broken flag must never leave the guards off.
guards_disabled() {
  [ "${GUARDS_DISABLE:-0}" = "1" ] && return 0
  [ -f "$GUARDS_SWITCH_FILE" ] || return 1
  local until now
  until="$(head -n1 -- "$GUARDS_SWITCH_FILE" 2> /dev/null)"
  [[ "$until" =~ ^[0-9]+$ ]] || return 1
  now="$(date +%s)"
  if [ "$now" -lt "$until" ]; then return 0; fi
  rm -f -- "$GUARDS_SWITCH_FILE" 2> /dev/null   # time is up: the switch puts itself back on
  return 1
}

# guards_disabled_until: the epoch second the switch stops being valid, or nothing when it is on.
guards_disabled_until() {
  [ -f "$GUARDS_SWITCH_FILE" ] || return 0
  local until; until="$(head -n1 -- "$GUARDS_SWITCH_FILE" 2> /dev/null)"
  [[ "$until" =~ ^[0-9]+$ ]] && [ "$(date +%s)" -lt "$until" ] && printf '%s\n' "$until"
  return 0
}
