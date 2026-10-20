#!/usr/bin/env bash
# guards/hooks/deadline-lib.sh — sourced by the hooks; not run directly.
#
# WHY: Claude Code fails OPEN when a command hook outlives its `timeout` in
# hooks.json: it kills the hook and carries on as if the hook did not exist, so
# a denied publish goes through and an unredacted result reaches the model (see
# docs/HOOKS.md). Every hook therefore enforces its OWN, shorter deadline and
# decides what to do when it expires, instead of leaving that to Claude Code.
#
# HOW: guards_deadline KIND SECONDS, called once near the top of a hook, re-runs
# the hook (`bash $0`, same stdin) under a deadline. The re-run is the "inner"
# hook; the first run is the "outer" one and never scans anything itself. The
# outer run then maps what the inner run did to a DELIBERATE outcome:
#
#   inner exit 0 or 2   its stdout and stderr are passed through unchanged
#   deadline expired    the KIND's expiry outcome (below). An inner exit of 124
#                       means the inner hook noticed its own budget ran out.
#   anything else       a crash (jq failure, set -u, signal ...) also gets the
#                       KIND's outcome: an exit status other than 0 or 2 is
#                       treated as no hook at all by Claude Code, i.e. fail-open.
#                       Partial output of a crashed or killed inner run is dropped.
#
# KINDs:
#   deny      PreToolUse: a deny decision with an actionable reason.
#   withhold-bash  PostToolUse on Bash: the output is replaced with a notice.
#   withhold-mcp   PostToolUse on MCP: same, in the shape of the result
#                  (nothing is changed for shapes the hook never scans).
#   silent    advisory hook: no decision, a line on stderr.
#
# The inner run is bounded with `timeout` when present, otherwise with a small
# watchdog in pure bash (macOS has no `timeout` by default).

GUARDS_DEADLINE_INNER="${GUARDS_DEADLINE_INNER:-}"

# gd_outcome KIND SECS WHY RAWFILE -- print the expiry outcome and return.
gd_outcome() {
  local kind="$1" secs="$2" why="$3" raw="$4" name msg
  name="$(basename "${GD_SCRIPT:-hook}" .sh)"
  echo "guards ${name}: ${why} (internal deadline ${secs} s); applying the ${kind} outcome" >&2
  case "$kind" in
    deny)
      msg="Blocked by guards ${name}: ${why}, so this call could not be checked and is denied (fail-closed: Claude Code would otherwise have let it through unchecked). Retry the call. If it keeps happening, check that the guards-unified service answers on GUARDS_ENDPOINT (docs/HOOKS.md lists the deadlines and what each hook does on expiry)."
      printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$msg"
      ;;
    withhold-bash)
      msg="guards ${name}: the output of this command was withheld because ${why}, so it could not be checked for secrets before the model saw it. Run the command again; for large output, redirect it to a file and look at the part you need."
      if command -v jq >/dev/null 2>&1 && [ -s "$raw" ]; then
        jq -c --arg n "$msg" '{hookSpecificOutput: {hookEventName: "PostToolUse", updatedToolOutput: {stdout: $n, stderr: "", interrupted: (.tool_response.interrupted // false), isImage: false}}}' < "$raw" 2>/dev/null && return 0
      fi
      printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"stdout":"%s","stderr":"","interrupted":false,"isImage":false}}}\n' "$msg"
      ;;
    withhold-mcp)
      msg="guards ${name}: the result of this tool call was withheld because ${why}, so it could not be checked for secrets before the model saw it. Call the tool again."
      if ! command -v jq >/dev/null 2>&1; then
        # No jq to match the result's shape: the usual array of text blocks.
        printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":[{"type":"text","text":"%s"}]}}\n' "$msg"
        return 0
      fi
      [ -s "$raw" ] || return 0
      jq -c --arg n "$msg" '
        .tool_response as $r
        | ([{type: "text", text: $n}]) as $blocks
        | (if ($r | type) == "array" then $blocks
           elif ($r | type) == "string" then $n
           elif (($r | type) == "object" and ($r.content | type) == "array") then ($r | .content = $blocks)
           else null end) as $new
        | if $new == null then empty
          else {hookSpecificOutput: {hookEventName: "PostToolUse", updatedToolOutput: $new}} end' < "$raw" 2>/dev/null
      ;;
    silent) ;;
  esac
  return 0
}

# gd_bounded SECS IN OUT ERR SCRIPT -- run `bash SCRIPT` with stdin from IN.
# Returns its exit status, or 124 when the deadline expired.
gd_bounded() {
  local secs="$1" in="$2" out="$3" err="$4" script="$5" pid wd rc flag
  flag="$out.expired"
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 1 "$secs" bash "$script" < "$in" > "$out" 2> "$err"
    rc=$?
    case "$rc" in 124|137|143) return 124 ;; esac
    return "$rc"
  fi
  bash "$script" < "$in" > "$out" 2> "$err" &
  pid=$!
  # The watchdog does nothing if the run already finished (kill -0 fails):
  # without that check, the cleanup below killing its `sleep` let it fall
  # through to the next line and plant the expiry flag, so a run that
  # finished in time was reported as a timeout (a random deny on stock macOS,
  # which has no `timeout`).
  ( sleep "$secs"; kill -0 "$pid" 2>/dev/null || exit 0
    : > "$flag"
    command -v pkill >/dev/null 2>&1 && pkill -TERM -P "$pid" 2>/dev/null
    kill -TERM "$pid" 2>/dev/null; sleep 1
    command -v pkill >/dev/null 2>&1 && pkill -KILL -P "$pid" 2>/dev/null
    kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  wd=$!
  wait "$pid" 2>/dev/null; rc=$?
  kill "$wd" 2>/dev/null
  command -v pkill >/dev/null 2>&1 && pkill -P "$wd" 2>/dev/null
  [ -e "$flag" ] && return 124
  return "$rc"
}

# guards_deadline KIND SECONDS -- see the header. Returns only in the inner run.
guards_deadline() {
  [ -n "$GUARDS_DEADLINE_INNER" ] && return 0
  local kind="$1" secs="$2" w rc why
  GD_SCRIPT="${BASH_SOURCE[1]}"
  export GUARDS_DEADLINE_INNER=1
  if ! w="$(mktemp -d 2>/dev/null)"; then
    gd_outcome "$kind" "$secs" "the hook could not create a temp directory" /dev/null
    exit 0
  fi
  # shellcheck disable=SC2064  # expand $w now
  trap "rm -rf '$w'" EXIT
  cat > "$w/in" 2>/dev/null
  gd_bounded "$secs" "$w/in" "$w/out" "$w/err" "$GD_SCRIPT"
  rc=$?
  case "$rc" in
    0|2)
      cat "$w/out"; cat "$w/err" >&2
      exit "$rc" ;;
    124) why="the scan did not finish in time" ;;
    *)   why="the hook crashed (exit status ${rc})" ;;
  esac
  gd_outcome "$kind" "$secs" "$why" "$w/in"
  exit 0
}
