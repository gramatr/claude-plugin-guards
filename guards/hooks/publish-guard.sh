#!/usr/bin/env bash
# guards/hooks/publish-guard.sh — PreToolUse hook on Bash (and GitHub MCP
# write tools): BLOCKS commands that would publish credential material.
#
# WHY: a live secret key was quoted in the body of a public GitHub issue
# (the issue and its repository have since been deleted); nothing in the
# plugin looked at outbound text. Redaction after the fact cannot help once something is
# published, and GitHub push protection only knows vendor token formats
# and does not scan issue bodies at all.
#
# WHAT IT SCANS, when the command publishes something:
#   gh issue|pr|release|gist create|comment|edit|review
#   gh api with a body (-f/-F/--field/--raw-field/--input)
#   git commit  (the -m/-F message AND the staged diff's added lines)
# Scanned text is the full command (heredoc bodies included) PLUS the
# contents of files the command names (--body-file/-F/--notes-file/
# --input, `cat FILE`, gist files) -- otherwise `--body-file x.md` would
# be a trivial bypass. For GitHub MCP write tools the whole tool_input.
#
# HOW: the secret-only scan in secret-scan-lib.sh: the guards-unified
# service's secret-only route first (the PII and injection models are not
# involved), then the vendored scan.sh for the passes that need this
# process's environment. If the service is down, slow or too old, the full
# local scan.sh runs (gitleaks, the private-key pass and the context-aware
# pass), so a publish check never depends on the service being up.
#
# ON A FINDING: DENY (never silently redact: a mangled post still
# publishes and hides the mistake). The message names the rule IDs and says
# WHERE the match is (the command text, a named file, the staged diff with
# file and line), up to 5 places, each line shown as the scanner redacts it,
# so the key and context are visible and the value never is. It then says
# what to do: describe the SHAPE only, the marker rules, the override rules.
#
# FAIL CLOSED: if the scanner cannot run at all (script missing, crashed,
# timed out) the publish is denied. If only gitleaks is missing the pure
# bash passes still run; that degraded mode is allowed with a notice.
#
# MARKER: a line containing `guards:synthetic` is dropped from the added
# lines of the staged diff before scanning. It exists for deliberately fake
# test fixtures and makes the intent visible in review. Marked lines are still
# checked for a few sure-thing vendor shapes (see MARKED_FAMILIES). It does NOT apply to
# command text (so not a -m message), issue/PR bodies or files named by the
# command (--body-file, -F, cat).
#
# WHICH DIFF: the repository is found by following cd/pushd and `git -C` in
# order (quotes and ~ understood, relative paths resolved against the
# session's cwd), plus --git-dir/--work-tree/GIT_DIR/GIT_WORK_TREE. With
# -a/--all it is the tracked changes against HEAD. With `git add ... && git
# commit` in one command the add is replayed against a throwaway copy of the
# index (plain pathspecs only), because the real add has not run yet.
#
# OVERRIDE: GUARDS_ALLOW_PUBLISH_SECRETS=1 in the environment Claude Code
# started from, for a reviewed false positive. Deliberate and visible.
#
# LIMITS: only commands that name a publish verb are inspected; a script
# that publishes indirectly is not. Covers Claude Code sessions with the
# plugin, not the GitHub web UI or a terminal outside Claude Code. Will
# occasionally block a post that merely sits near a secret-ish key name.
#
# Never returns updatedInput, so it can coexist with other PreToolUse
# hooks (see sendmessage-guard.sh's header for why that matters).

set -uo pipefail

# Own deadline below the hook timeout in hooks.json: Claude Code fails open when
# a hook outlives it. Re-runs this script bounded; see deadline-lib.sh.
# shellcheck source=guards/hooks/deadline-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/deadline-lib.sh" && guards_deadline deny 25
# Local scan budgets inside that deadline (secret-scan-lib.sh).
export SS_LOCAL_TIMEOUT="${SS_LOCAL_TIMEOUT:-15}" SS_ENV_TIMEOUT="${SS_ENV_TIMEOUT:-4}"

[ "${GUARDS_ALLOW_PUBLISH_SECRETS:-0}" = "1" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_SCAN="${GUARDS_SECRET_SCAN:-$(dirname "$SCRIPT_DIR")/vendor/secret-guard-core/scan.sh}"
MAX_BYTES="${PUBLISH_GUARD_MAX_BYTES:-524288}"

RAW="$(cat)"
TOOL_NAME="$(printf '%s' "$RAW" | jq -r '.tool_name // ""' 2>/dev/null)" || exit 0
CWD="$(printf '%s' "$RAW" | jq -r '.cwd // ""' 2>/dev/null)"
PERM_MODE="$(printf '%s' "$RAW" | jq -r '.permission_mode // ""' 2>/dev/null)"
[ -n "$CWD" ] || CWD="$PWD"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SCAN_INPUT="$WORK/input.txt"
: > "$SCAN_INPUT"

deny() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

# ask: hand the decision to the HUMAN through Claude Code's built-in permission
# prompt. The agent cannot answer it, so it is not a bypass the agent can type
# for itself. What Claude Code does with an ask when no human is attached (a
# non-interactive run) is not something this plugin controls or has verified;
# set GUARDS_PUBLISH_ASK=0 / GUARDS_CRED_ASK=0 to make those runs hard blocks.
ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

notice() {
  jq -n --arg ctx "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", additionalContext: $ctx}}'
}

# Every line handed to the scanner is recorded in META with where it came from
# ("<label><TAB><line number in that source>"), one META line per scan-input
# line, so a finding can be reported as "the staged diff, file x, line 12".
META="$WORK/meta.txt"
: > "$META"
DIFF_CAPPED=0

emit_src() { # emit_src LABEL FILE -- append FILE's lines to the scan input and record their source
  local label="$1" f="$2"
  [ -s "$f" ] || return 0
  cat -- "$f" >> "$SCAN_INPUT"
  [ -z "$(tail -c1 -- "$f" 2>/dev/null)" ] || printf '\n' >> "$SCAN_INPUT"
  LC_ALL=C awk -v l="$label" '{ print l "\t" NR }' "$f" >> "$META"
}

append_file() { # append_file PATH -- readable regular files only, size capped
  local f="$1"
  [ -f "$f" ] && [ -r "$f" ] || return 0
  head -c "$MAX_BYTES" -- "$f" > "$WORK/named-file.tmp" 2>/dev/null
  emit_src "file $f (named by the command)" "$WORK/named-file.tmp"
}

# resolve_dir BASE ARG -- ARG as a directory (quotes and ~ handled, relative
# to BASE), printed absolute; fails if it is not one.
resolve_dir() {
  local base="$1" a="$2"
  a="${a#\"}"; a="${a%\"}"; a="${a#\'}"; a="${a%\'}"
  case "$a" in \~) a="$HOME" ;; \~/*) a="$HOME/${a:2}" ;; esac
  case "$a" in /*) ;; *) a="$base/$a" ;; esac
  [ -d "$a" ] && (cd "$a" 2>/dev/null && pwd -P)
}

# staged_diff_lines GITDIR GIT_ENV... -- DIFF_ARGS (global) selects what is
# diffed. Appends the added lines to the scan input, minus lines carrying the
# synthetic marker, with file path and new-file line number recorded in META.
# Stops at MAX_BYTES (DIFF_CAPPED=1 if it did).
staged_diff_lines() {
  local gitdir="$1"; shift
  env "$@" git -C "$gitdir" -c core.quotepath=false diff "${DIFF_ARGS[@]}" -U0 --no-color --no-ext-diff --no-textconv \
      --src-prefix=a/ --dst-prefix=b/ 2>/dev/null \
    | LC_ALL=C awk -v body="$SCAN_INPUT" -v meta="$META" -v max="$MAX_BYTES" -v capf="$WORK/capped" -v marked="$WORK/marked.txt" -v markedmeta="$WORK/marked.meta" '
        /^diff --git / { inhdr = 1; next }
        inhdr && /^\+\+\+ / { path = substr($0, 5); sub(/^b\//, "", path); next }
        /^@@ / { inhdr = 0; s = $0; sub(/^@@ [^+]*\+/, "", s); ln = s + 0; next }
        inhdr { next }
        /^\+/ {
          line = substr($0, 2)
          if (index(line, "guards:synthetic")) {
            # dropped from the context scan, but kept for the sure-thing check
            print line >> marked
            print "the staged diff, file " path "\t" ln >> markedmeta
            ln++; next
          }
          total += length(line) + 1
          if (total > max) { print "1" > capf; exit }
          print line >> body
          print "the staged diff, file " path "\t" ln >> meta
          ln++
        }'
  [ -e "$WORK/capped" ] && DIFF_CAPPED=1
  return 0
}

case "$TOOL_NAME" in
  Bash)
    CMD="$(printf '%s' "$RAW" | jq -r '.tool_input.command // ""' 2>/dev/null)"
    [ -n "$CMD" ] || exit 0

    PUBLISH_RE='(^|[^A-Za-z0-9_-])gh[[:space:]]+(issue|pr|release|gist)[[:space:]]+(create|comment|edit|review)([^A-Za-z0-9_-]|$)'
    API_RE='(^|[^A-Za-z0-9_-])gh[[:space:]]+api[[:space:]]'
    API_BODY_RE='(^|[[:space:]])(-f|-F|--field|--raw-field|--input)([[:space:]=]|$)'
    # git, then any global options (-C DIR, -c K=V, --no-pager, --git-dir=D, ...), then commit.
    COMMIT_RE='(^|[^A-Za-z0-9_-])git(([[:space:]]+(-C|-c)[[:space:]]+[^[:space:]]+)|([[:space:]]+--?[A-Za-z][A-Za-z-]*(=[^[:space:]]+)?))*[[:space:]]+commit([^A-Za-z0-9_-]|$)'

    # Quoted strings removed, newlines flattened: what is left is command
    # syntax only, so a flag-looking word inside a message is not a flag.
    NQ="$(printf '%s' "$CMD" | tr '\n' ' ' | sed -E "s/\"[^\"]*\"//g; s/'[^']*'//g")"
    CMDL="$(printf '%s' "$CMD" | tr '\n' ';')"

    IS_COMMIT=0
    if [[ "$CMD" =~ $PUBLISH_RE ]]; then
      :
    elif [[ "$CMD" =~ $API_RE ]] && [[ "$CMD" =~ $API_BODY_RE ]]; then
      :
    elif [[ "$CMD" =~ $COMMIT_RE ]]; then
      IS_COMMIT=1
    else
      exit 0
    fi

    printf '%s\n' "$CMD" > "$WORK/cmd.txt"
    if [ "$IS_COMMIT" -eq 1 ]; then
      emit_src "the command text (for a git commit this includes the -m message)" "$WORK/cmd.txt"
    else
      emit_src "the command text" "$WORK/cmd.txt"
    fi

    # Files the command names: --body-file X, -F X, --notes-file X,
    # --input X, `cat X`, plus gist file arguments.
    FILE_FLAG_RE='(--body-file|--notes-file|--input|-F|-f)[[:space:]=]+@?([^[:space:];|&)"'"'"']+)'
    CAT_RE='cat[[:space:]]+([^[:space:];|&)"'"'"'<>]+)'
    rest="$CMD"
    while [[ "$rest" =~ $FILE_FLAG_RE ]]; do
      f="${BASH_REMATCH[2]}"; m="${BASH_REMATCH[0]}"
      [[ "$f" == *=@* ]] && f="${f#*=@}"
      case "$f" in -|/dev/stdin) ;; *) [ -d "$CWD" ] && f="$(cd "$CWD" && realpath -m -- "$f" 2>/dev/null || printf '%s' "$f")"; append_file "$f" ;; esac
      rest="${rest#*"$m"}"
    done
    rest="$CMD"
    while [[ "$rest" =~ $CAT_RE ]]; do
      f="${BASH_REMATCH[1]}"; m="${BASH_REMATCH[0]}"
      [ -d "$CWD" ] && f="$(cd "$CWD" && realpath -m -- "$f" 2>/dev/null || printf '%s' "$f")"
      append_file "$f"
      rest="${rest#*"$m"}"
    done
    if [[ "$CMD" =~ gh[[:space:]]+gist[[:space:]]+create ]]; then
      for tok in $CMD; do
        case "$tok" in -*|gh|gist|create) continue ;; esac
        f="$tok"; [ -d "$CWD" ] && f="$(cd "$CWD" && realpath -m -- "$tok" 2>/dev/null || printf '%s' "$tok")"
        append_file "$f"
      done
    fi

    # git commit: the added lines of the staged diff (and of the working
    # tree for -a/--all), minus lines carrying the synthetic marker.
    if [ "$IS_COMMIT" -eq 1 ]; then
      # Which repository? Follow cd/pushd and git -C in order, each resolved
      # against the directory the previous one left us in (the session's cwd
      # to start with), quotes and ~ understood.
      GITDIR="$CWD"; CUR="$CWD"
      TOK='("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:];&|()<>]+)'
      NAV_RE='(^|[^A-Za-z0-9_./-])(cd|pushd)[[:space:]]+'"$TOK"'|(^|[^A-Za-z0-9_-])git[[:space:]]+-C[[:space:]]+'"$TOK"
      rest="$CMD"
      while [[ "$rest" =~ $NAV_RE ]]; do
        m="${BASH_REMATCH[0]}"
        if [ -n "${BASH_REMATCH[2]}" ]; then
          d="$(resolve_dir "$CUR" "${BASH_REMATCH[3]}")" && { CUR="$d"; GITDIR="$d"; }
        else
          d="$(resolve_dir "$CUR" "${BASH_REMATCH[5]}")" && GITDIR="$d"
        fi
        rest="${rest#*"$m"}"
      done
      GIT_ENV=(GUARDS_PUBLISH_GUARD=1)
      GD_RE='(--git-dir[=[:space:]]+|(^|[[:space:]])GIT_DIR=)'"$TOK"
      WT_RE='(--work-tree[=[:space:]]+|(^|[[:space:]])GIT_WORK_TREE=)'"$TOK"
      if [[ "$CMD" =~ $GD_RE ]]; then
        d="$(resolve_dir "$CUR" "${BASH_REMATCH[3]}")" && GIT_ENV+=("GIT_DIR=$d")
      fi
      if [[ "$CMD" =~ $WT_RE ]]; then
        d="$(resolve_dir "$CUR" "${BASH_REMATCH[3]}")" && GIT_ENV+=("GIT_WORK_TREE=$d")
      fi

      DIFF_ARGS=(--cached)
      COMMIT_TAIL=""
      if [[ "$NQ" =~ $COMMIT_RE ]]; then
        COMMIT_TAIL="${NQ#*"${BASH_REMATCH[0]}"}"; COMMIT_TAIL="${COMMIT_TAIL%%[;&|]*}"
      fi
      if [[ "$COMMIT_TAIL" =~ (^|[[:space:]])(-[A-Za-z]*a[A-Za-z]*|--all)([[:space:]]|$) ]]; then
        DIFF_ARGS=(HEAD)
      elif [[ "$CMDL" =~ (^|[^A-Za-z0-9_-])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+add([[:space:]]|$) ]]; then
        # `git add ... && git commit` in one command: the add has not run yet,
        # so the index the hook can see is stale (and may still hold an
        # unmarked version of a line the marker was just added to). Run the
        # same add against a throwaway copy of the index and diff that. Only
        # plain pathspecs and a few flags; anything else falls back to the
        # tracked changes against HEAD (a superset of what the add stages).
        ADD_ARGS_RE='git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+add[[:space:]]+([^;&|<>()$`\\"'"'"'*?[]*)([;&|)]|$)'
        DIFF_ARGS=(HEAD)
        if [[ "$CMDL" =~ $ADD_ARGS_RE ]] && [ -n "${BASH_REMATCH[2]// /}" ]; then
          read -r -a add_args <<< "${BASH_REMATCH[2]}"
          ok=1
          for a in "${add_args[@]}"; do
            [[ "$a" =~ ^(-A|-u|-f|-N|--all|--update|--force|--intent-to-add|--|\.|[A-Za-z0-9_./@+,=][A-Za-z0-9_./@+,=-]*)$ ]] || ok=0
          done
          idx="$(env "${GIT_ENV[@]}" git -C "$GITDIR" rev-parse --path-format=absolute --git-path index 2>/dev/null)"
          obj="$(env "${GIT_ENV[@]}" git -C "$GITDIR" rev-parse --path-format=absolute --git-path objects 2>/dev/null)"
          if [ "$ok" -eq 1 ] && [ "${#add_args[@]}" -gt 0 ] && [ -n "$idx" ] && [ -n "$obj" ]; then
            mkdir -p "$WORK/sim-objects"
            if { [ ! -e "$idx" ] || cp -- "$idx" "$WORK/sim-index"; } \
               && env "${GIT_ENV[@]}" GIT_INDEX_FILE="$WORK/sim-index" GIT_OBJECT_DIRECTORY="$WORK/sim-objects" \
                    GIT_ALTERNATE_OBJECT_DIRECTORIES="$obj" git -C "$GITDIR" add "${add_args[@]}" >/dev/null 2>&1; then
              DIFF_ARGS=(--cached)
              GIT_ENV+=("GIT_INDEX_FILE=$WORK/sim-index")
            fi
          fi
        fi
      fi
      staged_diff_lines "$GITDIR" "${GIT_ENV[@]}"
    fi
    LABEL="this command"
    ;;
  mcp__*)
    case "$TOOL_NAME" in
      *create*|*update*|*add_*|*comment*|*push*|*merge*|*review*|*edit*|*post*|*send*|*write*) ;;
      *) exit 0 ;;
    esac
    printf '%s' "$RAW" | jq -r '.tool_input | tostring' > "$WORK/mcp.txt" 2>/dev/null
    emit_src "the $TOOL_NAME input (JSON on one line)" "$WORK/mcp.txt"
    LABEL="this $TOOL_NAME call"
    ;;
  *) exit 0 ;;
esac

# A marked line is dropped from the scan above. The marker says "this line is a
# fake fixture", and nothing checks that. So every marked line is still held
# against a few sure-thing shapes: a private-key header, an AWS access key id, a
# GitHub, Slack, Stripe or OpenAI-style live key. A match is denied even though
# the line is marked. JWT-shaped, high-entropy and base64 values are NOT in this
# set (fake ones are a normal fixture). A matched token that contains EXAMPLE or
# FAKE (the documented AWS example ids, for one) is accepted.
MARKED_FAMILIES=(
  "private-key header|-----BEGIN [A-Z0-9 ]*PRIVATE KEY"
  "AWS access key id|(AKIA|ASIA)[A-Z0-9]{16}"
  "GitHub token|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
  "Slack token|xox[abprs]-[A-Za-z0-9-]{10,}"
  "Stripe or OpenAI live key|(sk|rk)_live_[A-Za-z0-9]{16,}|sk-proj-[A-Za-z0-9_-]{20,}"
)
marked_hits() { # marked_hits -> lines "family<TAB>where" (never the value)
  [ -s "$WORK/marked.txt" ] || return 0
  local fam name re n w
  for fam in "${MARKED_FAMILIES[@]}"; do
    name="${fam%%|*}"; re="${fam#*|}"
    LC_ALL=C grep -noE -- "$re" "$WORK/marked.txt" 2>/dev/null \
      | { if [ "$name" = "private-key header" ]; then cat; else grep -viE 'example|fake'; fi; } \
      | while IFS=: read -r n _; do
          w="$(sed -n "${n}p" "$WORK/marked.meta" | awk -F'\t' '{ print $1 ", line " $2 }')"
          printf '%s\t%s\n' "$name" "$w"
        done
  done
}
MARKED_HITS="$(marked_hits | sort -u | head -n 5)"
if [ -n "$MARKED_HITS" ]; then
  deny "Blocked by guards publish-guard: a line marked guards:synthetic looks like a REAL vendor credential or key. The marker means 'fake fixture' and is not checked for anything else, so private-key headers, AWS access key ids, GitHub, Slack, Stripe and OpenAI-style live keys are still denied on a marked line.

Where (the value is never printed):
$(printf '%s\n' "$MARKED_HITS" | awk -F'\t' '{ printf "  %d. %s: %s\n", NR, $2, $1 }')
What to do: build the fake value at run time in the test (do not write it into the file), or use an obviously fake form: the documented example ids (for example the AWS documentation key ids) or any value that contains the word EXAMPLE or FAKE. A JWT-shaped or ordinary fake fixture value is fine with the marker. If this really is a real credential, remove it, rotate it, and describe its shape only."
fi

[ -s "$SCAN_INPUT" ] || exit 0

# Secrets only, fast: the warm service's secret-only route plus the local-
# environment passes, falling back to the full local scan.sh if the service is
# unavailable (see secret-scan-lib.sh). If NO scanner can run, we cannot vouch
# for the text, so deny: a publish cannot be un-done.
SS_WORK="$WORK"
# shellcheck source=guards/hooks/secret-scan-lib.sh
. "$SCRIPT_DIR/secret-scan-lib.sh"
if ! secret_scan "$SCAN_INPUT"; then
  if [ "$SS_TIMED_OUT" = 1 ]; then
    deny "Blocked by guards publish-guard: the local secret scan did not finish in time, so ${LABEL} cannot be checked for credentials before it is published. Fail-closed: a publish cannot be un-done. Retry; if the text is very large, publish a shorter one. Very long single lines (minified or generated files, one-line JSON blobs) are the slow case: the scan time grows much faster than the size of such a line. The guards:synthetic marker is for fake fixture lines, not a way past a size limit."
  fi
  deny "Blocked by guards publish-guard: no secret scanner could run (the guards-unified service is unreachable and the local scanner at $SECRET_SCAN is missing or failed), so ${LABEL} cannot be checked for credentials before it is published. Fail-closed: a publish cannot be un-done. Reinstall the plugin, or the user can set GUARDS_ALLOW_PUBLISH_SECRETS=1 to bypass."
fi

RULES="$(printf '%s' "$SS_RULES" | tr ' ' ',')"

# locate: where did the scanner change the text? Diffs the scan input against
# its redacted output and, for each changed place, prints the source recorded
# in META and the line AS REDACTED (the scanner's own output: the key and its
# context stay visible, the value is replaced by the redaction marker). The raw
# line is never printed. Prints up to 5 numbered lines, then "#TOTAL <n>".
locate() {
  local out="$WORK/out.norm"
  cp -- "$SS_OUT" "$out" 2>/dev/null || return 0
  [ -z "$(tail -c1 -- "$out" 2>/dev/null)" ] || printf '\n' >> "$out"
  LC_ALL=C diff -U0 -- "$SCAN_INPUT" "$out" 2>/dev/null | LC_ALL=C awk -v meta="$META" -v max=5 '
    BEGIN { while ((getline l < meta) > 0) m[++nm] = l }
    function flush(   i, src, idx, t) {
      if (!inh || nn == 0) return
      for (i = 1; i <= nn; i++) {
        idx = (no == nn) ? a + i - 1 : a
        if (idx < 1) idx = 1
        split(m[idx], src, "\t")
        t = news[i]; gsub(/[[:cntrl:]]/, " ", t)
        if (length(t) > 200) t = substr(t, 1, 200) "..."
        total++
        if (total <= max) printf "  %d. %s, line %s: %s\n", total, src[1], src[2], t
      }
    }
    /^@@ / {
      flush()
      s = $0; sub(/^@@ -/, "", s); split(s, p, " ")
      split(p[1], o, ","); a = o[1] + 0; no = (o[2] == "" ? 1 : o[2] + 0)
      inh = 1; nn = 0; next
    }
    !inh { next }
    /^\+/ { news[++nn] = substr($0, 2) }
    END { flush(); print "#TOTAL " total + 0 }'
}

WHERE=""; WHERE_TOTAL=0
if [ -n "$RULES" ]; then
  loc="$(locate)"
  WHERE_TOTAL="$(printf '%s\n' "$loc" | sed -n 's/^#TOTAL //p')"
  WHERE_TOTAL="${WHERE_TOTAL:-0}"
  WHERE="$(printf '%s\n' "$loc" | grep -v '^#TOTAL ')"
fi

# explain: the located lines plus what to do about them. Never contains a value.
# The MCP tools (guards/mcp/server.py: check_before_publish, explain_block, ...)
# pass this text through verbatim and parse its section headings ("Where",
# "What to do"), so keep it value-free and keep the wording stable; change both
# sides and publish-guard.test.sh together.
explain() {
  if [ -n "$WHERE" ]; then
    local shown="$WHERE_TOTAL"
    [ "$shown" -gt 5 ] && shown=5
    printf '\nWhere (first %s of %s; each line is shown as the scanner redacts it, the value itself is never printed):\n%s\n' "$shown" "$WHERE_TOTAL" "$WHERE"
  else
    printf '\nWhere: the scanner could not point to a line (it matched without changing the text).\n'
  fi
  if [ "$DIFF_CAPPED" -eq 1 ]; then
    printf 'Note: the diff is larger than %s bytes; only the first %s bytes were scanned.\n' "$MAX_BYTES" "$MAX_BYTES"
  fi
  cat <<'EOT'
What to do:
 1. If the match is only a key NAME (the id or reference of a secret, a token_type) and the value is not a credential, that is a false positive. Rename or reword the key if you can, and report it to the user. Do not retry unchanged.
 2. A deliberately fake fixture line in a git commit: put the marker guards:synthetic on the SAME line, in that file's comment syntax. It covers only the added lines of the staged diff of a git commit, and not a real vendor credential or key (a private-key header, an AWS access key id, a GitHub, Slack, Stripe or OpenAI-style live key stays denied on a marked line; the documented EXAMPLE ids and values containing EXAMPLE or FAKE are fine). It does NOT cover the command text (so not a -m message), gh issue/pr bodies, or files named by --body-file/-F/cat.
 3. A message or body: describe the SHAPE only (length, character classes, which tool produced it), never the value or a prefix of it. Put the text in a file and check it first with the guards MCP tool check_before_publish.
 GUARDS_ALLOW_PUBLISH_SECRETS=1 only works when set in the environment Claude Code was STARTED from; putting it in front of a command does nothing. Never disable the guards; ask the user to review a false positive.
EOT
}

# Sure things are blocked outright: a private key, a vendor token format
# gitleaks recognises, a value from this session's own environment. Matches
# that come from a key name or URL shape next to a value (they also fire on
# text that merely DOCUMENTS such things) go to the human instead. Setting
# GUARDS_PUBLISH_ASK=0 makes every match a hard block, as before.
AMBIGUOUS=" secret-lead-in url-password url-query-secret auth-header cookie-header cli-password-flag netrc-password pgpass-password k8s-env-value json-key-value azure-client-secret gcloud-oauth-token bcrypt-hash generic-api-key "
HARD=0
for r in $SS_RULES; do
  case "$AMBIGUOUS" in *" $r "*) ;; *) HARD=1 ;; esac
done
# An ask only protects anything if a PERSON answers it. In auto, bypassPermissions
# and dontAsk modes (or any mode this hook does not recognise) Claude Code resolves
# it without one: verified live in auto mode, where a command carrying a fake
# password ran straight through an ask. A publish cannot be undone, so with no
# person to ask the ambiguous match is a deny. GUARDS_PUBLISH_ASK=force asks
# regardless of mode (for an operator who knows a person is attached).
HUMAN=0
case "$PERM_MODE" in default|acceptEdits|plan) HUMAN=1 ;; esac
[ "${GUARDS_PUBLISH_ASK:-1}" = "force" ] && HUMAN=1
MODE_NOTE=""
if [ -n "$RULES" ] && [ "$HARD" -eq 0 ] && { [ "${GUARDS_PUBLISH_ASK:-1}" = "1" ] || [ "${GUARDS_PUBLISH_ASK:-1}" = "force" ]; }; then
  if [ "$HUMAN" -eq 1 ]; then
    ask "guards publish-guard: ${LABEL} may contain a credential (detector rule(s): ${RULES}). Approve only if it shows a SHAPE or a documented example. If it contains a real value, deny it and rewrite the text to describe the shape only (length, character classes, which tool produced it); nothing real belongs in a public repo, issue, PR, comment or commit, not even a rotated one.
$(explain)"
  fi
  MODE_NOTE=" [permission mode '${PERM_MODE:-unknown}' has no person to answer an approval prompt, so an ambiguous match is blocked instead of asked]"
fi

if [ -n "$RULES" ]; then
  deny "Blocked by guards publish-guard: ${LABEL} would publish text that looks like it contains a credential (detector rule(s): ${RULES})${MODE_NOTE}. Do not include the value, not even a prefix, a partial, or a rotated/dead one. Describe the SHAPE only. Put real material nowhere in a public repo, issue, PR, comment or commit.
$(explain)"
fi

NOTE=""
if [ "$SS_SOURCE" = "local" ] && grep -q 'gitleaks not found' "$WORK/ss.err" 2>/dev/null; then
  NOTE="publish-guard: gitleaks is not installed, so only the built-in private-key and context checks ran on ${LABEL}. Vendor-token formats were not checked."
fi
if [ "$DIFF_CAPPED" -eq 1 ]; then
  NOTE="${NOTE:+$NOTE }publish-guard: the diff to be committed is larger than ${MAX_BYTES} bytes; only the first ${MAX_BYTES} bytes were scanned."
fi
# GUARDS_PUBLISH_GUARD_REPORT=1 (set by the MCP check_before_publish tool): say
# that the text WAS inspected, so "allowed" is told apart from "not a publish".
if [ "${GUARDS_PUBLISH_GUARD_REPORT:-0}" = "1" ]; then
  NOTE="${NOTE:+$NOTE }publish-guard checked $(wc -l < "$SCAN_INPUT" | tr -d ' ') line(s) from ${LABEL} and found no credential."
fi
[ -z "$NOTE" ] || notice "$NOTE"
exit 0
