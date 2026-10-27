#!/usr/bin/env bash
# guards/hooks/approve-lib.sh -- the approve-once store for publish-guard (coordination#124, part B).
#
# WHY: in auto, bypassPermissions and dontAsk modes nobody can answer an ask, so an ambiguous match
# (a key name next to a value that may be only a reference) was a plain deny, and the only way
# through was for the person to run the same command outside the session. This gives the person a
# one-line way to say "that one is fine" without leaving it, and without the agent being able to say
# it for them.
#
# HOW: a block names an id, the hash of the exact scanned text plus the matched rules. The person
# runs bin/guards-approve.sh with that id in their own session (the ! prefix, which does not pass
# through hooks), which writes a single-use approval valid for GUARDS_APPROVE_TTL seconds (default
# 600). The agent retries the identical command; publish-guard finds the approval, uses it up and
# allows. A changed text has a new id and needs a new approval. Only the ambiguous rules are
# approvable; a sure-thing match (a private key, a vendor token format, a value from the session's
# own environment) is never offered for approval.
#
# LIMITS: the store is plain files in the user's home. publish-guard refuses an agent command that
# names the approve script or the store, but an agent that can write files anywhere (for instance
# under bypassPermissions) can get around that; this stops accidents and an agent that is not
# trying to get around it, nothing more (docs/THREAT-MODEL.md).
#
# Sourced, not run. Values are never stored: only the id, the rules, the label and the redacted
# "where" lines that publish-guard already shows in its deny message.

GUARDS_APPROVE_DIR="${GUARDS_APPROVE_DIR:-${GUARDS_STATE_DIR:-$HOME/.local/share/gramatr-guards}}"
GUARDS_APPROVE_TTL="${GUARDS_APPROVE_TTL:-600}"

# approve_sha: stdin -> first 16 hex characters of its SHA-256 (sha256sum, shasum or openssl).
approve_sha() {
  {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256
    else openssl dgst -sha256 | sed 's/^.*= //'
    fi
  } | cut -c1-16
}

# approve_id RULES FILE: the id of this exact text under these rules.
approve_id() {
  { printf '%s\n' "$1"; cat -- "$2"; } | approve_sha
}

approve_valid_id() { [[ "$1" =~ ^[0-9a-f]{16}$ ]]; }

approve_mkdirs() {
  mkdir -p "$GUARDS_APPROVE_DIR/approvals" "$GUARDS_APPROVE_DIR/pending" 2>/dev/null || return 1
  chmod 700 "$GUARDS_APPROVE_DIR/approvals" "$GUARDS_APPROVE_DIR/pending" 2>/dev/null
  return 0
}

# approve_pending_write ID LABEL RULES WHERE: remember what a block was about, so the person sees it
# when approving. Never holds a value. Pending notes older than a day are removed.
approve_pending_write() {
  approve_mkdirs || return 0
  local f="$GUARDS_APPROVE_DIR/pending/$1"
  { printf 'label\t%s\nrules\t%s\nwhen\t%s\n' "$2" "$3" "$(date +%s)"; printf 'where\n%s\n' "$4"; } > "$f" 2>/dev/null
  chmod 600 "$f" 2>/dev/null
  find "$GUARDS_APPROVE_DIR/pending" -type f -mmin +1440 -exec rm -f {} + 2>/dev/null
  return 0
}

# approve_peek ID: succeeds when an unexpired approval exists. Does not use it up.
approve_peek() {
  approve_valid_id "$1" || return 1
  local f="$GUARDS_APPROVE_DIR/approvals/$1" exp now
  [ -f "$f" ] || return 1
  exp="$(head -n1 -- "$f" 2>/dev/null)"
  now="$(date +%s)"
  [[ "$exp" =~ ^[0-9]+$ ]] && [ "$now" -le "$exp" ]
}

# approve_consume ID: succeeds once for an unexpired approval and removes it either way.
approve_consume() {
  approve_valid_id "$1" || return 1
  local f="$GUARDS_APPROVE_DIR/approvals/$1" rc=1
  approve_peek "$1" && rc=0
  rm -f -- "$f" 2>/dev/null
  return $rc
}

# approve_log ID RULES: one metadata line per approval used (no text), so a rule that needs approving
# often shows up and can be tuned.
approve_log() {
  approve_mkdirs || return 0
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >> "$GUARDS_APPROVE_DIR/approvals.log" 2>/dev/null
  return 0
}
