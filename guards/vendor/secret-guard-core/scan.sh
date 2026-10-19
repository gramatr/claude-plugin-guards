#!/usr/bin/env bash
# VENDORED COPY — source of truth is gramatr/secret-guard's core/scan.sh. Sync manually.
# Local fix ahead of upstream: quoted redaction pattern, fail-closed verify, deterministic private-key pass (guards-unified#3 / guards-coordination#5).
# core/scan.sh — tool-agnostic secret scan + redaction.
#
# Reads arbitrary text on stdin, scans it with gitleaks, and writes the
# same text back to stdout with any detected secrets replaced by
# ***REDACTED:SECRET***. Exits 0 always (scanning failures must not
# break the caller's pipeline — see README "fail-open vs fail-closed").
#
# IMPORTANT distinction: "fail-open" below means "gitleaks itself isn't
# available, so we don't know whether there's a secret — pass the text
# through unchanged." It does NOT mean "we found a secret but can't
# redact it, so pass it through anyway" — that would be the exact leak
# this script exists to prevent. Once gitleaks has confirmed findings,
# redaction happens with plain bash string substitution (no secondary
# interpreter dependency to fail silently on).
#
# On stderr: one line per finding ("REDACTED rule=<id> line=<n>"), for
# adapters that want to log/count without touching stdout.
#
# If SECRET_GUARD_FINDINGS_JSON is set, writes a JSON array of findings
# there (RuleID/StartLine/Fingerprint — no Secret/Match values) for
# adapters that want to report findings via core/report.sh without
# re-scanning the text themselves.
#
# Requires: gitleaks (>=8.x), jq.

set -uo pipefail

INPUT_FILE="$(mktemp)"
REPORT_FILE="$(mktemp)"
trap 'rm -f "$INPUT_FILE" "$REPORT_FILE"' EXIT

cat > "$INPUT_FILE"

WITHHELD='***REDACTED:SECRET*** (secret-guard could not safely redact this output; withheld)'

# --- Deterministic private-key pass, independent of gitleaks ------------
# A private key must never depend on gitleaks having a good run: it
# intermittently reported no finding for an input it detects when replayed
# (observed about once per few hundred scans in CI, with its stderr
# discarded below), and its private-key rule needs the END marker, so a
# truncated key (head, clipped output) was never detected at all
# (guards-coordination#5/#10). So: match BEGIN ... PRIVATE KEY----- plus
# whatever base64 / escaped-newline / whitespace body follows, END marker
# optional, and redact it here. Runs even if gitleaks or jq is missing.
# Known limit: legacy encrypted PEM with Proc-Type/DEK-Info header lines
# stops at the first dash in those headers; gitleaks still covers that.
PEM_RE='-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[A-Za-z0-9+/=\\[:space:]]*(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----)?'
PEM_HITS=0
PEM_TEXT="$(cat "$INPUT_FILE")"
while [[ "$PEM_TEXT" =~ $PEM_RE ]] && [ "$PEM_HITS" -lt 50 ]; do
  m="${BASH_REMATCH[0]}"
  PEM_TEXT="${PEM_TEXT/"$m"/***REDACTED:SECRET***}"
  PEM_HITS=$((PEM_HITS + 1))
done
if [ "$PEM_HITS" -gt 0 ]; then
  echo "REDACTED rule=private-key-fallback hits=$PEM_HITS" >&2
fi

# emit_unflagged: output for the paths where gitleaks found nothing (or
# could not run). Preserves the input byte-for-byte unless the private-key
# pass changed something, and reports that pass as a finding.
emit_unflagged() {
  if [ "$PEM_HITS" -gt 0 ]; then
    if [ -n "${SECRET_GUARD_FINDINGS_JSON:-}" ]; then
      printf '[{"RuleID":"private-key-fallback","StartLine":0,"Fingerprint":""}]' > "$SECRET_GUARD_FINDINGS_JSON"
    fi
    printf '%s' "$PEM_TEXT"
  else
    cat "$INPUT_FILE"
  fi
}

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "secret-guard: gitleaks not found on PATH, skipping scan (fail-open — unknown whether a secret is present)" >&2
  emit_unflagged
  exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "secret-guard: jq not found on PATH, skipping scan (fail-open — unknown whether a secret is present)" >&2
  emit_unflagged
  exit 0
fi

# One retry if gitleaks itself errors, so a transient failure is not
# silently read as "no secrets". Its stderr is kept to the log line only.
run_gitleaks() {
  gitleaks detect --no-git -s "$INPUT_FILE" --report-format json --report-path "$REPORT_FILE" --exit-code 0 >/dev/null 2>&1
}
if ! run_gitleaks; then
  echo "secret-guard: gitleaks exited non-zero, retrying once" >&2
  : > "$REPORT_FILE"
  run_gitleaks || echo "secret-guard: gitleaks failed twice; relying on the private-key pass only" >&2
fi

if [ ! -s "$REPORT_FILE" ] || [ "$(cat "$REPORT_FILE")" = "null" ]; then
  emit_unflagged
  exit 0
fi

# Findings confirmed from here on — redact unconditionally, no fallback
# path that could pass a known secret through unredacted.
while IFS= read -r finding; do
  rule="$(echo "$finding" | jq -r '.RuleID // "unknown"')"
  line="$(echo "$finding" | jq -r '.StartLine // "?"')"
  echo "REDACTED rule=$rule line=$line" >&2
done < <(jq -c '.[]' "$REPORT_FILE")

if [ -n "${SECRET_GUARD_FINDINGS_JSON:-}" ]; then
  jq -c '[.[] | {RuleID: (.RuleID // "unknown"), StartLine: .StartLine, Fingerprint: (.Fingerprint // "")}]' \
    "$REPORT_FILE" > "$SECRET_GUARD_FINDINGS_JSON"
fi

# Start from the private-key-pass output (identical to the input when it
# found nothing).
TEXT="$PEM_TEXT"

# Replace longest secrets first so overlapping/substring matches don't
# clobber each other's placeholders. Plain bash substring substitution,
# NOT regex -- but the pattern MUST be quoted: an unquoted ${TEXT//$s/..}
# treats $s as a glob, so a backslash, *, ? or [ in the secret (an
# escaped-newline PEM inside JSON, a password with punctuation) silently
# stops matching and the "redaction" is a no-op while the verdict still
# says found (guards-coordination#4/#5).
#
# Secrets are NUL-delimited, not newline-delimited: a multi-line secret
# (a PEM block) must be replaced as ONE unit, not as its lines.
SECRETS_FILE="$(mktemp)"
FRAGMENTS_FILE="$(mktemp)"
trap 'rm -f "$INPUT_FILE" "$REPORT_FILE" "$SECRETS_FILE" "$FRAGMENTS_FILE"' EXIT

jq -j '[.[] | .Secret // empty] | unique | sort_by(-length) | .[] | (., "\u0000")' \
  "$REPORT_FILE" > "$SECRETS_FILE"
# Per-line fragments (16+ chars) of every secret, as a second pass: the
# whole-secret replace above can miss when the scanner's reported span
# and the text differ by line endings (CRLF). Short fragments are skipped
# so ordinary words are never clobbered.
jq -j '[.[] | .Secret // empty | split("\n")[] | rtrimstr("\r") | select(length >= 16)] | unique | sort_by(-length) | .[] | (., "\u0000")' \
  "$REPORT_FILE" > "$FRAGMENTS_FILE"

while IFS= read -r -d '' secret; do
  [ -n "$secret" ] && TEXT="${TEXT//"$secret"/***REDACTED:SECRET***}"
done < "$SECRETS_FILE"
while IFS= read -r -d '' frag; do
  [ -n "$frag" ] && TEXT="${TEXT//"$frag"/***REDACTED:SECRET***}"
done < "$FRAGMENTS_FILE"

# Verify, fail CLOSED. A finding was confirmed above, so if any reported
# secret (or 16+ char line of one) is still present, withhold the whole
# output instead of passing known secret material through.
LEAKED=0
while IFS= read -r -d '' secret; do
  if [ -n "$secret" ] && [[ "$TEXT" == *"$secret"* ]]; then LEAKED=1; fi
done < "$SECRETS_FILE"
while IFS= read -r -d '' frag; do
  if [ -n "$frag" ] && [[ "$TEXT" == *"$frag"* ]]; then LEAKED=1; fi
done < "$FRAGMENTS_FILE"
if [ "$LEAKED" -eq 1 ]; then
  echo "secret-guard: redaction did not remove a confirmed secret, withholding the whole output (fail-closed)" >&2
  printf '%s' "$WITHHELD"
  exit 0
fi

# The private-key pass counts as a finding even when gitleaks reported
# others, so adapters reading the findings JSON see it.
if [ "$PEM_HITS" -gt 0 ] && [ -n "${SECRET_GUARD_FINDINGS_JSON:-}" ] \
  && ! jq -e 'any(.[]; .RuleID == "private-key")' "$SECRET_GUARD_FINDINGS_JSON" >/dev/null 2>&1; then
  jq -c '. + [{RuleID: "private-key-fallback", StartLine: 0, Fingerprint: ""}]' "$SECRET_GUARD_FINDINGS_JSON" \
    > "$SECRET_GUARD_FINDINGS_JSON.tmp" && mv "$SECRET_GUARD_FINDINGS_JSON.tmp" "$SECRET_GUARD_FINDINGS_JSON"
fi

printf '%s' "$TEXT"
