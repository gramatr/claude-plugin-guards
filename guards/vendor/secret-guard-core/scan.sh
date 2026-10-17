#!/usr/bin/env bash
# VENDORED COPY — source of truth is gramatr/secret-guard's core/scan.sh. Sync manually.
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

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "secret-guard: gitleaks not found on PATH, skipping scan (fail-open — unknown whether a secret is present)" >&2
  cat "$INPUT_FILE"
  exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "secret-guard: jq not found on PATH, skipping scan (fail-open — unknown whether a secret is present)" >&2
  cat "$INPUT_FILE"
  exit 0
fi

gitleaks detect --no-git -s "$INPUT_FILE" --report-format json --report-path "$REPORT_FILE" --exit-code 0 >/dev/null 2>&1

if [ ! -s "$REPORT_FILE" ] || [ "$(cat "$REPORT_FILE")" = "null" ]; then
  cat "$INPUT_FILE"
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

TEXT="$(cat "$INPUT_FILE")"

# Replace longest secrets first so overlapping/substring matches don't
# clobber each other's placeholders. Plain bash substring substitution
# (not regex) — safe for arbitrary secret content.
while IFS= read -r secret; do
  [ -n "$secret" ] && TEXT="${TEXT//$secret/***REDACTED:SECRET***}"
done < <(jq -r '[.[] | .Secret // empty] | unique_by(. ) | sort_by(-(. | length)) | .[]' "$REPORT_FILE")

printf '%s' "$TEXT"
