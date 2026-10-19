#!/usr/bin/env bash
# shellcheck disable=SC2034  # the SS_* variables are consumed by the scripts that source this file
# guards/hooks/secret-scan-lib.sh — sourced by the hooks; not run directly.
#
# secret_scan INFILE
#   Secrets only, fast. Asks the warm guards-unified service for the
#   secret-only answer (POST /v1/scan/secret, about 60 ms) and then runs the
#   vendored scan.sh with SECRET_GUARD_SKIP_GITLEAKS=1 for the passes that
#   need THIS process's environment (SECRET_GUARD_ENV_VALUES): about 40 ms,
#   no gitleaks start-up (about 230 ms on a laptop). If the service is down,
#   too slow (SS_SERVICE_TIMEOUT, default 2 s), too old to have the route, or
#   answers with an error, it falls back to the full local scan.sh with
#   gitleaks, so protection never depends on the service being up.
#
#   The PII and prompt-injection models are NOT involved: they cost about
#   0.25 s per KB, are flag-only, and secrets are what must never wait on
#   them.
#
# Needs from the caller: SS_WORK (a writable temp dir) and SECRET_SCAN (path
# to the vendored scan.sh). Optional: GUARDS_ENDPOINT.
# Sets:  SS_OUT (file with the redacted text), SS_RULES (space-separated
#        detector rule IDs, never values), SS_CHANGED (1 if SS_OUT differs
#        from INFILE), SS_SOURCE (service|local).
# Returns 0 on success, 1 if no scanner could run at all.

secret_scan() {
  local in="$1" w="${SS_WORK:?SS_WORK not set}"
  local svc="$w/ss.svc.json" svc_out="$w/ss.svc.out" loc="$w/ss.loc.json" verdict r
  SS_OUT="$w/ss.final.out"; SS_RULES=""; SS_CHANGED=0; SS_SOURCE=local
  : > "$loc"

  if jq -n --rawfile text "$in" '{text: $text}' 2>/dev/null \
      | curl -sS -m "${SS_SERVICE_TIMEOUT:-2}" -X POST "${GUARDS_ENDPOINT:-http://127.0.0.1:8700}/v1/scan/secret" \
          -H 'Content-Type: application/json' -d @- -o "$svc" 2>/dev/null \
     && jq -e '(.findings | type == "array") and (.findings[0].type == "secret") and (.findings[0].verdict != "error")' "$svc" >/dev/null 2>&1; then
    SS_SOURCE=service
    verdict="$(jq -r '.findings[0].verdict' "$svc")"
    if [ "$verdict" = "found" ]; then
      jq -j '.redacted_text' "$svc" > "$svc_out"
      SS_RULES="$(jq -r '.findings[0].reason_code // [] | map(sub("^SECRET_"; "") | ascii_downcase) | join(" ")' "$svc")"
    else
      cp "$in" "$svc_out"
    fi
    # Local-environment passes only (no gitleaks).
    if ! SECRET_GUARD_SKIP_GITLEAKS=1 SECRET_GUARD_ENV_VALUES=1 SECRET_GUARD_FINDINGS_JSON="$loc" \
         timeout 10 bash "$SECRET_SCAN" < "$svc_out" > "$SS_OUT" 2>/dev/null; then
      cp "$svc_out" "$SS_OUT"
    fi
  else
    # Service unavailable: the full local scan, gitleaks included.
    [ -f "$SECRET_SCAN" ] || return 1
    SECRET_GUARD_ENV_VALUES=1 SECRET_GUARD_FINDINGS_JSON="$loc" \
      timeout 30 bash "$SECRET_SCAN" < "$in" > "$SS_OUT" 2>"$w/ss.err" || return 1
    SS_SOURCE=local
  fi

  if [ -s "$loc" ] && grep -q RuleID "$loc"; then
    for r in $(grep -o '"RuleID":"[^"]*"' "$loc" | cut -d'"' -f4); do
      case " $SS_RULES " in *" $r "*) ;; *) SS_RULES="${SS_RULES:+$SS_RULES }$r" ;; esac
    done
  fi
  cmp -s "$in" "$SS_OUT" || SS_CHANGED=1
  return 0
}
