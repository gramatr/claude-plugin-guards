#!/usr/bin/env bash
# guards/tests/scan-redaction.test.sh — regression test for the vendored
# secret-guard-core/scan.sh redaction (guards-coordination#5): a confirmed
# secret must never come back unchanged.
#
# The bug: the redaction pattern was unquoted, so the secret was treated
# as a glob and a PEM embedded in JSON (escaped \n) was detected but left
# intact. Throwaway keys are generated at run time with openssl and thrown
# away; nothing real is involved.
#
# Modes:
#   default           uses gitleaks + jq on PATH
#   SCAN_IMAGE=<img>  runs scan.sh inside that docker image (CI uses the
#                     freshly built secret-guard-core:ci, so the shipped
#                     artifact is what gets tested)
# Needs: bash, openssl, jq (host side), plus gitleaks or docker.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$HERE/../vendor/secret-guard-core/scan.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

scan() {
  if [ -n "${SCAN_IMAGE:-}" ]; then
    docker run --rm -i --entrypoint bash "$SCAN_IMAGE" /app/scan.sh 2>/dev/null
  else
    bash "$SCAN" 2>/dev/null
  fi
}

openssl ecparam -genkey -name prime256v1 -noout -out "$T/ec.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/p8.pem" 2>/dev/null

pass=0 fail=0

# check NAME FILE: output must differ from input and keep none of the key
# body lines (16+ chars) that were in the input.
check() {
  local name="$1" file="$2" out leaked=0 line
  out="$(scan < "$file")"
  if [ "$out" = "$(cat "$file")" ]; then
    echo "FAIL: $name: output identical to input"; fail=$((fail + 1)); return
  fi
  while IFS= read -r line; do
    [ "${#line}" -ge 16 ] || continue
    case "$line" in -----*) continue ;; esac
    if [[ "$out" == *"$line"* ]]; then leaked=$((leaked + 1)); fi
  done < "$T/body.txt"
  if [ "$leaked" -gt 0 ]; then
    echo "FAIL: $name: $leaked key body lines survive"; fail=$((fail + 1))
  else
    pass=$((pass + 1))
  fi
}

for key in ec p8; do
  grep -v -- '-----' "$T/$key.pem" > "$T/body.txt"
  cp "$T/$key.pem" "$T/in_plain.txt"
  jq -n --rawfile k "$T/$key.pem" '{private_key: $k}' > "$T/in_json.txt"
  sed 's/$/\r/' "$T/$key.pem" > "$T/in_crlf.txt"
  check "$key plain"          "$T/in_plain.txt"
  check "$key json-escaped"   "$T/in_json.txt"
  check "$key crlf"           "$T/in_crlf.txt"
done

echo "scan-redaction: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
