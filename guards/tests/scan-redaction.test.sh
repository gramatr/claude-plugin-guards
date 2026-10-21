#!/usr/bin/env bash
# guards/tests/scan-redaction.test.sh — regression test for the vendored
# secret-guard-core/scan.sh redaction: a confirmed
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
  awk '{ printf "%s\r\n", $0 }' "$T/$key.pem" > "$T/in_crlf.txt"   # not sed 's/$/\r/': BSD sed has no \r
  sed '$d' "$T/$key.pem" > "$T/in_trunc.txt"   # drop the END line; not head -n -1: BSD head rejects a negative count
  check "$key plain"          "$T/in_plain.txt"
  check "$key json-escaped"   "$T/in_json.txt"
  check "$key crlf"           "$T/in_crlf.txt"
  check "$key truncated"      "$T/in_trunc.txt"
done

# Context rules: the secret must disappear and the surrounding text stay.
ctx() { # ctx NAME INPUT SECRET
  local out
  out="$(printf '%s' "$2" | scan)"
  if [[ "$out" == *"$3"* ]] || [ "$out" = "$2" ]; then
    echo "FAIL: $1: secret survives"; fail=$((fail + 1))
  else
    pass=$((pass + 1))
  fi
}
ctx "dsn postgres"      'postgresql://svc:Tq7vN2xLm9Kd4RzP8wYb@db.internal:5432/app' 'Tq7vN2xLm9Kd4RzP8wYb'
ctx "dsn redis"         'redis://:Tq7vN2xLm9Kd4RzP8wYb@cache.internal:6379/0'          'Tq7vN2xLm9Kd4RzP8wYb'
ctx "env punctuation"   'DB_PASSWORD=Xk9mQ4vT2p@Lw8RzN5bJc7Hd3'                         'Xk9mQ4vT2p@Lw8RzN5bJc7Hd3'
ctx "json punctuation"  '{"secretKey": "Qm4*Xw9%tL2!pR7=zN3^vB8", "user": "bob"}'       'Qm4*Xw9%tL2!pR7=zN3^vB8'
ctx "bearer header"     'Authorization: Bearer Tq7vN2xLm9Kd4RzP8wYb'                    'Tq7vN2xLm9Kd4RzP8wYb'
B64DSN="$(printf 'postgresql://svc:Tq7vN2xLm9Kd4RzP8wYb@db.internal:5432/app' | base64 | tr -d '\n')"   # not base64 -w0: BSD base64 has no -w
ctx "base64 DSN under a plain key" "{\"conn\": \"$B64DSN\"}" "$B64DSN"
# Harmless lookalikes stay byte-identical.
# /usr/bin exists on the host AND inside the scan image (SCAN_IMAGE mode), unlike $HOME.
for benign in "PWD=/usr/bin" "cwd listing for /usr/bin done" 'password: ${DB_PASSWORD}' 'secretName: db-credentials' 'The secret to good tests is isolation.' 'commit 3f2a9c1e5b7d4a6082f1c3e5a7b9d1f3e5a7c9b1 Author: x' 'SCAN_SECRET_MAX_BYTES=2000000' 'API_TOKEN_TIMEOUT=30000' 'CRED_MODE=strict' 'self._tokenizer = AutoTokenizer.from_pretrained(name)'; do  # guards:synthetic
  if [ "$(printf '%s' "$benign" | scan)" = "$benign" ]; then pass=$((pass + 1)); else echo "FAIL: benign altered: $benign"; fail=$((fail + 1)); fi
done
# A heading that ends in a keyword and a colon is not a key: the next line's first
# word is not its value (found live while verifying v0.2.2).
for benign in $'Rotate the secret:\n  kubectl delete secret old' $'About the token:\n  local: running' $'secret:\n  name: db-creds' $'token:\n  one two three' $'A heading that ended in "token:" then text\nline two\nand later "secret:" follows here\nlast line'; do  # guards:synthetic
  if [ "$(printf '%s' "$benign" | scan)" = "$benign" ]; then pass=$((pass + 1)); else echo "FAIL: heading altered: ${benign%%$'\n'*}"; fail=$((fail + 1)); fi
done
# The one next-line form that IS a value: a YAML scalar under a line that is only the key and a colon.
ctx "yaml scalar on the line after a bare key" $'password:\n  Tq7vN2xLm9Kd4RzP8wYb' 'Tq7vN2xLm9Kd4RzP8wYb'  # guards:synthetic

# Large input with a secret: the span split used to be quadratic (232 KB took
# 19 s, 1 MB 447 s), and the loops stopped after 200 matches, leaving later
# secrets unredacted. Allow generous time for slow CI.
many="$(for i in $(seq 1 300); do printf 'APP%s_PASSWORD=hunter2-%s\n' "$i" "$i"; done)"
left="$(printf '%s' "$many" | scan | grep -c 'hunter2-' || true)"
if [ "$left" = "0" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $left of 300 secret lines survive (match cap?)"; fi
big="$(python3 -I -c "
import random, string
random.seed(1)
print(' '.join(''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(3, 9))) for _ in range(34000)))
print('DB_PASSWORD=Tq7vN2xLm9Kd4RzP8wYb')")"
start=$SECONDS
out="$(printf '%s' "$big" | scan)"
took=$((SECONDS - start))
if [[ "$out" != *Tq7vN2xLm9Kd4RzP8wYb* ]] && [ "$took" -le 20 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: large input: took ${took}s (limit 20s) or secret survived"; fi

echo "scan-redaction: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
