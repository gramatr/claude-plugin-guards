#!/usr/bin/env bash
# guards/tests/deny-messages.test.sh -- every message a guards hook prints says what to do (coordination#100).
#
# deny-messages.py reads the hook sources and returns every deny, ask and withhold string
# (nothing is executed). This test fails when:
#   1. a message starts with "Blocked by guards" or "guards <hook>" and has no "Fix:" clause;
#   2. a withhold notice (it contains "withheld") does not say that the command or tool RAN and
#      that its OUTPUT / RESULT was withheld, so the model does not read it as a failure;
#   3. fewer than 30 messages are found (the extractor broke, which would pass everything);
#   4. a message carries a bare prefix but no hook name.
# A negative control feeds a message without a clause and expects the test logic to catch it.
# Needs: bash, python3.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="$HERE/../hooks"
PY="${GUARDS_TEST_PYTHON:-python3}"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

# judge LINE_ID TEXT -> prints a reason when the message is not acceptable, nothing when it is.
judge() {
  local id="$1" text="$2"
  case "$text" in
    "Blocked by guards "* | "guards "*) ;;
    *) return 0 ;;
  esac
  # ${NOJQ_INSTALL} and ${SAFE_FORMS} are shell variables whose value starts with "Fix:" (json-lib.sh, outbound-guard.sh).
  case "$text" in
    *"Fix:"* | *'${NOJQ_INSTALL}'* | *'${SAFE_FORMS}'*) ;;
    *) echo "$id: no 'Fix:' clause: ${text:0:110}"; return 0 ;;
  esac
  case "$text" in
    *withheld*)
      case "$text" in
        *"command ran"* | *"tool ran"*) ;;
        *) echo "$id: a withhold notice that does not say the command or tool ran: ${text:0:110}"; return 0 ;;
      esac
      case "$text" in
        *"output was withheld"* | *"result was withheld"*) ;;
        *) echo "$id: a withhold notice that does not say the output or result was withheld: ${text:0:110}"; return 0 ;;
      esac ;;
  esac
  return 0
}

n=0
while IFS=$'\t' read -r id text; do
  case "$text" in "Blocked by guards "* | "guards "*) ;; *) continue ;; esac
  n=$((n + 1))
  verdict="$(judge "$id" "$text")"
  if [ -z "$verdict" ]; then ok; else bad "$verdict"; fi
  # the second word after the prefix must be a hook name or a variable that holds one
  rest="${text#Blocked by }"; rest="${rest#guards }"
  case "$rest" in
    [a-z]*-guard:* | combined-hook:* | '${name}:'* | '$'*) ok ;;
    *) bad "$id: the prefix does not name a hook: ${text:0:80}" ;;
  esac
done < <("$PY" "$HERE/deny-messages.py" "$HOOKS")

if [ "$n" -ge 30 ]; then ok; else bad "only $n guards messages found; the extractor is broken or messages moved"; fi

# negative control: the judge catches a message with no clause and a withhold notice that hides the ran fact
[ -n "$(judge ctl1 'Blocked by guards credfile-guard: this is not allowed.')" ] && ok || bad "negative control: a message without a Fix clause was accepted"
[ -n "$(judge ctl2 'guards combined-hook: the output of this command was withheld because x. Fix: run it again.')" ] && ok || bad "negative control: a withhold notice that does not say the command ran was accepted"
[ -z "$(judge ctl3 'guards combined-hook: the command ran, but its output was withheld because x. Fix: run it again.')" ] && ok || bad "negative control: a good withhold notice was rejected"

echo "deny-messages: $pass passed, $fail failed ($n messages)"
[ "$fail" -eq 0 ]
