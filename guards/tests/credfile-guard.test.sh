#!/usr/bin/env bash
# guards/tests/credfile-guard.test.sh — tests for hooks/credfile-guard.sh.
#
# Everything here is generated at run time inside a temp dir and thrown
# away: keys come from ssh-keygen / openssl and have never been used for
# anything. Nothing real is read, nothing is committed. HOME is pointed
# at the temp dir so the hook's ~ and $HOME expansion never touches the
# operator's real credential files.
#
# Needs: bash, jq, ssh-keygen, openssl, realpath.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HERE/../hooks/credfile-guard.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.ssh" "$HOME/.aws" "$HOME/.kube" "$HOME/proj"

ssh-keygen -q -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519" -C throwaway
ssh-keygen -q -t rsa -b 2048 -m PEM -N "" -f "$HOME/.ssh/id_rsa" -C throwaway
openssl ecparam -genkey -name prime256v1 -noout -out "$HOME/proj/innocuous-name.txt" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$HOME/proj/deploy.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=throwaway \
  -keyout /dev/null -out "$HOME/proj/public-cert.pem" 2>/dev/null
printf 'aws_secret_access_key = not-a-real-secret\n' > "$HOME/.aws/credentials"
printf 'Host x\n  HostName example.invalid\n' > "$HOME/.ssh/config"
printf 'KEY=value\n' > "$HOME/proj/.env"
printf 'KEY=changeme\n' > "$HOME/proj/.env.example"
printf 'hello\n' > "$HOME/proj/README.md"
printf 'clusters: []\n' > "$HOME/.kube/config"
# a key whose PEM header is embedded in JSON with escaped newlines
jq -n --rawfile k "$HOME/proj/deploy.pem" '{private_key: $k}' > "$HOME/proj/sa.json"

pass=0 fail=0

# run TOOL TOOL_INPUT_JSON -> prints "deny" or "allow"
# MODE is the permission_mode put in the payload (default: "default", a mode
# where a person can answer an ask); MODE=none omits the field.
ASKVAR="GUARDS_CRED_ASK" # name kept in a variable for the force cases
MODE="default"
run() { # run TOOL INPUT_JSON [ENV...] -> deny | ask | allow
  local out d
  out="$(jq -n --arg t "$1" --argjson i "$2" --arg cwd "$HOME/proj" --arg m "$MODE" \
    '{tool_name: $t, tool_input: $i, cwd: $cwd} + (if $m == "none" then {} else {permission_mode: $m} end)' | env "${@:3}" bash "$HOOK")"
  # jq -e exits 0 on empty input, so compare the decision text instead.
  d="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2>/dev/null)"
  case "$d" in deny|ask) echo "$d" ;; *) echo allow ;; esac
}
expect() { # expect WANT DESCRIPTION TOOL INPUT
  local got
  got="$(run "$3" "$4" "${@:5}")"
  if [ "$got" = "$1" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $2 (wanted $1, got $got)"
  fi
}

read_in() { jq -n --arg p "$1" '{file_path: $p}'; }
grep_in() { jq -n --arg p "$1" --arg g "${2:-}" '{pattern: "x", path: $p, glob: $g}'; }
bash_in() { jq -n --arg c "$1" '{command: $c}'; }

# --- Read ---
expect deny  "Read ed25519 private key"           Read "$(read_in "$HOME/.ssh/id_ed25519")"
expect deny  "Read rsa private key"               Read "$(read_in "$HOME/.ssh/id_rsa")"
# shellcheck disable=SC2088  # the literal tilde is the point of this case
expect deny  "Read ~ form"                        Read "$(read_in '~/.ssh/id_rsa')"
expect deny  "Read \$HOME form"                   Read "$(read_in '$HOME/.ssh/id_rsa')"
expect deny  "Read key under an innocuous name"   Read "$(read_in "$HOME/proj/innocuous-name.txt")"
expect deny  "Read .pem private key"              Read "$(read_in "$HOME/proj/deploy.pem")"
expect deny  "Read JSON with embedded key"        Read "$(read_in "$HOME/proj/sa.json")"
expect deny  "Read aws credentials"               Read "$(read_in "$HOME/.aws/credentials")"
expect ask   "Read .env"                          Read "$(read_in "$HOME/proj/.env")"
expect ask   "Read kubeconfig"                    Read "$(read_in "$HOME/.kube/config")"
expect allow "Read public key"                    Read "$(read_in "$HOME/.ssh/id_rsa.pub")"
expect allow "Read ssh config"                    Read "$(read_in "$HOME/.ssh/config")"
expect allow "Read public certificate .pem"       Read "$(read_in "$HOME/proj/public-cert.pem")"
expect allow "Read .env.example"                  Read "$(read_in "$HOME/proj/.env.example")"
expect allow "Read ordinary file"                 Read "$(read_in "$HOME/proj/README.md")"
expect allow "Read nonexistent file"              Read "$(read_in "$HOME/proj/nope.txt")"

# --- Grep ---
expect deny  "Grep a private key file"            Grep "$(grep_in "$HOME/.ssh/id_rsa")"
expect deny  "Grep the .ssh directory"            Grep "$(grep_in "$HOME/.ssh")"
expect ask   "Grep with .env glob"                Grep "$(grep_in "$HOME/proj" ".env*")"
expect deny  "Grep with *.pem glob"               Grep "$(grep_in "$HOME/proj" "*.pem")"
expect allow "Grep ordinary file"                 Grep "$(grep_in "$HOME/proj/README.md")"
expect allow "Grep project dir, plain glob"       Grep "$(grep_in "$HOME/proj" "*.md")"
expect allow "Grep .env.example glob"             Grep "$(grep_in "$HOME/proj" ".env.example")"

# --- Bash ---
expect deny  "cat private key"                    Bash "$(bash_in "cat $HOME/.ssh/id_ed25519")"
expect deny  "cat ~ form"                         Bash "$(bash_in 'cat ~/.ssh/id_rsa')"
expect deny  "cat with prompt-ish prefix"         Bash "$(bash_in 'echo hi; cat ~/.ssh/id_rsa | head')"
expect deny  "cat glob over .ssh"                 Bash "$(bash_in 'cat ~/.ssh/id_*')"
expect ask   "head of .env"                       Bash "$(bash_in 'head -n 5 .env')"
expect deny  "base64 of key"                      Bash "$(bash_in "base64 $HOME/.ssh/id_rsa")"
expect deny  "grep inside key under odd name"     Bash "$(bash_in 'grep -n . innocuous-name.txt')"
expect deny  "cat redirect-quoted path"           Bash "$(bash_in "cat '$HOME/.aws/credentials'")"
expect deny  "python reading key"                 Bash "$(bash_in "python3 -c 'print(open(\"$HOME/.ssh/id_rsa\").read())'")"
expect allow "ssh -i uses key without printing"   Bash "$(bash_in "ssh -i $HOME/.ssh/id_ed25519 host.invalid true")"
expect allow "ssh-keygen -l fingerprint"          Bash "$(bash_in "ssh-keygen -l -f $HOME/.ssh/id_ed25519")"
expect allow "cat public key"                     Bash "$(bash_in "cat $HOME/.ssh/id_ed25519.pub")"
expect allow "cat ordinary file"                  Bash "$(bash_in 'cat README.md')"
expect allow "cat .env.example"                   Bash "$(bash_in 'cat .env.example')"
expect allow "ls .ssh (no content)"               Bash "$(bash_in 'ls -la ~/.ssh')"
expect allow "test -f key"                        Bash "$(bash_in 'test -f ~/.ssh/id_rsa && echo yes')"

# --- ask vs deny (ask for ambiguous files, deny only the clear credential stores) ---
printf '//registry.npmjs.org/:_authToken=not-a-real-token\n' > "$HOME/proj/.npmrc"
printf '{"resources": []}\n' > "$HOME/proj/terraform.tfstate"
expect ask   "Read .npmrc asks"                   Read "$(read_in "$HOME/proj/.npmrc")"
expect ask   "Read terraform state asks"          Read "$(read_in "$HOME/proj/terraform.tfstate")"
expect deny  "a private key still denies"         Read "$(read_in "$HOME/.ssh/id_rsa")"
expect deny  "aws credentials still deny"         Read "$(read_in "$HOME/.aws/credentials")"
expect deny  "a deny-class path beats an ask-class one" Bash "$(bash_in "cat .env $HOME/.ssh/id_rsa")"
expect deny  "ask-class first, deny-class second, still deny" Bash "$(bash_in "head .env && cat ~/.ssh/id_ed25519")"
expect deny  "GUARDS_CRED_ASK=0 restores the hard deny for .env" Read "$(read_in "$HOME/proj/.env")" GUARDS_CRED_ASK=0
expect deny  "GUARDS_CRED_ASK=0 restores the hard deny for kubeconfig" Read "$(read_in "$HOME/.kube/config")" GUARDS_CRED_ASK=0
expect allow "override env still allows everything" Read "$(read_in "$HOME/proj/.env")" GUARDS_ALLOW_CRED_READ=1

# --- permission mode: ask only where a person can answer (same rule as publish-guard) ---
# Each mode is tried against every ask-class shape and against a deny-class
# file, which must deny in every mode.
for m in default acceptEdits plan; do
  MODE="$m"
  expect ask  "[$m] Read .env asks"               Read "$(read_in "$HOME/proj/.env")"
  expect ask  "[$m] Read kubeconfig asks"         Read "$(read_in "$HOME/.kube/config")"
  expect ask  "[$m] Read .npmrc asks"             Read "$(read_in "$HOME/proj/.npmrc")"
  expect ask  "[$m] Read tfstate asks"            Read "$(read_in "$HOME/proj/terraform.tfstate")"
  expect ask  "[$m] Grep .env glob asks"          Grep "$(grep_in "$HOME/proj" ".env*")"
  expect ask  "[$m] Bash head .env asks"          Bash "$(bash_in 'head -n 5 .env')"
done
for m in auto bypassPermissions dontAsk someFutureMode none ""; do
  MODE="$m"; label="${m:-empty}"
  expect deny "[$label] Read .env denies"         Read "$(read_in "$HOME/proj/.env")"
  expect deny "[$label] Read kubeconfig denies"   Read "$(read_in "$HOME/.kube/config")"
  expect deny "[$label] Read .npmrc denies"       Read "$(read_in "$HOME/proj/.npmrc")"
  expect deny "[$label] Read tfstate denies"      Read "$(read_in "$HOME/proj/terraform.tfstate")"
  expect deny "[$label] Grep .env glob denies"    Grep "$(grep_in "$HOME/proj" ".env*")"
  expect deny "[$label] Bash head .env denies"    Bash "$(bash_in 'head -n 5 .env')"
  expect ask  "[$label] GUARDS_CRED_ASK force asks" Read "$(read_in "$HOME/proj/.env")" "$ASKVAR=force"
  expect deny "[$label] GUARDS_CRED_ASK=0 denies"  Read "$(read_in "$HOME/proj/.env")" GUARDS_CRED_ASK=0
  expect allow "[$label] GUARDS_ALLOW_CRED_READ=1 allows" Read "$(read_in "$HOME/proj/.env")" GUARDS_ALLOW_CRED_READ=1
  expect allow "[$label] .env.example still allowed" Read "$(read_in "$HOME/proj/.env.example")"
done
for m in default acceptEdits plan auto bypassPermissions dontAsk someFutureMode; do
  MODE="$m"
  expect deny "[$m] private key denies"           Read "$(read_in "$HOME/.ssh/id_rsa")"
  expect deny "[$m] deny-class beats ask-class"   Bash "$(bash_in "cat .env $HOME/.ssh/id_rsa")"
  expect deny "[$m] GUARDS_CRED_ASK force does not soften a private key" Read "$(read_in "$HOME/.ssh/id_rsa")" "$ASKVAR=force"
done
MODE="default"
MODE="auto"
out="$(jq -n --argjson i "$(read_in "$HOME/proj/.env")" --arg cwd "$HOME/proj" '{tool_name:"Read",tool_input:$i,cwd:$cwd,permission_mode:"auto"}' | bash "$HOOK")"
msg="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
if [[ "$msg" == *"auto"* && "$msg" == *"no person"* && "$msg" != *"KEY=value"* ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: deny message in auto names the mode and the reason ($msg)"; fi
MODE="default"

# the ask message must not leak content and must say what will happen
out="$(jq -n --argjson i "$(read_in "$HOME/proj/.env")" --arg cwd "$HOME/proj" '{tool_name:"Read",tool_input:$i,cwd:$cwd}' | bash "$HOOK")"
msg="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
if [[ "$msg" == *"transcript"* && "$msg" == *".env"* && "$msg" != *"KEY=value"* ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: ask message is informative and does not echo file content ($msg)"; fi

# --- other tools untouched ---
expect allow "Glob not inspected"                 Glob '{"pattern":"**/*.pem"}'

# --- override ---
GUARDS_ALLOW_CRED_READ=1 expect allow "override env allows read" Read "$(read_in "$HOME/.ssh/id_rsa")"

# --- jq missing: the guard must still decide (an awk parser reads the payload) ---
# A PATH with every tool except jq. The payloads are built with the real jq
# first, then fed to the hook under the shadow PATH.
NOJQ="$T/nojq-bin"
mkdir -p "$NOJQ"
for d in /usr/local/bin /usr/bin /bin; do
  for f in "$d"/*; do
    n="$(basename "$f")"
    [ "$n" = jq ] && continue
    [ -e "$NOJQ/$n" ] || ln -s "$f" "$NOJQ/$n" 2>/dev/null
  done
done
[ -e "$NOJQ/jq" ] && { echo "FAIL: test setup: jq is on the shadow PATH"; fail=$((fail + 1)); }

decision() { # decision OUTPUT -> deny | ask | allow (parsed with the real jq)
  local d
  d="$(printf '%s' "$1" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2>/dev/null)"
  case "$d" in deny|ask) echo "$d" ;; *) echo allow ;; esac
}
nojq_payload() { # nojq_payload TOOL INPUT_JSON MODE
  jq -n --arg t "$1" --argjson i "$2" --arg cwd "$HOME/proj" --arg m "$3" \
    '{tool_name: $t, tool_input: $i, cwd: $cwd} + (if $m == "none" then {} else {permission_mode: $m} end)'
}
expect_nojq() { # expect_nojq WANT DESCRIPTION TOOL INPUT [MODE]
  local out got
  out="$(nojq_payload "$3" "$4" "${5:-default}" | env PATH="$NOJQ" bash "$HOOK")"
  got="$(decision "$out")"
  if [ "$got" = "$1" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: no jq: $2 (wanted $1, got $got)"; fi
}

expect_nojq deny  "Read private key"                     Read "$(read_in "$HOME/.ssh/id_rsa")"
expect_nojq deny  "Read key under an innocuous name"     Read "$(read_in "$HOME/proj/innocuous-name.txt")"
expect_nojq allow "Read README"                          Read "$(read_in "$HOME/proj/README.md")"
expect_nojq ask   "Read .env where a person can answer"  Read "$(read_in "$HOME/proj/.env")" default
expect_nojq deny  "Read .env in auto mode"               Read "$(read_in "$HOME/proj/.env")" auto
expect_nojq deny  "Grep glob for pem files"              Grep '{"pattern":"x","glob":"*.pem"}'
expect_nojq deny  "Bash cat of a key"                    Bash "$(jq -n --arg c "cat $HOME/.ssh/id_rsa" '{command:$c}')"
# the command string carries escaped quotes; they must not end the value early
expect_nojq deny  "Bash with escaped quotes around a key path" Bash "$(jq -n --arg c "cat \"$HOME/.ssh/id_rsa\" | head -1" '{command:$c}')"
expect_nojq allow "Bash cat of a harmless file"          Bash "$(jq -n --arg c "cat $HOME/proj/README.md" '{command:$c}')"
# a key name that only appears inside another string is not a key
expect_nojq allow "key names inside a command string"    Bash "$(jq -n --arg c "echo '{\"file_path\":\"$HOME/.ssh/id_rsa\"}'" '{command:$c}')"
# field order must not matter
expect_nojq deny  "tool_input before the other fields"   Read "$(read_in "$HOME/.aws/credentials")"

# an unreadable payload: with jq it is passed (documented), without jq it is refused
out="$(printf 'not json at all' | env PATH="$NOJQ" bash "$HOOK")"
got="$(decision "$out")"
if [ "$got" = deny ] && [[ "$out" == *"jq is not installed"* ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: no jq: unreadable payload is refused with an actionable reason (got $got: $out)"; fi
out="$(printf 'not json at all' | bash "$HOOK")"
if [ -z "$out" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: with jq: unreadable payload is passed (got: $out)"; fi

# the decision JSON is valid and the reason survives escaping
out="$(nojq_payload Read "$(read_in "$HOME/.ssh/id_rsa")" default | env PATH="$NOJQ" bash "$HOOK")"
if printf '%s' "$out" | jq -e '.hookSpecificOutput.permissionDecisionReason | contains("Blocked by guards credfile-guard")' >/dev/null 2>&1; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: no jq: deny output is valid JSON with the reason ($out)"; fi

# the override still works without jq
out="$(nojq_payload Read "$(read_in "$HOME/.ssh/id_rsa")" default | env PATH="$NOJQ" GUARDS_ALLOW_CRED_READ=1 bash "$HOOK")"
if [ -z "$out" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: no jq: override allows the read ($out)"; fi

echo "credfile-guard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
