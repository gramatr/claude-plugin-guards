#!/usr/bin/env bash
# guards/tests/publish-guard.test.sh — tests for hooks/publish-guard.sh.
#
# Every credential-shaped value below is FABRICATED for this test (a
# made-up password, a throwaway key generated at run time). Nothing real
# is read or committed. Needs: bash, jq, git, openssl, gitleaks (optional:
# without it only the built-in checks run).

set -uo pipefail
# Hermetic: never talk to a real guards-unified service from a test.
export GUARDS_ENDPOINT="http://127.0.0.1:1"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HERE/../hooks/publish-guard.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME" "$T/repo"
cd "$T/repo" || exit 1
git init -q . && git config user.email t@example.invalid && git config user.name t
echo base > README.md && git add README.md && git commit -q -m base

PW="Tq7vN2xLm9Kd4RzP8wYb"
openssl ecparam -genkey -name prime256v1 -noout -out "$T/key.pem" 2>/dev/null

pass=0 fail=0
run() { # run TOOL INPUT_JSON [ENV...] -> deny | ask | allow
  local out d
  out="$(jq -n --arg t "$1" --argjson i "$2" --arg cwd "$T/repo" '{tool_name:$t, tool_input:$i, cwd:$cwd}' \
    | env "${@:3}" bash "$HOOK")"
  d="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2>/dev/null)"
  case "$d" in deny|ask) echo "$d" ;; *) echo allow ;; esac
}
expect() { # expect WANT DESC TOOL INPUT [ENV...]
  local got; got="$(run "$3" "$4" "${@:5}")"
  if [ "$got" = "$1" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $2 (wanted $1, got $got)"; fi
}
bash_in() { jq -n --arg c "$1" '{command: $c}'; }

# --- deny: secrets in what gets published ---
expect ask   "issue body with DSN password"        Bash "$(bash_in "gh issue create -R o/r --title t --body 'conn postgresql://svc:$PW@db.internal:5432/app'")"
expect ask   "issue body with lead-in value"       Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")"
expect ask   "pr comment with bearer header"       Bash "$(bash_in "gh pr comment 3 --body 'Authorization: Bearer $PW'")"
expect ask   "heredoc body"                        Bash "$(bash_in "gh pr create --title t --body-file - <<'EOT'
password: \"$PW\"
EOT")"
printf 'secret_key: %s\n' "$PW" > "$T/body.md"
expect ask   "--body-file with secret"             Bash "$(bash_in "gh issue create -R o/r --title t --body-file $T/body.md")"
expect ask   "-F body=@file"                       Bash "$(bash_in "gh api repos/o/r/issues -F body=@$T/body.md")"
expect ask   "body via \$(cat file)"               Bash "$(bash_in "gh issue comment 4 --body \"\$(cat $T/body.md)\"")"
expect ask   "gh api -f body with secret"          Bash "$(bash_in "gh api repos/o/r/issues -f title=t -f body='token=$PW'")"
expect deny  "gist of a private key"               Bash "$(bash_in "gh gist create $T/key.pem")"
expect ask   "commit message with secret"          Bash "$(bash_in "git commit -m 'add config password=$PW'")"
printf 'DB_PASSWORD=%s\n' "$PW" > config.env && git add config.env
expect ask   "git commit with secret in staged diff" Bash "$(bash_in 'git commit -m "add config"')"
git reset -q config.env && rm -f config.env
cp "$T/key.pem" deploy.pem && git add deploy.pem
expect deny  "git commit staging a private key"    Bash "$(bash_in 'git commit -m "add key"')"
git reset -q deploy.pem && rm -f deploy.pem
expect ask   "marker does not excuse a message"    Bash "$(bash_in "gh issue create --title t --body 'DB_PASSWORD=$PW # guards:synthetic'")"
expect ask   "MCP issue create with secret"        mcp__github__create_issue "$(jq -n --arg b "password: $PW" '{owner:"o",repo:"r",title:"t",body:$b}')"

# A bare value with no key name: only the environment-value pass can catch it.
expect deny  "bare env-var value in an issue body"  Bash "$(bash_in "gh issue create -R o/r --title t --body 'it printed $PW and then failed'")" MY_SERVICE_TOKEN="$PW"

# --- ask vs deny: a human decides the ambiguous cases, sure things stay blocked ---
expect deny  "a vendor token format is a sure thing"  Bash "$(bash_in "gh issue create -R o/r --title t --body 'token ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'")"
expect deny  "ambiguous AND sure thing together denies" Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW and ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'")"
expect deny  "GUARDS_PUBLISH_ASK=0 restores the hard block" Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")" GUARDS_PUBLISH_ASK=0
out="$(jq -n --arg c "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'" --arg cwd "$T/repo" '{tool_name:"Bash",tool_input:{command:$c},cwd:$cwd}' | bash "$HOOK")"
msg="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
if [[ "$msg" == *"SHAPE"* && "$msg" == *secret-lead-in* && "$msg" != *"$PW"* ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: ask message names the rule, explains the choice and never echoes the value"; fi

# --- allow: clean posts, non-publish commands, markers, override ---
expect allow "clean issue body"                    Bash "$(bash_in "gh issue create -R o/r --title t --body 'The login flow fails after the token expires.'")"
expect allow "mentions password without a value"   Bash "$(bash_in "gh issue create -R o/r --title t --body 'Rotate the DB password and update the consumers.'")"
expect allow "placeholder value"                   Bash "$(bash_in "gh pr comment 3 --body 'password: \${DB_PASSWORD}'")"
expect allow "echo of a secret is not a publish"   Bash "$(bash_in "echo 'DB_PASSWORD=$PW'")"
expect allow "gh issue list"                       Bash "$(bash_in "gh issue list -R o/r")"
echo "clean change" > notes.txt && git add notes.txt
expect allow "clean commit"                        Bash "$(bash_in 'git commit -m "docs: notes"')"
git reset -q notes.txt && rm -f notes.txt
printf 'DB_PASSWORD=%s # guards:synthetic\n' "$PW" > fixture.txt && git add fixture.txt
expect allow "synthetic marker in staged diff"    Bash "$(bash_in 'git commit -m "test fixture"')"
git reset -q fixture.txt && rm -f fixture.txt
expect allow "non-write MCP tool"                  mcp__github__get_issue '{"owner":"o","repo":"r","issue_number":1}'
expect allow "override env"                        Bash "$(bash_in "gh issue create --title t --body 'DB_PASSWORD=$PW'")" GUARDS_ALLOW_PUBLISH_SECRETS=1

# --- fail closed ---
expect deny  "scanner missing fails closed"        Bash "$(bash_in "gh issue create --title t --body hello")" GUARDS_SECRET_SCAN="$T/nope.sh"
printf '#!/usr/bin/env bash\nexit 7\n' > "$T/broken.sh"
expect deny  "scanner crash fails closed"          Bash "$(bash_in "gh issue create --title t --body hello")" GUARDS_SECRET_SCAN="$T/broken.sh"

echo "publish-guard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
