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
# Permission mode sent in every payload. Only default/acceptEdits/plan have a person to answer an ask.
PM_MODE=default
run() { # run TOOL INPUT_JSON [ENV...] -> deny | ask | allow
  local out d
  out="$(jq -n --arg t "$1" --argjson i "$2" --arg cwd "$T/repo" --arg pm "$PM_MODE" '{tool_name:$t, tool_input:$i, cwd:$cwd, permission_mode:$pm}' \
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

# --- a commit is judged on its message and staged diff, not on unrelated commands on the line (coordination#99) ---
NL=$'\n'
CMT_OK="git commit --allow-empty -q -m 'unrelated change'"
expect allow "commit after an unrelated heredoc that writes a secret-looking file" Bash "$(bash_in "cat > fixture.txt <<'EOF'${NL}password: $PW${NL}EOF${NL}$CMT_OK")"
expect allow "commit after a tee heredoc that writes a secret-looking file"        Bash "$(bash_in "tee fixture.txt <<EOF${NL}DB_PASSWORD=$PW${NL}EOF${NL}$CMT_OK")"
expect ask   "secret in the message still asks after such a heredoc"               Bash "$(bash_in "cat > fixture.txt <<'EOF'${NL}hello${NL}EOF${NL}git commit -m 'add config password=$PW'")"
expect ask   "heredoc then git add then commit still asks (the file is committed)" Bash "$(bash_in "cat > fixture.txt <<'EOF'${NL}password: $PW${NL}EOF${NL}git add fixture.txt && $CMT_OK")"
expect ask   "heredoc then commit -a still asks"                                   Bash "$(bash_in "cat > fixture.txt <<'EOF'${NL}password: $PW${NL}EOF${NL}git commit -a -q -m x")"
expect ask   "heredoc then commit with a pathspec still asks"                      Bash "$(bash_in "cat > fixture.txt <<'EOF'${NL}password: $PW${NL}EOF${NL}git commit -q -m x -- fixture.txt")"
expect ask   "a heredoc fed to a shell is still scanned"                           Bash "$(bash_in "bash <<'EOF'${NL}echo password: $PW${NL}EOF${NL}$CMT_OK")"
expect ask   "off switch: the writing heredoc is scanned again"                    Bash "$(bash_in "cat > fixture.txt <<'EOF'${NL}password: $PW${NL}EOF${NL}$CMT_OK")" GUARDS_PUBLISH_COMMIT_SCOPE=0
# a route string that ends in a credential word is a path, not a key
ROUTE_A="/v1/secret"; ROUTE_B="/api/v1/secret"
expect allow "route string with a custom-method colon in a commit message"         Bash "$(bash_in "git commit --allow-empty -q -m 'document the ${ROUTE_A}:rotate route'")"
expect allow "route string followed by prose in a commit message"                  Bash "$(bash_in "git commit --allow-empty -q -m 'GET ${ROUTE_B}: returns the stored value'")"
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
# A private key is a sure thing and needs no gitleaks (the private-key pass is deterministic).
{ printf 'DB_PASSWORD=%s\n' "$PW"; cat "$T/key.pem"; } > "$T/mixed.md"
cp "$T/key.pem" "$T/keyonly.md"
expect deny  "a private key in an issue body is a sure thing"      Bash "$(bash_in "gh issue create -R o/r --title t --body-file $T/keyonly.md")"
expect deny  "ambiguous AND sure thing together denies"            Bash "$(bash_in "gh issue create -R o/r --title t --body-file $T/mixed.md")"
# A vendor token format is a sure thing too, but only gitleaks knows those.
if command -v gitleaks >/dev/null 2>&1; then
  expect deny  "a vendor token format is a sure thing (gitleaks)"  Bash "$(bash_in "gh issue create -R o/r --title t --body 'token ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'")"
fi
expect deny  "GUARDS_PUBLISH_ASK=0 restores the hard block" Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")" GUARDS_PUBLISH_ASK=0
out="$(jq -n --arg c "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'" --arg cwd "$T/repo" '{tool_name:"Bash",tool_input:{command:$c},cwd:$cwd}' | bash "$HOOK")"
msg="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
if [[ "$msg" == *"SHAPE"* && "$msg" == *secret-lead-in* && "$msg" != *"$PW"* ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: ask message names the rule, explains the choice and never echoes the value"; fi

# --- an ask needs a person: in modes with nobody to answer, ambiguous matches deny ---
# (live finding: in auto mode a command with a fake password ran straight through an ask)
for PM_MODE in auto bypassPermissions dontAsk ""; do
  expect deny  "ambiguous match denies in permission mode '${PM_MODE:-unknown}'" Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")"
done
expect allow "a clean post is still allowed in auto mode" Bash "$(bash_in "gh issue create -R o/r --title t --body 'nothing sensitive here'")"
for PM_MODE in default acceptEdits plan; do
  expect ask   "ambiguous match asks in permission mode '$PM_MODE'" Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")"
done
PM_MODE=auto
expect ask   "GUARDS_PUBLISH_ASK=force asks even in auto mode" Bash "$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")" GUARDS_PUBLISH_ASK=force
out="$(jq -n --arg c "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'" --arg cwd "$T/repo" '{tool_name:"Bash",tool_input:{command:$c},cwd:$cwd,permission_mode:"auto"}' | bash "$HOOK")"
msg="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
if [[ "$msg" == *"no person to answer"* && "$msg" == *auto* && "$msg" != *"$PW"* ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: the deny explains that no person could be asked, and never echoes the value"; fi
PM_MODE=default

# The working directory lives in PWD, a name that matches the PW alias; live testing found a
# command that merely contained the cwd hard-blocked as an env-value credential.
expect allow "a post that mentions the working directory is not an env-value hit" Bash "$(bash_in "gh issue comment 3 --body 'logs are in $T/repo/out.txt'")" PWD="$T/repo"

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

# --- where the match is: located, value-free explanations -----------------------
# Every repo below is a throwaway under $T. The hook is run as the agent would
# see it: auto mode (no person to ask), a session cwd, a command.
mkrepo() { # mkrepo DIR -- a repo with one commit
  mkdir -p "$1" && ( cd "$1" && git init -q . && git config user.email t@example.invalid && git config user.name t \
    && echo base > README.md && git add README.md && git commit -q -m base )
}
decide() { # decide CWD COMMAND [ENV...] -> deny|ask|allow; the reason (or notice) lands in $T/last.msg
  local cwd="$1" cmd="$2" out d
  shift 2
  out="$(jq -n --arg c "$cmd" --arg cwd "$cwd" '{tool_name:"Bash",tool_input:{command:$c},cwd:$cwd,permission_mode:"auto"}' \
    | env -u GUARDS_ALLOW_PUBLISH_SECRETS "$@" bash "$HOOK")"
  d="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2>/dev/null)"
  printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // .hookSpecificOutput.additionalContext // ""' > "$T/last.msg" 2>/dev/null
  case "$d" in deny|ask) echo "$d" ;; *) echo allow ;; esac
}
check() { # check DESC CONDITION-EXIT-STATUS
  if [ "$2" -eq 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1"; fi
}
want() { # want WANT DESC CWD COMMAND [ENV...]
  local w="$1" desc="$2" got
  got="$(decide "${@:3}")"
  if [ "$got" = "$w" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $desc (wanted $w, got $got)"; fi
}
has() { [[ "$(cat "$T/last.msg")" == *"$1"* ]]; }

LR="$T/loc"; mkrepo "$LR"
mkdir -p "$LR/src"
{ echo 'const a = 1;'; echo 'const b = 2;'; printf 'db_password: "%s"\n' "$PW"; echo 'const c = 3;'; printf 'api_secret = "%s"\n' "$PW"; } > "$LR/src/cfg.ts"  # guards:synthetic
git -C "$LR" add -A
want deny "unmarked staged lines are denied" "$LR" 'git commit -m "add cfg"'
has "the staged diff, file src/cfg.ts, line 3: db_password: \"***REDACTED:SECRET***\""; check "message locates the first staged line (file, line number, redacted line)" $?
has "the staged diff, file src/cfg.ts, line 5: api_secret = \"***REDACTED:SECRET***\""; check "message locates the second staged line" $?
has "first 2 of 2"; check "message counts the matches" $?
! has "$PW"; check "message never contains the value (staged diff)" $?
has "guards:synthetic"; check "message names the marker" $?
has "added lines of the staged diff of a git commit"; check "message says what the marker covers" $?
has "NOT cover the command text"; check "message says what the marker does not cover" $?
has "STARTED"; check "message says the override only works from the starting environment" $?
has "SHAPE"; check "message keeps the shape advice" $?

# Marker semantics: honoured for added lines of the staged diff, nothing else.
sed 's|$| # guards:synthetic|' "$LR/src/cfg.ts" > "$LR/src/cfg.ts.new" && mv "$LR/src/cfg.ts.new" "$LR/src/cfg.ts"  # not sed -i: BSD sed needs a suffix argument
git -C "$LR" add -A
want allow "the marker on the same line allows the staged line" "$LR" 'git commit -m "add cfg"'
git -C "$LR" reset -q
printf 'db_password: "%s"\n' "$PW" > "$LR/src/cfg.ts"  # guards:synthetic
git -C "$LR" add -A
want deny  "inline GUARDS_ALLOW_PUBLISH_SECRETS=1 on an unmarked staged line still denies" "$LR" 'GUARDS_ALLOW_PUBLISH_SECRETS=1 git commit -m "add cfg"'
want allow "the real environment override still works" "$LR" 'git commit -m "add cfg"' GUARDS_ALLOW_PUBLISH_SECRETS=1
git -C "$LR" reset -q
rm -f "$LR/src/cfg.ts"

# The marker does not cover the command text or a file named by the command.
printf 'src/ok.ts\n' > "$LR/clean.txt"; git -C "$LR" add clean.txt
want deny "a marker in the command text does not excuse a -m message" "$LR" "git commit -m 'DB_PASSWORD=$PW # guards:synthetic'"
has "the command text (for a git commit this includes the -m message), line 1: "; check "message locates a match in the command text" $?
! has "$PW"; check "message never contains the value (command text)" $?
printf 'password: "%s" # guards:synthetic\n' "$PW" > "$LR/msg.txt"
want deny "a marker in a -F message file does not excuse it" "$LR" 'git commit -F msg.txt'
has "msg.txt (named by the command), line 1: password: \"***REDACTED:SECRET***\""; check "message locates a match in a named file" $?
! has "$PW"; check "message never contains the value (named file)" $?
# Stock macOS has no `realpath -m`: a relative file the command names must still be found and scanned.
mkdir -p "$T/noreal"
printf '#!/bin/sh\ncase "$1" in -m) echo "realpath: illegal option -- m" >&2; exit 1 ;; esac\nexec /bin/realpath "$@"\n' > "$T/noreal/realpath"
chmod +x "$T/noreal/realpath"
want deny "a named relative file is still scanned when realpath has no -m" "$LR" 'git commit -F msg.txt' "PATH=$T/noreal:$PATH"
has "msg.txt (named by the command), line 1"; check "message locates a named file without realpath -m" $?
git -C "$LR" reset -q; rm -f "$LR/clean.txt" "$LR/msg.txt"

# More than 5 matches: only the first 5 are listed.
{ for i in 1 2 3 4 5 6 7; do printf 'password%s = "%s"\n' "$i" "$PW"; done; } > "$LR/many.ts"  # guards:synthetic
git -C "$LR" add many.ts
want deny "seven unmarked lines" "$LR" 'git commit -m many'
has "first 5 of 7"; check "message caps the list at 5 and says how many there are" $?
[ "$(grep -c '^  [0-9]\. ' "$T/last.msg")" -eq 5 ]; check "exactly 5 locations are listed" $?
git -C "$LR" reset -q; rm -f "$LR/many.ts"

# No value leak for the other rule kinds: a private key, a value from the environment.
cp "$T/key.pem" "$LR/leak.pem"; git -C "$LR" add leak.pem
want deny "a staged private key" "$LR" 'git commit -m key'
KEYBODY="$(sed -n 2p "$T/key.pem")"
! has "$KEYBODY"; check "message never contains private key material" $?
git -C "$LR" reset -q; rm -f "$LR/leak.pem"
want deny "a bare value from the session environment in a message" "$LR" "git commit -m 'it printed $PW and failed'" MY_SERVICE_TOKEN="$PW"
! has "$PW"; check "message never contains an environment value" $?

# --- reporter variants: a marked fixture must not be denied -------------------------
VR="$T/var"; mkrepo "$VR"; mkdir -p "$VR/src"
fixture() { printf 'db_password: "%s"%s\n' "$PW" "$1"; }  # guards:synthetic
fixture ' // guards:synthetic' > "$VR/src/a.ts"
git -C "$VR" add -A
want allow "marked fixture: plain commit"                    "$VR" 'git commit -m x'
want allow "marked fixture: git -C from another cwd"         "/" "git -C $VR commit -m x"
want allow "marked fixture: cd && commit from another cwd"   "/" "cd $VR && git commit -m x"
want allow "marked fixture: quoted cd"                       "/" "cd '$VR' && git commit -m x"
want allow "marked fixture: relative cd"                     "$(dirname "$VR")" "cd $(basename "$VR") && git commit -m x"
want allow "marked fixture: git -c k=v commit"               "$VR" 'git -c user.name=x commit -m x'
want allow "marked fixture: --amend"                         "$VR" 'git commit --amend --no-edit'
want allow "marked fixture: -a"                              "$VR" 'git commit -a -m x'
want allow "marked fixture: -am"                             "$VR" 'git commit -am x'
want allow "marked fixture: a message that contains ' -a'"   "$VR" 'git commit -m "use -a to skip it"'
# CRLF file, # style marker, several files
fixture ' # guards:synthetic' | sed 's/$/\r/' > "$VR/src/crlf.py"
fixture ' # guards:synthetic' > "$VR/src/b.py"
git -C "$VR" add -A
want allow "marked fixture: CRLF file and # marker"          "$VR" 'git commit -m x'
# A marked line next to unmarked related lines (the multi-line rules join lines).
{ echo 'db_password:'; printf '  %s # guards:synthetic\n' "$PW"; echo 'next: 1'; } > "$VR/src/y.yaml"  # guards:synthetic
git -C "$VR" add -A
want allow "marked value line below an unmarked key line"    "$VR" 'git commit -m x'
git -C "$VR" reset -q; rm -f "$VR/src/crlf.py" "$VR/src/b.py" "$VR/src/y.yaml"

# The session cwd is one repo, the commit goes to another: the cwd repo's staged
# lines are not the commit's. (cd with quotes, git -C with quotes, pushd.)
OR="$T/other"; mkrepo "$OR"; fixture '' > "$OR/unmarked.ts"; git -C "$OR" add -A
git -C "$VR" add -A
want deny  "control: the session's own repo has an unmarked staged line" "$OR" 'git commit -m x'
want deny  "git -c k=v commit and git --no-pager commit are scanned too" "$OR" 'git -c user.name=x --no-pager commit -m x'
want allow "cd 'quoted' to the marked repo"                 "$OR" "cd '$VR' && git commit -m x"
want allow "git -C 'quoted' to the marked repo"              "$OR" "git -C '$VR' commit -m x"
want allow "pushd to the marked repo"                        "$OR" "pushd $VR >/dev/null && git commit -m x"
want allow "(cd ...; git commit) subshell"                   "$OR" "(cd $VR; git commit -m x)"
want allow "GIT_DIR and GIT_WORK_TREE"                       "$OR" "GIT_DIR=$VR/.git GIT_WORK_TREE=$VR git commit -m x"
want allow "--git-dir and --work-tree"                       "$OR" "git --git-dir=$VR/.git --work-tree=$VR commit -m x"
git -C "$OR" reset -q

# git add and git commit in one command: the add has not run yet, so the index
# the hook sees is stale. The add is replayed against a copy of the index.
SR="$T/stale"; mkrepo "$SR"; mkdir -p "$SR/src"
fixture '' > "$SR/src/s.ts"; git -C "$SR" add -A
fixture ' // guards:synthetic' > "$SR/src/s.ts"
want deny  "control: the index still holds the unmarked version" "$SR" 'git commit -m x'
want allow "git add -A && git commit sees the marker just added" "$SR" 'git add -A && git commit -m x'
want allow "git add path && git commit sees the marker just added" "$SR" 'git add src/s.ts && git commit -m x'
git -C "$SR" reset -q
fixture '' > "$SR/src/new.ts"
want deny  "git add -A && git commit scans a new unmarked file" "$SR" 'git add -A && git commit -m x'
fixture ' // guards:synthetic' > "$SR/src/new.ts"
want allow "git add -A && git commit with the new file marked" "$SR" 'git add -A && git commit -m x'
[ -z "$(git -C "$SR" diff --cached --name-only)" ]; check "the replayed add did not touch the real index" $?

# A very large diff: only the first MAX bytes are scanned, and the hook says so.
BR="$T/big"; mkrepo "$BR"
for i in $(seq 1 40); do echo "const line$i = $i; // filler text to take up room in the diff"; done > "$BR/big.ts"
git -C "$BR" add -A
want allow "a diff over the byte cap is allowed when what is scanned is clean" "$BR" 'git commit -m x' PUBLISH_GUARD_MAX_BYTES=300
has "only the first 300 bytes were scanned"; check "an oversize diff says it was cut" $?

# --- the marker is not a way to commit a real vendor credential or key ----------
# Marked lines are dropped from the context scan but still held against a few
# sure-thing shapes. Every value is built at run time; none is written here.
MR="$T/marked"; mkrepo "$MR"
mark_commit() { # mark_commit LINE -- stage one marked line in a fresh file
  printf '%s // guards:synthetic\n' "$1" > "$MR/fx.ts"
  git -C "$MR" add -A
}
rnd() { head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
HDR="$(printf -- '-----BEGIN %s-----' "$(printf 'EC %s' 'PRIVATE KEY')")"
mark_commit "const pem = '$HDR';"
want deny "a marked private-key header is denied" "$MR" 'git commit -m fx'
has "marked guards:synthetic looks like a REAL vendor credential or key"; check "message says a marked line looks like a real credential" $?
has "the staged diff, file fx.ts, line 1: private-key header"; check "message names the file, line and family" $?
! has "BEGIN"; check "message does not echo the matched header" $?
GHT="gh$(printf 'p')_$(rnd 36)"
mark_commit "const t = \"$GHT\";"
want deny "a marked GitHub-token-shaped value is denied" "$MR" 'git commit -m fx'
has "GitHub token"; check "message names the GitHub family" $?
! has "$GHT"; check "message never contains the marked token" $?
mark_commit "const a = \"AKIA$(rnd 16 | tr 'a-z' 'A-Z')\";"
want deny "a marked AWS-access-key-id-shaped value is denied" "$MR" 'git commit -m fx'
mark_commit "const s = \"xoxb-$(rnd 24)\";"
want deny "a marked Slack-token-shaped value is denied" "$MR" 'git commit -m fx'
mark_commit "const k = \"sk_live_$(rnd 24)\";"
want deny "a marked live-key-shaped value is denied" "$MR" 'git commit -m fx'
mark_commit "const k = \"sk-proj-$(rnd 30)\";"
want deny "a marked sk-proj-shaped value is denied" "$MR" 'git commit -m fx'
mark_commit "const a = \"AKIAIOSFODNN7EXAMPLE\";"
want allow "the documented AWS example id is accepted on a marked line" "$MR" 'git commit -m fx'
mark_commit "const a = \"AKIA$(rnd 8 | tr 'a-z' 'A-Z')FAKE$(rnd 4 | tr 'a-z' 'A-Z')\";"
want allow "a marked value containing FAKE is accepted" "$MR" 'git commit -m fx'
mark_commit "const j = \"eyJhbGciOiJIUzI1NiJ9.$(rnd 30).$(rnd 40)\";"
want allow "a marked JWT-shaped string is accepted" "$MR" 'git commit -m fx'
mark_commit "const o = { client_secret: \"$(rnd 20)\" };"
want allow "a marked ordinary fixture is accepted" "$MR" 'git commit -m fx'
printf 'const t = "%s"\n' "$GHT" > "$MR/fx.ts"; git -C "$MR" add -A
if command -v gitleaks >/dev/null 2>&1; then
  want deny "control: the same token unmarked is denied by the normal scan" "$MR" 'git commit -m fx'
fi
git -C "$MR" reset -q

# --- approve-once (coordination#124, part B): in auto mode the person can approve one blocked text, once ---
APPROVE="$HERE/../bin/guards-approve.sh"
hook_out() { # hook_out TOOL INPUT_JSON [ENV...] -> the hook's raw JSON output
  jq -n --arg t "$1" --argjson i "$2" --arg cwd "$T/repo" --arg pm "$PM_MODE" '{tool_name:$t, tool_input:$i, cwd:$cwd, permission_mode:$pm}' \
    | env "${@:3}" bash "$HOOK"
}
decision() { local d; d="$(jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null)"; echo "${d:-allow}"; }   # a hook that prints nothing allows
AMB="$(bash_in "gh issue create -R o/r --title t --body 'DB_PASSWORD=$PW'")"   # an ambiguous rule: a key name beside a value
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
APPROVALS="$HOME/.local/share/gramatr-guards"
PM_MODE=auto

o="$(hook_out Bash "$AMB")"
[ "$(printf '%s' "$o" | decision)" = deny ] && ok || bad "approve: auto mode denies an ambiguous match first"
msg="$(printf '%s' "$o" | jq -r '.hookSpecificOutput.permissionDecisionReason')"
AID="$(printf '%s' "$msg" | grep -oE 'guards-approve\.sh [0-9a-f]{16}' | head -n1 | awk '{print $2}')"
[ -n "$AID" ] && ok || bad "approve: the deny names an approval id and the command to run"
[[ "$msg" == *"only the PERSON"* && "$msg" == *"Fix:"* && "$msg" != *"$PW"* ]] && ok || bad "approve: the deny says who approves, has a Fix clause, and holds no value"
[ "$(hook_out Bash "$AMB" | decision)" = deny ] && ok || bad "approve: still denied before the person approves"

out="$(bash "$APPROVE" "$AID" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && [[ "$out" == *"Approving once"* && "$out" == *"secret-lead-in"* && "$out" != *"$PW"* ]] && ok || bad "approve: the command shows what is approved, without the value (rc $rc)"
o="$(hook_out Bash "$AMB")"
[ "$(printf '%s' "$o" | decision)" = allow ] && ok || bad "approve: the identical retry passes after the person approves"
[[ "$(printf '%s' "$o" | jq -r '.hookSpecificOutput.additionalContext // ""')" == *"allowed once by the person"* ]] && ok || bad "approve: the pass says it was the person's approval"
[ "$(hook_out Bash "$AMB" | decision)" = deny ] && ok || bad "approve: an approval is single-use (the next retry is denied)"

AMB2="$(bash_in "gh issue create -R o/r --title t2 --body 'DB_PASSWORD=$PW'")"
bash "$APPROVE" "$AID" >/dev/null 2>&1
[ "$(hook_out Bash "$AMB2" | decision)" = deny ] && ok || bad "approve: a changed text needs its own approval"
bash "$APPROVE" "$AID" >/dev/null 2>&1   # the earlier id is spent and now approved again for the first text only
[ "$(hook_out Bash "$AMB" | decision)" = allow ] && ok || bad "approve: the same id approves the same text again when re-approved"

# expiry: an approval already past its time is refused and removed
o="$(hook_out Bash "$AMB2")"; AID2="$(printf '%s' "$o" | jq -r '.hookSpecificOutput.permissionDecisionReason' | grep -oE 'guards-approve\.sh [0-9a-f]{16}' | head -n1 | awk '{print $2}')"
GUARDS_APPROVE_TTL=-30 bash "$APPROVE" "$AID2" >/dev/null 2>&1
[ "$(hook_out Bash "$AMB2" | decision)" = deny ] && ok || bad "approve: an expired approval does not pass"
[ ! -e "$APPROVALS/approvals/$AID2" ] && ok || bad "approve: an expired approval is removed"

# the MCP checker reports without using the approval up
o="$(hook_out Bash "$AMB2")"; AID3="$(printf '%s' "$o" | jq -r '.hookSpecificOutput.permissionDecisionReason' | grep -oE 'guards-approve\.sh [0-9a-f]{16}' | head -n1 | awk '{print $2}')"
bash "$APPROVE" "$AID3" >/dev/null 2>&1
[ "$(hook_out Bash "$AMB2" GUARDS_PUBLISH_GUARD_REPORT=1 | decision)" = allow ] && ok || bad "approve: the checker sees the approval"
[ "$(hook_out Bash "$AMB2" | decision)" = allow ] && ok || bad "approve: the checker did not use the approval up"
[ "$(hook_out Bash "$AMB2" | decision)" = deny ] && ok || bad "approve: the real attempt used it up"

# never for a sure thing, and not when switched off or when an operator wants hard blocks
o="$(hook_out Bash "$(bash_in "gh gist create $T/key.pem")")"
[ "$(printf '%s' "$o" | decision)" = deny ] && ok || bad "approve: a private key is denied"
[[ "$(printf '%s' "$o" | jq -r '.hookSpecificOutput.permissionDecisionReason')" != *guards-approve* ]] && ok || bad "approve: a sure-thing match is never offered for approval"
o="$(hook_out Bash "$AMB" GUARDS_PUBLISH_APPROVE=0)"
[ "$(printf '%s' "$o" | decision)" = deny ] && [[ "$(printf '%s' "$o" | jq -r '.hookSpecificOutput.permissionDecisionReason')" != *guards-approve* ]] && ok || bad "approve: GUARDS_PUBLISH_APPROVE=0 restores the plain deny"
o="$(hook_out Bash "$AMB" GUARDS_PUBLISH_ASK=0)"
[[ "$(printf '%s' "$o" | jq -r '.hookSpecificOutput.permissionDecisionReason')" != *guards-approve* ]] && ok || bad "approve: GUARDS_PUBLISH_ASK=0 stays a hard block"

# an agent cannot answer its own block
for c in "bash /x/guards/bin/guards-approve.sh 0123456789abcdef" "echo 99999999999 > $APPROVALS/approvals/0123456789abcdef" "cat $APPROVALS/pending/0123456789abcdef" "cd /x && ./guards-approve.sh --list"; do
  [ "$(hook_out Bash "$(bash_in "$c")" | decision)" = deny ] && ok || bad "approve: an agent command is refused: $c"
done
[ "$(hook_out Bash "$(bash_in "ls -la")" | decision)" = allow ] && ok || bad "approve: an unrelated command is untouched"

# the command's own checks
bash "$APPROVE" notanid >/dev/null 2>&1; [ $? -eq 2 ] && ok || bad "approve: a malformed id is refused"
bash "$APPROVE" 0123456789abcdef >/dev/null 2>&1; [ $? -eq 1 ] && ok || bad "approve: an unknown id is refused"
[[ "$(bash "$APPROVE" --list 2>&1)" == *"secret-lead-in"* ]] && ok || bad "approve: --list shows what is waiting"
grep -q "secret-lead-in" "$APPROVALS/approvals.log" 2>/dev/null && ! grep -q "$PW" "$APPROVALS/approvals.log" && ok || bad "approve: each use is logged by rule, without text"
[ "$(stat -c %a "$APPROVALS/approvals" 2>/dev/null || stat -f %Lp "$APPROVALS/approvals")" = 700 ] && ok || bad "approve: the store is private to the user"

# a person present (default mode) still gets the normal ask
PM_MODE=default
[ "$(hook_out Bash "$AMB" | decision)" = ask ] && ok || bad "approve: default mode still asks the person"

echo "publish-guard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
