#!/usr/bin/env bash
# guards/tests/credfile-diff.test.sh -- credfile-guard behaves byte-for-byte as
# it did before its classification moved into credclass-lib.sh.
#
# A fixed set of Read/Grep/Bash payloads is run through the hook in each of the
# four permission modes (default, acceptEdits, plan, auto). The sha256 of every
# stdout is compared with credfile-diff.golden, which was generated from the
# ORIGINAL monolithic hook (v0.2.9, commit 6a6eaca). When that commit is
# reachable in this checkout the original is also run live and compared byte for
# byte; CI with a shallow clone relies on the golden file alone.
#
#   bash guards/tests/credfile-diff.test.sh                # check
#   bash guards/tests/credfile-diff.test.sh --regen HOOK   # rewrite the golden file from HOOK
#
# Outputs can carry glob-expanded absolute paths, so the temp HOME is replaced
# by <HOME> before hashing. Fixtures are generated at run time; keys come from ssh-keygen /
# openssl and have never been used for anything. Also checks the hot-path
# fallback: with credclass-lib.sh missing the hook must deny, naming the file.
#
# Needs: bash, jq, ssh-keygen, openssl, realpath, sha256sum (or shasum).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="$HERE/../hooks"
GOLDEN="$HERE/credfile-diff.golden"
OLD_REF="6a6eaca"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.ssh" "$HOME/.aws" "$HOME/.kube" "$HOME/proj/sub" "$HOME/.config/gcloud" "$HOME/.docker"
ssh-keygen -q -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519" -C throwaway
ssh-keygen -q -t rsa -b 2048 -m PEM -N "" -f "$HOME/.ssh/id_rsa" -C throwaway
openssl ecparam -genkey -name prime256v1 -noout -out "$HOME/proj/innocuous-name.txt" 2>/dev/null
printf 'aws_secret_access_key = not-a-real-secret\n' > "$HOME/.aws/credentials" # guards:synthetic
printf 'Host x\n  HostName example.invalid\n' > "$HOME/.ssh/config"
printf 'clusters: []\n' > "$HOME/.kube/config"
printf '{}\n' > "$HOME/.docker/config.json"
printf 'KEY=value\n' > "$HOME/proj/.env"
printf 'KEY=changeme\n' > "$HOME/proj/.env.example"
printf 'hello\n' > "$HOME/proj/README.md"
printf 'x\n' > "$HOME/proj/sub/notes.txt"

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }

# TOOL<TAB>tool_input JSON. Names are positional: case N.
CASES=(
  'Read	{"file_path":"~/.ssh/id_ed25519"}'
  'Read	{"file_path":"~/.ssh/id_rsa"}'
  'Read	{"file_path":"~/.ssh/id_ed25519.pub"}'
  'Read	{"file_path":"~/.ssh/config"}'
  'Read	{"file_path":"$HOME/.aws/credentials"}'
  'Read	{"file_path":"${HOME}/.kube/config"}'
  'Read	{"file_path":"~/.docker/config.json"}'
  'Read	{"file_path":".env"}'
  'Read	{"file_path":".env.example"}'
  'Read	{"file_path":"innocuous-name.txt"}'
  'Read	{"file_path":"README.md"}'
  'Read	{"file_path":"sub/../.env"}'
  'Read	{"file_path":"/nonexistent/dir/file.txt"}'
  'Read	{"file_path":""}'
  'Read	{}'
  'Grep	{"pattern":"x","path":"~/.ssh"}'
  'Grep	{"pattern":"x","path":"~/.aws/credentials"}'
  'Grep	{"pattern":"x","path":"."}'
  'Grep	{"pattern":"x","path":"sub"}'
  'Grep	{"pattern":"x","glob":"*.env"}'
  'Grep	{"pattern":"x","glob":"*.env.example"}'
  'Grep	{"pattern":"x","glob":"*.pem"}'
  'Grep	{"pattern":"x","glob":"id_rsa*"}'
  'Grep	{"pattern":"x","glob":"*.md"}'
  'Grep	{"pattern":"x","path":"innocuous-name.txt"}'
  'Bash	{"command":"cat ~/.ssh/id_ed25519"}'
  'Bash	{"command":"cat ~/.ssh/id_rsa.pub"}'
  'Bash	{"command":"head -n 3 .env"}'
  'Bash	{"command":"cat .env.example"}'
  'Bash	{"command":"cat README.md"}'
  'Bash	{"command":"ls -la"}'
  'Bash	{"command":"echo hello"}'
  'Bash	{"command":"ssh -i ~/.ssh/id_ed25519 host.invalid true"}'
  'Bash	{"command":"ssh-keygen -l -f ~/.ssh/id_ed25519"}'
  'Bash	{"command":"grep -r token ~/.aws"}'
  'Bash	{"command":"cat ~/.ssh/*"}'
  'Bash	{"command":"cat .en?"}'
  'Bash	{"command":"base64 \"$HOME/.kube/config\""}'
  'Bash	{"command":"cat innocuous-name.txt | wc -c"}'
  'Bash	{"command":"awk 1 sub/notes.txt; cat ~/.docker/config.json"}'
  'Bash	{"command":"python3 -c \"print(open('.env').read())\""}'
  'Bash	{"command":"cat ~/.ssh/config"}'
  'Bash	{"command":"tail -5 ~/.aws/credentials && echo done"}'
  'Bash	{"command":""}'
  'Bash	{}'
  'Write	{"file_path":"~/.ssh/id_ed25519"}'
)
MODES=(default acceptEdits plan auto)

payload() { # payload TOOL INPUT MODE
  jq -nc --arg t "$1" --argjson i "$2" --arg cwd "$HOME/proj" --arg m "$3" \
    '{tool_name: $t, tool_input: $i, cwd: $cwd, permission_mode: $m}'
}

# results HOOK -> "case mode sha" lines
results() {
  local hook="$1" n=0 c tool input m
  for c in "${CASES[@]}"; do
    n=$((n + 1)); tool="${c%%	*}"; input="${c#*	}"
    for m in "${MODES[@]}"; do
      printf '%s %s %s\n' "$n" "$m" "$(payload "$tool" "$input" "$m" | bash "$hook" 2>&1 | sed "s|$HOME|<HOME>|g" | sha)"
    done
  done
}

if [ "${1:-}" = "--regen" ]; then
  results "$2" > "$GOLDEN" && echo "wrote $GOLDEN ($(wc -l < "$GOLDEN") lines)"
  exit 0
fi

pass=0 fail=0
check() { if [ "$2" = "$3" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $1"; fi; }

new="$(results "$HOOKS/credfile-guard.sh")"
total="$(printf '%s\n' "$new" | wc -l)"
while IFS= read -r line; do
  want="$(grep -F -x -m1 -e "${line% *}"' '"${line##* }" "$GOLDEN" || true)"
  check "case/mode ${line% *} differs from the golden output" "$line" "$want"
done <<< "$new"
check "golden file has one line per case and mode" "$total" "$(wc -l < "$GOLDEN" | tr -d ' ')"
check "at least 40 payloads" yes "$([ "${#CASES[@]}" -ge 40 ] && echo yes || echo no)"

# Live differential against the original hook when its commit is reachable.
live="skipped (commit $OLD_REF not reachable)"
if git -C "$HERE" cat-file -e "$OLD_REF:guards/hooks/credfile-guard.sh" 2>/dev/null; then
  OLD="$T/old"; mkdir -p "$OLD"
  git -C "$HERE" show "$OLD_REF:guards/hooks/credfile-guard.sh" > "$OLD/credfile-guard.sh"
  cp "$HOOKS/deadline-lib.sh" "$HOOKS/json-lib.sh" "$OLD/"
  check "live differential against $OLD_REF" "$(results "$OLD/credfile-guard.sh")" "$new"
  live="live against $OLD_REF too"
fi

# Hot-path fallback: no classification library means deny, naming the file.
NOLIB="$T/nolib"; mkdir -p "$NOLIB"
cp "$HOOKS/credfile-guard.sh" "$HOOKS/deadline-lib.sh" "$HOOKS/json-lib.sh" "$NOLIB/"
out="$(payload Read '{"file_path":"README.md"}' default | bash "$NOLIB/credfile-guard.sh" 2>/dev/null)"
check "missing lib denies" deny "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // "none"')"
case "$out" in *credclass-lib.sh*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "FAIL: missing-lib deny does not name credclass-lib.sh" ;; esac
out="$(payload Bash '{"command":"echo hi"}' auto | bash "$NOLIB/credfile-guard.sh" 2>/dev/null)"
check "missing lib denies a plain command too" deny "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // "none"')"

echo "credfile-diff: $pass passed, $fail failed (${#CASES[@]} payloads x ${#MODES[@]} modes, $live)"
[ "$fail" -eq 0 ]
