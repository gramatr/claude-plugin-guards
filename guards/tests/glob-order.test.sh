#!/usr/bin/env bash
# guards/tests/glob-order.test.sh -- a glob in a command is expanded in sorted order.
#
# `compgen -G` returns files in an order that is neither sorted nor the directory's
# own order, and it differs between machines (bash 5.1 and 5.2, ext4, APFS). The
# credential-file and outbound guards expand a glob with it and look at the first 20
# matches, so an unsorted result made two things arbitrary: which credential file the
# message named, and which 20 files were checked when more matched. It failed a golden
# test at random in CI. The expansion is now piped through `sort` (C locale).
#
#   1. static: every `compgen -G` in the hooks is followed by a sort;
#   2. dynamic: with a `compgen` that answers in reverse order (loaded through
#      BASH_ENV), the credential-file guard still names the first key in sorted order.
# Fabricated keys from ssh-keygen. Needs bash, jq, ssh-keygen.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="${GUARDS_HOOKS_DIR:-$HERE/../hooks}"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

# --- 1. static ---------------------------------------------------------------------
for f in "$HOOKS"/*.sh; do
  while IFS= read -r line; do
    case "$line" in *"| LC_ALL=C sort"*) ok ;; *) bad "${f##*/}: compgen -G is not sorted: $(printf '%s' "$line" | sed -E 's/^[[:space:]]+//' | cut -c1-110)" ;; esac
  done < <(grep -h -F 'compgen -G' "$f" | grep -v '^[[:space:]]*#')
done

# --- 2. dynamic --------------------------------------------------------------------
T="$(mktemp -d)"; T="$(cd "$T" && pwd -P)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.ssh" "$HOME/proj"
ssh-keygen -q -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519" -C throwaway
ssh-keygen -q -t rsa -b 2048 -m PEM -N "" -f "$HOME/.ssh/id_rsa" -C throwaway
printf 'Host x\n  HostName example.invalid\n' > "$HOME/.ssh/config"

# A compgen that answers in reverse sorted order: the worst order for this test.
cat > "$T/reverse-compgen.sh" << 'EOF'
compgen() {
  if [ "$1" = "-G" ]; then
    builtin compgen -G "$2" | LC_ALL=C sort -r
  else
    builtin compgen "$@"
  fi
}
EOF

run() { # run COMMAND -> the permissionDecisionReason of credfile-guard
  jq -nc --arg c "$1" --arg cwd "$HOME/proj" '{tool_name:"Bash",permission_mode:"auto",cwd:$cwd,tool_input:{command:$c}}' \
    | env BASH_ENV="$T/reverse-compgen.sh" bash "$HOOKS/credfile-guard.sh" 2> /dev/null \
    | jq -r '.hookSpecificOutput.permissionDecisionReason // ""'
}

# Sanity: the stub really reverses (otherwise this test proves nothing).
rev="$(env BASH_ENV="$T/reverse-compgen.sh" bash -c 'compgen -G "$HOME/.ssh/id_*" | head -1')"
case "$rev" in *id_rsa.pub) ok ;; *) bad "the reverse-order stub does not reverse (first match: $rev)" ;; esac

text="$(run 'cat ~/.ssh/*')"
case "$text" in *.ssh/id_ed25519*) ok ;; *) bad "an unsorted compgen made the guard name the wrong key (wanted .ssh/id_ed25519 first): ${text:0:200}" ;; esac
case "$text" in *.ssh/id_rsa*) bad "the guard named id_rsa, which sorts after id_ed25519 (${text:0:200})" ;; *) ok ;; esac

echo "glob-order: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
