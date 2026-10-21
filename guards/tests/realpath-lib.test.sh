#!/usr/bin/env bash
# guards/tests/realpath-lib.test.sh -- path resolution without GNU `realpath -m`.
#
# macOS `realpath` has no -m. The credential-file guard fell back to the raw
# path, so a symlink to ~/.aws/credentials was not recognised as that file.
# realpath-lib.sh walks the path in bash instead. Here:
#   1. gd_realpath_pure gives the expected result on a tree of real symlinks
#      (absolute, relative, chains, directory links, `..` after a link, a missing
#      tail, a loop that must end), and matches GNU `realpath -m` where that works;
#   2. the real credential-file guard denies a symlink to a credentials file, and
#      allows an ordinary copy, with `realpath` hidden from PATH.
# Fabricated values only.
# Set GUARDS_HOOKS_DIR to run the same checks against another copy of the hooks.
# Needs bash, jq.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="${GUARDS_HOOKS_DIR:-$HERE/../hooks}"
BASH_BIN="$(command -v bash)"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
check() { # check NAME EXPECTED GOT
  if [ "$2" = "$3" ]; then ok; else bad "$1 (wanted '$2', got '$3')"; fi
}

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
T="$(cd "$T" && pwd -P)"   # macOS mktemp lives under a symlinked /var

# A `realpath` that fails the way macOS's does for -m (the hooks then take the bash
# walk). A one-file stub in front of PATH: copying every tool on PATH just to leave
# one out takes minutes on a machine with a big PATH and slow process launches.
NOREAL="$T/noreal"; mkdir -p "$NOREAL"
printf '#!/bin/sh\necho "realpath: illegal option -- m" >&2\nexit 1\n' > "$NOREAL/realpath"; chmod +x "$NOREAL/realpath"
NOREAL_PATH="$NOREAL:$PATH"

# --- 1. the resolver on a real tree -----------------------------------------
mkdir -p "$T/real/dir" "$T/real/dir2" "$T/links"
printf 'x\n' > "$T/real/dir/file.txt"
ln -s "$T/real/dir/file.txt" "$T/links/abs-file"
ln -s ../real/dir/file.txt "$T/links/rel-file"
ln -s ../real/dir "$T/links/dir-link"
ln -s chain2 "$T/links/chain1"
ln -s ../real/dir/file.txt "$T/links/chain2"
ln -s loop-b "$T/links/loop-a"
ln -s loop-a "$T/links/loop-b"
ln -s ../real/nowhere "$T/links/dangling"
ln -s ../real/dir/../dir2 "$T/links/up"
ln -s "$T/real" "$T/links/abs-dir"

F="$T/real/dir/file.txt"
if [ ! -f "$HOOKS/realpath-lib.sh" ]; then
  echo "note: $HOOKS has no realpath-lib.sh (the previous hooks); sections 2 and 3 only"
else
# shellcheck source=guards/hooks/realpath-lib.sh
. "$HOOKS/realpath-lib.sh" || { echo "FAIL: cannot source realpath-lib.sh"; exit 1; }

check "plain file" "$F" "$(gd_realpath_pure "$F")"
check "dot-dot collapses" "$T/real/dir2" "$(gd_realpath_pure "$T/real/dir/../dir2")"
check "dot and double slash" "$F" "$(gd_realpath_pure "$T/real/./dir//file.txt")"
check "absolute symlink" "$F" "$(gd_realpath_pure "$T/links/abs-file")"
check "relative symlink" "$F" "$(gd_realpath_pure "$T/links/rel-file")"
check "file through a directory link" "$F" "$(gd_realpath_pure "$T/links/dir-link/file.txt")"
check "symlink chain" "$F" "$(gd_realpath_pure "$T/links/chain1")"
check "dangling link keeps its target" "$T/real/nowhere" "$(gd_realpath_pure "$T/links/dangling")"
check "link whose target has dot-dot" "$T/real/dir2" "$(gd_realpath_pure "$T/links/up")"
check "absolute directory link" "$F" "$(gd_realpath_pure "$T/links/abs-dir/dir/file.txt")"
check "dot-dot after a directory link is physical" "$T/real/dir2" "$(gd_realpath_pure "$T/links/dir-link/../dir2")"
check "missing tail is kept" "$T/real/dir/missing/y" "$(gd_realpath_pure "$T/real/dir/missing/x/../y")"
check "trailing slash" "$T/real/dir" "$(gd_realpath_pure "$T/real/dir/")"
check "root" "/" "$(gd_realpath_pure "/")"
check "dot-dot above root" "/" "$(gd_realpath_pure "/..")"
check "relative file" "$F" "$(cd "$T/links" && gd_realpath_pure "rel-file")"
check "relative dot-dot" "$T/real/dir" "$(cd "$T/links" && gd_realpath_pure "../real/dir")"
check "relative dot" "$T/links" "$(cd "$T/links" && gd_realpath_pure ".")"
check "relative parent" "$T" "$(cd "$T/links" && gd_realpath_pure "..")"
check "gd_realpath of empty prints nothing" "" "$(gd_realpath "")"

# A loop terminates and gives the input back.
start=$SECONDS
loop_out="$(gd_realpath_pure "$T/links/loop-a")"
check "symlink loop returns the input" "$T/links/loop-a" "$loop_out"
if [ $((SECONDS - start)) -le 3 ]; then ok; else bad "the symlink loop took $((SECONDS - start))s"; fi

# Same answers as GNU realpath -m where it exists.
if realpath -m / > /dev/null 2>&1; then
  for p in "$F" "$T/real/dir/../dir2" "$T/real/./dir//file.txt" "$T/links/abs-file" "$T/links/rel-file" \
    "$T/links/dir-link/file.txt" "$T/links/chain1" "$T/links/dangling" "$T/links/up" \
    "$T/links/abs-dir/dir/file.txt" "$T/links/dir-link/../dir2" "$T/real/dir/missing/x/../y" "$T/real/dir/"; do
    check "same as realpath -m: ${p#"$T"/}" "$(realpath -m -- "$p")" "$(gd_realpath_pure "$p")"
  done
else
  echo "note: realpath -m is not available here; compared with the fixed expectations only"
fi
fi

# --- 2. the credential-file guard sees through a symlink --------------------
H="$T/home"; mkdir -p "$H/.aws" "$H/proj"
printf '[default]\nfake_setting = not-a-real-value\n' > "$H/.aws/credentials"
ln -s "$H/.aws/credentials" "$H/proj/link-to-creds"
cp "$H/.aws/credentials" "$H/proj/plain-copy.txt"
decision() { # decision FILE -> the permissionDecision in the hook output, or "allow" when there is none
  if [ -s "$1" ]; then jq -r '.hookSpecificOutput.permissionDecision // "allow"' < "$1"; else printf 'allow'; fi
}
cred() { # cred PATH  -> the permissionDecision, or "allow"
  printf '{"tool_name":"Read","permission_mode":"default","cwd":"%s/proj","tool_input":{"file_path":"%s"}}' "$H" "$1" \
    | env PATH="$NOREAL_PATH" HOME="$H" "$BASH_BIN" "$HOOKS/credfile-guard.sh" 2> /dev/null > "$T/hook.out"
  decision "$T/hook.out"
}
check "credfile-guard, no realpath: direct path" "deny" "$(cred "$H/.aws/credentials")"
check "credfile-guard, no realpath: symlink to the credentials file" "deny" "$(cred "$H/proj/link-to-creds")"
check "credfile-guard, no realpath: ordinary copy" "allow" "$(cred "$H/proj/plain-copy.txt")"
check "credfile-guard, relative symlink from the project directory" "deny" "$(cred "link-to-creds")"

echo "realpath-lib: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
