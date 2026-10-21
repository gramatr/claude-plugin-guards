#!/usr/bin/env bash
# guards/tests/gitleaks-install.test.sh -- how the self-heal script installs gitleaks.
#
# Extracts ensure_gitleaks and its helpers from bin/guards-selfheal.sh and runs them with a
# stub `curl` (serves fixture files, no network) and a throwaway HOME. Pins (issue #55):
#   - a patched download whose binary hashes to the recorded value is installed, and the
#     upstream release is not touched;
#   - a tampered patched binary (hash mismatch), a missing asset (404), a platform with no
#     recorded hash and a missing hash file each fall back to the upstream release, with a
#     warning, and the upstream install says it is UNPATCHED;
#   - when neither can be installed nothing is installed;
#   - gitleaks already on PATH is left alone, no download.
# The binaries are tiny stand-in scripts; all values are fabricated. Needs bash, tar, awk.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELFHEAL="${SELFHEAL:-$HERE/../bin/guards-selfheal.sh}"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/fix" "$T/shim" "$T/sys" "$T/build"

# The system PATH minus gitleaks, curl and uname (the cases control those).
for d in /usr/local/bin /usr/bin /bin; do
  for f in "$d"/*; do
    n="$(basename "$f")"
    case "$n" in gitleaks|curl|uname) continue ;; esac
    [ -e "$T/sys/$n" ] || ln -s "$f" "$T/sys/$n" 2> /dev/null
  done
done

sha() { if command -v sha256sum > /dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# Fixtures: a patched binary and an upstream binary (stand-in scripts), their tarballs, and
# the upstream checksum file in the upstream layout.
VER="$(sed -n 's/^GITLEAKS_VERSION="\(.*\)"/\1/p' "$SELFHEAL")"
[ -n "$VER" ] || { echo "FAIL: cannot read GITLEAKS_VERSION from $SELFHEAL"; exit 1; }
printf '#!/bin/sh\necho patched\n' > "$T/build/gitleaks"; chmod +x "$T/build/gitleaks"
tar -czf "$T/fix/gitleaks-patched_${VER}_linux_x64.tar.gz" -C "$T/build" gitleaks
PATCHED_SHA="$(sha "$T/build/gitleaks")"
printf '#!/bin/sh\necho upstream\n' > "$T/build/gitleaks"
tar -czf "$T/fix/gitleaks_${VER}_linux_x64.tar.gz" -C "$T/build" gitleaks
UP_TAR_SHA="$(sha "$T/fix/gitleaks_${VER}_linux_x64.tar.gz")"
printf '%s  gitleaks_%s_linux_x64.tar.gz\n' "$UP_TAR_SHA" "$VER" > "$T/fix/gitleaks_${VER}_checksums.txt"
printf '# fixture\n%s  linux_x64\n' "$PATCHED_SHA" > "$T/hashes"

# curl stand-in: serve fixture files by basename; -o is where to write; a missing fixture exits
# 22 (what curl -f does for an HTTP error). Every request is logged.
cat > "$T/shim/curl" << 'CURL'
#!/usr/bin/env bash
out="" url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift ;; http*) url="$1" ;; esac
  shift
done
echo "$url" >> "$CURL_LOG"
f="$FIXTURES/$(basename "$url")"
[ -f "$f" ] || exit 22
cp "$f" "$out"
CURL
cat > "$T/shim/uname" << 'UNAME'
#!/usr/bin/env bash
case "${1:-}" in -s) echo Linux ;; -m) echo "${FAKE_ARCH:-x86_64}" ;; *) echo Linux ;; esac
UNAME
chmod +x "$T/shim/curl" "$T/shim/uname"

# run_case -> sets OUT (the log text), RC (ensure_gitleaks' return code) and INSTALLED (what the
# installed binary prints, empty if none)
run_case() {
  local home="$T/home.$RANDOM"
  mkdir -p "$home"
  : > "$T/curl.log"
  OUT="$(
    {
    export HOME="$home" FIXTURES="$T/fix" CURL_LOG="$T/curl.log"
    export PATH="$T/shim:$T/sys${EXTRA_PATH:+:$EXTRA_PATH}"
    log() { echo "selfheal: $*" >&2; }
    # These are read by the functions sourced below.
    # shellcheck disable=SC2034
    GUARDS_ROOT="$T/root"
    # shellcheck disable=SC2034
    GITLEAKS_VERSION="$VER"
    # shellcheck disable=SC2034
    GITLEAKS_ASSETS_URL="https://assets.invalid"
    # shellcheck disable=SC2034
    GITLEAKS_ASSETS_SHA="${HASHFILE:-$T/hashes}"
    # shellcheck disable=SC1090
    source <(
      sed -n '/^file_sha256() {/,/^}/p;/^_install_patched_in() {/,/^}/p;/^install_patched_gitleaks() {/,/^}/p;/^ensure_gitleaks() {/,/^}/p' "$SELFHEAL"
    )
    ensure_gitleaks
    echo "RC=$?"
    } 2>&1
  )"
  RC="$(printf '%s\n' "$OUT" | sed -n 's/^.*RC=\([0-9]*\)$/\1/p' | tail -n 1)"
  INSTALLED=""
  [ -x "$home/.local/bin/gitleaks" ] && INSTALLED="$("$home/.local/bin/gitleaks" 2> /dev/null)"
  return 0
}

# 1. patched, hash matches
HASHFILE="" FAKE_ARCH=x86_64 run_case
[ "$INSTALLED" = patched ] && ok || bad "a verified patched binary is installed (installed: '$INSTALLED'; $OUT)"
grep -q 'Installed patched gitleaks' <<< "$OUT" && ok || bad "the patched install says so"
grep -q 'checksums' "$T/curl.log" && bad "no upstream request when the patched install works" || ok

# 2. patched binary tampered (hash mismatch) -> upstream, with a warning
cp "$T/fix/gitleaks-patched_${VER}_linux_x64.tar.gz" "$T/patched.good"
printf '#!/bin/sh\necho evil\n' > "$T/build/gitleaks"
tar -czf "$T/fix/gitleaks-patched_${VER}_linux_x64.tar.gz" -C "$T/build" gitleaks
HASHFILE="" FAKE_ARCH=x86_64 run_case
[ "$INSTALLED" = upstream ] && ok || bad "a tampered patched binary is not installed; upstream is (installed: '$INSTALLED')"
grep -q 'does not match the hash' <<< "$OUT" && ok || bad "the mismatch is warned about"
grep -q 'UPSTREAM (unpatched)' <<< "$OUT" && ok || bad "the upstream install says it is unpatched"
cp "$T/patched.good" "$T/fix/gitleaks-patched_${VER}_linux_x64.tar.gz"

# 3. patched asset missing -> upstream
mv "$T/fix/gitleaks-patched_${VER}_linux_x64.tar.gz" "$T/patched.moved"
HASHFILE="" FAKE_ARCH=x86_64 run_case
[ "$INSTALLED" = upstream ] && ok || bad "a missing patched asset falls back to upstream (installed: '$INSTALLED')"
grep -q 'is not available' <<< "$OUT" && ok || bad "the missing asset is logged"

# 4. both missing -> nothing installed
mv "$T/fix/gitleaks_${VER}_linux_x64.tar.gz" "$T/up.moved"
HASHFILE="" FAKE_ARCH=x86_64 run_case
[ -z "$INSTALLED" ] && ok || bad "nothing is installed when neither download works (installed: '$INSTALLED')"
[ "${RC:-x}" = 1 ] && ok || bad "ensure_gitleaks returns 1 when it could not install (rc=${RC:-?})"
mv "$T/up.moved" "$T/fix/gitleaks_${VER}_linux_x64.tar.gz"
mv "$T/patched.moved" "$T/fix/gitleaks-patched_${VER}_linux_x64.tar.gz"

# 5. no recorded hash for this platform, or no hash file -> upstream, and no patched download
printf '# fixture\n%s  darwin_arm64\n' "$PATCHED_SHA" > "$T/hashes.other"
HASHFILE="$T/hashes.other" FAKE_ARCH=x86_64 run_case
[ "$INSTALLED" = upstream ] && ok || bad "no recorded hash for this platform falls back to upstream (installed: '$INSTALLED')"
grep -q 'gitleaks-patched' "$T/curl.log" && bad "no patched download without a recorded hash" || ok
HASHFILE="$T/no-such-file" FAKE_ARCH=x86_64 run_case
[ "$INSTALLED" = upstream ] && ok || bad "a missing hash file falls back to upstream (installed: '$INSTALLED')"

# 6. gitleaks already on PATH: nothing downloaded
mkdir -p "$T/have"; printf '#!/bin/sh\necho existing\n' > "$T/have/gitleaks"; chmod +x "$T/have/gitleaks"
EXTRA_PATH="$T/have" HASHFILE="" FAKE_ARCH=x86_64 run_case
[ ! -s "$T/curl.log" ] && [ -z "$INSTALLED" ] && ok || bad "an existing gitleaks is left alone, nothing downloaded"

# 7. the committed hash file has the four targets
n="$(grep -v '^[[:space:]]*#' "$HERE/../vendor/secret-guard-core/gitleaks-assets.sha256" | grep -c -E '^[0-9a-f]{64}  (linux|darwin)_(x64|arm64)$')"
[ "$n" -eq 4 ] && ok || bad "vendored gitleaks-assets.sha256 lists the four targets ($n)"

echo "gitleaks-install: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
