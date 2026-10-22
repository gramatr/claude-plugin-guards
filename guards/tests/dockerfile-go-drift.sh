#!/usr/bin/env bash
# guards/tests/dockerfile-go-drift.sh -- fail if the Go module patch list in the vendored
# Dockerfile differs from guards-unified's Dockerfile.cpu.
#
# Both Dockerfiles build gitleaks from its release tag and `go get` fixed versions of the
# modules it bundles. The server's list is the one its CI scans (every fixable finding fails
# the build); this plugin's scan image must patch the same modules to the same versions, or a
# finding the server already fixed comes back here (coordination#118).
#
# What is compared: the arguments of the `RUN go get ...` command (module@version words, line
# continuations joined, order ignored). Nothing else in the two files.
#
# Which server file is compared (same rules as scan-sh-drift.sh):
#   SERVER_DOCKERFILE=path   a local file (used by the tests; no network)
#   SERVER_REF=ref           a branch or tag of guards-unified
#   otherwise                the tag being built if the server has it, else main
#
#   bash guards/tests/dockerfile-go-drift.sh   # exit non-zero on drift
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDORED="${VENDORED_DOCKERFILE:-$HERE/../vendor/secret-guard-core/Dockerfile}"
RAW="https://raw.githubusercontent.com/gramatr/guards-unified"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

fetch() { curl -fsSL --retry 3 --retry-delay 2 -o "$TMP" "$RAW/$1/Dockerfile.cpu"; }

if [ -n "${SERVER_DOCKERFILE:-}" ]; then
  cp "$SERVER_DOCKERFILE" "$TMP" || exit 2
  ref="$SERVER_DOCKERFILE"
elif [ -n "${SERVER_REF:-}" ]; then
  fetch "$SERVER_REF" || { echo "go patch drift: cannot fetch Dockerfile.cpu at $SERVER_REF" >&2; exit 2; }
  ref="$SERVER_REF"
else
  ref=main
  if [ "${GITHUB_REF_TYPE:-}" = tag ] && fetch "$GITHUB_REF_NAME" 2> /dev/null; then
    ref="$GITHUB_REF_NAME"
  else
    fetch main || { echo "go patch drift: cannot fetch Dockerfile.cpu at main" >&2; exit 2; }
  fi
fi
[ -s "$TMP" ] || { echo "go patch drift: the server Dockerfile is empty" >&2; exit 2; }

# The words after `go get`, one per line, sorted. A command ends at the first word that is `&&`.
mods() {
  awk '
    /^RUN go get / { on = 1; sub(/^RUN go get /, "") }
    on {
      line = $0
      cont = (line ~ /\\[[:space:]]*$/)
      sub(/\\[[:space:]]*$/, "", line)
      n = split(line, w, /[[:space:]]+/)
      for (i = 1; i <= n; i++) {
        if (w[i] == "") continue
        if (w[i] == "&&") { on = 0; break }
        print w[i]
      }
      if (!cont) on = 0
    }' "$1" | LC_ALL=C sort
}

srv="$(mods "$TMP")"
ven="$(mods "$VENDORED")"
[ -n "$srv" ] || { echo "go patch drift: no 'RUN go get' command found in the server Dockerfile" >&2; exit 2; }
[ -n "$ven" ] || { echo "go patch drift: no 'RUN go get' command found in $VENDORED" >&2; exit 1; }

if diff -u <(printf '%s\n' "$srv") <(printf '%s\n' "$ven") >&2; then
  echo "go patch drift check: the vendored Dockerfile patches the same $(printf '%s\n' "$srv" | wc -l | tr -d ' ') modules as guards-unified Dockerfile.cpu at $ref"
else
  echo "go patch drift check FAILED: the vendored Dockerfile's 'go get' list differs from guards-unified Dockerfile.cpu at $ref (diff above; '-' is the server, '+' is the vendored copy)." >&2
  echo "Change the server's list first, then copy it into guards/vendor/secret-guard-core/Dockerfile." >&2
  exit 1
fi
