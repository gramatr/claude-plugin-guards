#!/usr/bin/env bash
# guards/tests/dockerfile-go-drift.test.sh -- the drift check itself: an identical list passes
# (also when the lines are wrapped differently or in another order), a different version, a
# missing module and a missing command fail. Runs against local copies, no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/dockerfile-go-drift.sh"
V="$HERE/../vendor/secret-guard-core/Dockerfile"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
expect() { # expect WANT_EXIT LABEL SERVER_FILE [VENDORED_FILE]
  local want="$1" label="$2" srv="$3" ven="${4:-$V}" rc
  SERVER_DOCKERFILE="$srv" VENDORED_DOCKERFILE="$ven" bash "$CHECK" >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq "$want" ]; then pass=$((pass + 1)); printf '  ok    %s\n' "$label"
  else fail=$((fail + 1)); printf '  FAIL  %s (exit %s, want %s)\n' "$label" "$rc" "$want"; fi
}

# A server file that carries the vendored list, wrapped on one line, with other lines around it.
list="$(awk '/^RUN go get /{on=1; sub(/^RUN go get /,"")} on{l=$0; c=(l ~ /\\[[:space:]]*$/); sub(/\\[[:space:]]*$/,"",l); n=split(l,w,/[[:space:]]+/); for(i=1;i<=n;i++){ if(w[i]=="")continue; if(w[i]=="&&"){on=0;break}; print w[i]} if(!c)on=0}' "$V")"
[ -n "$list" ] || { echo "  FAIL  test setup: no go get list in the vendored Dockerfile"; exit 1; }
one_line="$(printf '%s\n' "$list" | tr '\n' ' ')"
printf 'FROM scratch\nARG X=1\nRUN go get %s && go mod tidy\n' "$one_line" > "$W/same.Dockerfile"
expect 0 "the same modules on one line pass" "$W/same.Dockerfile"

printf 'FROM scratch\nRUN go get %s \\\n    && go mod tidy\n' "$(printf '%s\n' "$list" | sort -r | tr '\n' ' ')" > "$W/reordered.Dockerfile"
expect 0 "the same modules in another order pass" "$W/reordered.Dockerfile"

# A different version of one module.
printf 'FROM scratch\nRUN go get %s && go mod tidy\n' "$(printf '%s\n' "$list" | sed '1s/@.*/@v9.9.9/' | tr '\n' ' ')" > "$W/version.Dockerfile"
expect 1 "one module at another version fails" "$W/version.Dockerfile"

# A module the vendored file lacks (server patches more).
printf 'FROM scratch\nRUN go get %s example.invalid/extra@v1.0.0 && go mod tidy\n' "$one_line" > "$W/extra.Dockerfile"
expect 1 "a module only the server patches fails" "$W/extra.Dockerfile"

# A module the server lacks (vendored patches more).
printf 'FROM scratch\nRUN go get %s && go mod tidy\n' "$(printf '%s\n' "$list" | sed '1d' | tr '\n' ' ')" > "$W/fewer.Dockerfile"
expect 1 "a module only the vendored file patches fails" "$W/fewer.Dockerfile"

# The vendored file with no go get at all.
printf 'FROM scratch\nRUN echo nothing\n' > "$W/none.Dockerfile"
expect 1 "a vendored Dockerfile without the command fails" "$W/same.Dockerfile" "$W/none.Dockerfile"

# A server file with no go get at all is an error (2), not a pass.
expect 2 "a server Dockerfile without the command is an error" "$W/none.Dockerfile"

echo "dockerfile-go-drift: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
