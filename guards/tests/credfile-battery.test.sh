#!/usr/bin/env bash
# guards/tests/credfile-battery.test.sh -- 20 "use, not print" command shapes through the real credfile-guard.
#
# Why: of these 20 realistic shapes, 9 were denied although nothing prints a credential, all from one
# cause: a reader word (head, grep, base64 ...) and a sensitive path anywhere on the same line
# (gramatr/guards-coordination#79, design: docs/scope/credential-override-design-2026-10-21.md, Evidence 1).
# This pins the outcome for each shape in `default` and `auto`, so a change that makes a shape deny again
# (a false positive) or allow a thing that should deny shows up as a named failure.
#
# Shapes that are still denied although they print nothing are listed as KNOWN and asserted as deny, so the
# list stays honest; when one is fixed the test fails and says to move it. Shapes that are allowed although
# they are not safe by design (a path assembled from pieces) are asserted as EXPECTED MISSES for the same
# reason. All credentials are generated at run time in a throwaway HOME.
# Needs: bash, jq, ssh-keygen.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="${HOOK:-$HERE/../hooks/credfile-guard.sh}" # HOOK=path runs the same shapes against another copy (negative control)
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.ssh" "$HOME/.kube" "$HOME/.docker" "$HOME/proj"
KEY="$HOME/.ssh/id_ed25519"
ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C throwaway
printf 'apiVersion: v1\nkind: Config\n' > "$HOME/.kube/config"
printf '{"auths":{}}\n' > "$HOME/.docker/config.json"

decide() { # decide COMMAND MODE -> deny|ask|allow
  local out d
  out="$(jq -n --arg c "$1" --arg m "$2" --arg cwd "$HOME/proj" '{tool_name:"Bash", tool_input:{command:$c}, cwd:$cwd, permission_mode:$m}' | bash "$HOOK")"
  d="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2> /dev/null)"
  case "$d" in deny|ask) echo "$d" ;; *) echo allow ;; esac
}

# row ID WANT_DEFAULT WANT_AUTO DESCRIPTION COMMAND
row() {
  local id="$1" wd="$2" wa="$3" desc="$4" cmd="$5" gd ga
  gd="$(decide "$cmd" default)"
  ga="$(decide "$cmd" auto)"
  if [ "$gd" = "$wd" ]; then ok; else bad "shape $id ($desc) in default: wanted $wd, got $gd: $cmd"; fi
  if [ "$ga" = "$wa" ]; then ok; else bad "shape $id ($desc) in auto: wanted $wa, got $ga: $cmd"; fi
}

# --- use, not print: allowed ---------------------------------------------------
row 1  allow allow "openssl pkey public half"          "openssl pkey -in $KEY -pubout | head"
row 2  allow allow "openssl dgst -sign"                "openssl dgst -sha256 -sign $KEY f | base64"
row 3  allow allow "git core.sshCommand with ssh -i"   "git -c core.sshCommand=\"ssh -i $KEY\" ls-remote | head"
row 4  allow allow "GIT_SSH_COMMAND with ssh -i"       "GIT_SSH_COMMAND=\"ssh -i $KEY\" git pull | tail"
row 5  allow allow "rsync -e ssh -i"                   "rsync -e \"ssh -i $KEY\" src dst | tail"
row 6  allow allow "ssh-add then list"                 "ssh-add $KEY && ssh-add -l | grep ed25519"
row 7  allow allow "ssh -o IdentityFile with remote cat" "ssh -o IdentityFile=$KEY host cat /etc/hosts"
row 8  allow allow "curl --key"                        "curl --key $KEY --cert c.pem https://x | head"
row 10 allow allow "age -d -i (the PR 112 shape)"      "age -d -i $KEY f.age | head"
row 11 allow allow "kubectl --kubeconfig"              "kubectl --kubeconfig ~/.kube/config get pods | head"
row 12 allow allow "KUBECONFIG env then kubectl"       "KUBECONFIG=~/.kube/config kubectl get pods | grep Run"
row 14 allow allow "docker --config"                   "docker --config ~/.docker ps | tail"
# --- allowed by design, with a stated limit -------------------------------------
row 15 allow allow "ssh-keygen -p rewrites the key (integrity, coordination#87)" "ssh-keygen -p -f $KEY -N ''; cat notes"
row 16 allow allow "ssh-keygen -t ... -f can overwrite the key (integrity, coordination#87)" "ssh-keygen -t ed25519 -f $KEY <<< y; cat x"
row 17 allow allow "age -d prints the decrypted payload, not the key (output redaction covers it)" "age -d -i $KEY f.age; cat x"
# --- must stay denied -----------------------------------------------------------------
row 18 deny deny "a typed override prefix is not an override" "GUARDS_ALLOW_CRED_READ=1 cat $KEY"
row 19 deny deny "cat of a path built by a substitution"      "cat \"\$(echo $KEY)\""
# --- KNOWN: denied although nothing prints a credential (still false positives) ----------
row 9  deny deny "KNOWN: sops has no registry row (not installed in CI, so no canary)" "sops --age-key-file $KEY -d f.yaml | head"
row 13 deny deny "KNOWN: ls of a credential directory piped to a reader (needs the pipe-sink rule, coordination#89)" "ls -la ~/.ssh | head"
# --- EXPECTED MISS: allowed although it reads the key (documented indirect read, LIMITS) ----
row 20 allow allow "EXPECTED MISS: a path assembled from pieces" "python3 -c \"import os;p=os.path.expanduser('~')+'/.ss'+'h/id_'+'ed25519';print(len(open(p).read()))\""

# --- EXPECTED MISS: the hook checks at most the first 60 path-like words (gramatr/guards-coordination#91) ----
# Control first: the same command with few words before the key denies, so the miss below is the cap and not
# something else about the shape.
few="$(seq -s ' ' 1 10)"
many="$(seq -s ' ' 1 70)"
row 21 deny  deny  "a key after 10 words is seen"                                   "cat $few $KEY"
row 22 allow allow "EXPECTED MISS: a key after more than 60 words is not seen (#91)" "cat $many $KEY"

echo "credfile-battery: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
