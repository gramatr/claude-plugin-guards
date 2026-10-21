#!/usr/bin/env bash
# guards/tests/cred-use-registry.test.sh -- the tools in hooks/cred-use-registry.tsv really do not print the
# credential they are handed, the forbidden forms really do, and the loader behaves the same everywhere.
#
# Why: credfile-guard drops a credential from the line before it looks for sensitive paths when the tool
# only USES it. Every row of that registry is a trust decision ("this tool, in this form, never prints
# the credential"), so every row needs evidence that is re-run, not remembered:
#   1. Registry shape: every row has 7 columns, a test_id, and a canary function in this file.
#   2. Canaries: run the REAL tool against a throwaway credential generated here, capture stdout+stderr,
#      assert the credential body does not appear. A tool that is not installed is SKIPPED, loudly.
#   3. Negative controls: for each forbidden form the same real tool DOES print the credential, so the
#      forbid is real and not folklore.
#   4. Hook agreement: the real credfile-guard allows the canary shape with a trailing reader word, and still
#      denies the forbidden form with one.
#   5. The stripper gives the same answers under every awk found (gawk, mawk, busybox awk, the default awk).
#   6. Fallback: a missing or unusable registry, a missing awk script or GUARDS_CRED_IDENTITY_USE=0 makes
#      the hook deny the shape again (more, never less).
# Needs: bash, jq, ssh-keygen, openssl. Optional (skipped when absent): ssh, scp, sftp, ssh-add, age, kubectl,
# curl, docker, rage. All credentials are generated at run time and thrown away.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="$HERE/../hooks"
REG="$HOOKS/cred-use-registry.tsv"
pass=0 fail=0 skipped=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }
skip() { skipped=$((skipped + 1)); echo "SKIP $1: $2"; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.ssh" "$HOME/.kube" "$HOME/.docker" "$HOME/proj"
W="$T/work"; mkdir -p "$W"

have() { command -v "$1" > /dev/null 2>&1; }
for need in jq ssh-keygen openssl; do
  have "$need" || { echo "cred-use-registry: needs $need"; exit 2; }
done

# --- throwaway credentials --------------------------------------------------
KEY="$HOME/.ssh/id_ed25519"
ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C throwaway
BODY_ED="$(sed -n 2p "$KEY")"
RSA="$W/rsa.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA" 2> /dev/null
BODY_RSA="$(sed -n 2p "$RSA")"
CLIENT_KEY="$W/client.key"; CLIENT_CERT="$W/client.crt"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CLIENT_KEY" -out "$CLIENT_CERT" -subj /CN=throwaway -days 1 2> /dev/null
BODY_CLIENT="$(sed -n 2p "$CLIENT_KEY")"
TOKEN="tok-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
KUBECONFIG_FILE="$HOME/.kube/config"
printf 'apiVersion: v1\nkind: Config\nclusters:\n- cluster: {server: "https://127.0.0.1:9"}\n  name: c\ncontexts:\n- context: {cluster: c, user: u}\n  name: x\ncurrent-context: x\nusers:\n- name: u\n  user: {token: "%s"}\n' "$TOKEN" > "$KUBECONFIG_FILE"
AUTH="$(printf 'throwaway-auth-%s' "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" | base64 | tr -d '\n=')"
printf '{"auths":{"example.invalid":{"auth":"%s"}}}\n' "$AUTH" > "$HOME/.docker/config.json"
AGE_KEY="$W/age.key"
BODY_AGE=""
if have age-keygen && have age; then
  age-keygen -o "$AGE_KEY" 2> /dev/null
  BODY_AGE="$(grep -v '^#' "$AGE_KEY" | head -n 1)"
  echo "payload-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')" | age -r "$(age-keygen -y "$AGE_KEY")" > "$W/f.age"
fi
echo hi > "$W/f"

# output of a command, stdout+stderr, bounded to 8 seconds where timeout exists
run() { if have timeout; then timeout 8 "$@" 2>&1; else "$@" 2>&1; fi; }
leaks() { # leaks BODY TEXT -> 0 if the credential (or a text dump of its numbers) is in TEXT
  printf '%s' "$2" | grep -aqF -- "$1" && return 0
  printf '%s' "$2" | grep -aqiE 'Private-Key:|privateExponent|priv:' && return 0
  return 1
}
clean() { # clean LABEL BODY TEXT
  if leaks "$2" "$3"; then bad "$1 printed the credential"; else ok; fi
}
dirty() { # dirty LABEL BODY TEXT : the forbidden form really prints it
  if leaks "$2" "$3"; then ok; else bad "$1 did not print the credential, so its forbid is not proven (check the tool version)"; fi
}

# --- canaries: one function per test_id (dashes become underscores) ------------
canary_age_identity() {
  have age && [ -n "$BODY_AGE" ] || { skip age-identity "age or age-keygen not installed"; return; }
  clean "age -d -i KEY" "$BODY_AGE" "$(run age -d -i "$AGE_KEY" "$W/f.age")"
  clean "age -d --identity=KEY" "$BODY_AGE" "$(run age -d --identity="$AGE_KEY" "$W/f.age")"
}
canary_rage_identity() {
  have rage || { skip rage-identity "rage not installed (the row is kept from PR #112 and is unverified here)"; return; }
  skip rage-identity "rage is installed but no keypair fixture is generated for it yet"
}
canary_ssh_identity() {
  have ssh || { skip ssh-identity "ssh not installed"; return; }
  clean "ssh -vvv -i KEY" "$BODY_ED" "$(run ssh -vvv -i "$KEY" -o BatchMode=yes -o ConnectTimeout=1 -p 9 127.0.0.1 true)"
  clean "ssh -o IdentityFile=KEY" "$BODY_ED" "$(run ssh -vvv -o "IdentityFile=$KEY" -o BatchMode=yes -o ConnectTimeout=1 -p 9 127.0.0.1 true)"
  clean "ssh -oIdentityFile=KEY" "$BODY_ED" "$(run ssh -vvv "-oIdentityFile=$KEY" -o BatchMode=yes -o ConnectTimeout=1 -p 9 127.0.0.1 true)"
}
canary_scp_identity() {
  have scp || { skip scp-identity "scp not installed"; return; }
  clean "scp -i KEY" "$BODY_ED" "$(run scp -v -i "$KEY" -o BatchMode=yes -o ConnectTimeout=1 -P 9 "$W/f" 127.0.0.1:/tmp/x)"
}
canary_sftp_identity() {
  have sftp || { skip sftp-identity "sftp not installed"; return; }
  clean "sftp -i KEY" "$BODY_ED" "$(run sftp -v -i "$KEY" -o BatchMode=yes -o ConnectTimeout=1 -P 9 127.0.0.1)"
}
canary_ssh_keygen_file() {
  clean "ssh-keygen -l -f KEY" "$BODY_ED" "$(run ssh-keygen -l -f "$KEY")"
  clean "ssh-keygen -y -f KEY" "$BODY_ED" "$(run ssh-keygen -y -f "$KEY")"
  clean "ssh-keygen -e -f KEY" "$BODY_ED" "$(run ssh-keygen -e -f "$KEY")"
}
canary_ssh_add_operand() {
  have ssh-add && have ssh-agent || { skip ssh-add-operand "ssh-add or ssh-agent not installed"; return; }
  local agent out
  agent="$(ssh-agent -s)"
  out="$(eval "$agent" > /dev/null; ssh-add "$KEY" 2>&1; ssh-add -l 2>&1; ssh-add -L 2>&1; kill "$SSH_AGENT_PID" 2> /dev/null)"
  clean "ssh-add KEY, -l, -L" "$BODY_ED" "$out"
}
canary_openssl_sign() {
  clean "openssl dgst -sign KEY" "$BODY_RSA" "$(run openssl dgst -sha256 -sign "$RSA" "$W/f" | tr -c '[:print:]\n' '.')"
  clean "openssl req -new -key KEY" "$BODY_RSA" "$(run openssl req -new -key "$RSA" -subj /CN=x)"
  openssl dgst -sha256 -binary "$W/f" > "$W/digest" 2> /dev/null
  clean "openssl pkeyutl -sign -inkey KEY" "$BODY_RSA" "$(run openssl pkeyutl -sign -inkey "$RSA" -in "$W/digest" -pkeyopt digest:sha256 | tr -c '[:print:]\n' '.')"
  openssl req -new -key "$RSA" -subj /CN=x -out "$W/csr.pem" 2> /dev/null
  clean "openssl x509 -req -signkey KEY" "$BODY_RSA" "$(run openssl x509 -req -in "$W/csr.pem" -signkey "$RSA" -days 1)"
  clean "openssl s_client -key KEY" "$BODY_RSA" "$(run openssl s_client -key "$RSA" -connect 127.0.0.1:9 < /dev/null)"
}
canary_openssl_pubout() {
  clean "openssl pkey -in KEY -pubout" "$BODY_RSA" "$(run openssl pkey -in "$RSA" -pubout)"
  clean "openssl rsa -in KEY -pubout" "$BODY_RSA" "$(run openssl rsa -in "$RSA" -pubout)"
  # negative controls: the forms the row refuses really print the key
  dirty "openssl pkey -in KEY (no -pubout)" "$BODY_RSA" "$(run openssl pkey -in "$RSA")"
  dirty "openssl pkey -in KEY -text -noout (no -pubout)" "$BODY_RSA" "$(run openssl pkey -in "$RSA" -text -noout)"
  dirty "openssl rsa -in KEY -pubout -text" "$BODY_RSA" "$(run openssl rsa -in "$RSA" -pubout -text)"
}
canary_kubectl_kubeconfig() {
  have kubectl || { skip kubectl-kubeconfig "kubectl not installed"; return; }
  clean "kubectl --kubeconfig P get pods" "$TOKEN" "$(run kubectl --kubeconfig "$KUBECONFIG_FILE" get pods --request-timeout=1s)"
  clean "KUBECONFIG=P kubectl get pods" "$TOKEN" "$(KUBECONFIG="$KUBECONFIG_FILE" run kubectl get pods --request-timeout=1s)"
  clean "kubectl --kubeconfig P config view" "$TOKEN" "$(run kubectl --kubeconfig "$KUBECONFIG_FILE" config view)"
  dirty "kubectl --kubeconfig P config view --raw" "$TOKEN" "$(run kubectl --kubeconfig "$KUBECONFIG_FILE" config view --raw)"
}
canary_curl_key() {
  have curl || { skip curl-key "curl not installed"; return; }
  clean "curl -v --key KEY --cert CERT" "$BODY_CLIENT" "$(run curl -sv --max-time 2 --key "$CLIENT_KEY" --cert "$CLIENT_CERT" https://127.0.0.1:9/)"
}
canary_docker_config() {
  have docker || { skip docker-config "docker not installed"; return; }
  clean "docker --config DIR ps" "$AUTH" "$(run docker --config "$HOME/.docker" ps)"
  clean "docker --config DIR --version" "$AUTH" "$(run docker --config "$HOME/.docker" --version)"
}

# --- 1. registry shape ----------------------------------------------------------
rows=0
ids=""
while IFS=$'\t' read -r tool subs use needs forbid test_id note; do
  case "$tool" in ''|'#'*) continue ;; esac
  rows=$((rows + 1))
  [ -n "$tool" ] && [ -n "$subs" ] && [ -n "$use" ] && [ -n "$needs" ] && [ -n "$forbid" ] && ok || bad "registry row $rows ($tool) has an empty column (use - for none)"
  if [ -z "$test_id" ] || [ "$test_id" = - ]; then bad "registry row $rows ($tool) has no test_id"; continue; fi
  fn="canary_${test_id//-/_}"
  if [ "$(type -t "$fn")" = function ]; then ok; else bad "registry row $rows ($tool) test_id '$test_id' has no function $fn in this test"; fi
  case " $ids " in *" $test_id "*) bad "test_id '$test_id' is used by two rows" ;; *) ok ;; esac
  ids="$ids $test_id"
  : "$note"
done < "$REG"
[ "$rows" -ge 10 ] && ok || bad "registry has too few rows ($rows)"
# every canary function belongs to a row (no orphan evidence)
for fn in $(declare -F | awk '{print $3}' | grep '^canary_'); do
  id="${fn#canary_}"; id="${id//_/-}"
  case " $ids " in *" $id "*) ok ;; *) bad "$fn has no registry row" ;; esac
done

# --- 2 and 3. canaries and negative controls ----------------------------------------
for fn in $(declare -F | awk '{print $3}' | grep '^canary_'); do "$fn"; done

# --- 4. the real hook agrees ------------------------------------------------------
decide() { # decide COMMAND [ENV...] -> deny|ask|allow
  local out d
  out="$(jq -n --arg c "$1" --arg cwd "$HOME/proj" '{tool_name:"Bash", tool_input:{command:$c}, cwd:$cwd, permission_mode:"default"}' | env "${@:2}" bash "${HOOK:-$HOOKS/credfile-guard.sh}")"
  d="$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // ""' 2> /dev/null)"
  case "$d" in deny|ask) echo "$d" ;; *) echo allow ;; esac
}
expect() { # expect WANT DESCRIPTION COMMAND [ENV...]
  local got
  got="$(decide "$3" "${@:4}")"
  if [ "$got" = "$1" ]; then ok; else bad "$2 (wanted $1, got $got): $3"; fi
}
expect allow "age -i beside a reader"                "age -d -i $KEY f.age | head"
expect allow "ssh -i beside a reader"                "ssh -i $KEY host.invalid cat /etc/hosts"
expect allow "ssh -o IdentityFile"                   "ssh -o IdentityFile=$KEY host.invalid cat x"
expect allow "ssh -oIdentityFile glued"              "ssh -oIdentityFile=$KEY host.invalid cat x"
expect allow "scp -i"                                "scp -i $KEY ./f host.invalid:/tmp/ && cat ./f"
expect allow "ssh-add operand then a reader"         "ssh-add $KEY && ssh-add -l | grep ed25519"
expect allow "openssl dgst -sign beside a reader"    "openssl dgst -sha256 -sign $KEY f | base64"
expect allow "openssl pkey -pubout beside a reader"  "openssl pkey -in $KEY -pubout | head"
expect deny  "openssl pkey without -pubout"          "openssl pkey -in $KEY | head"
expect deny  "openssl pkey -pubout -text"            "openssl pkey -in $KEY -pubout -text | head"
expect allow "kubectl --kubeconfig beside a reader"  "kubectl --kubeconfig ~/.kube/config get pods | head"
expect allow "KUBECONFIG env beside a reader"        "KUBECONFIG=~/.kube/config kubectl get pods | grep Run"
expect ask   "kubectl config view --raw"             "kubectl --kubeconfig ~/.kube/config config view --raw | head"
expect allow "curl --key beside a reader"            "curl --key $KEY --cert c.pem https://x | head"
expect allow "docker --config beside a reader"       "docker --config ~/.docker ps | tail"
expect allow "git sshCommand with ssh -i (quoted)"   "git -c core.sshCommand=\"ssh -i $KEY\" ls-remote | head"
expect allow "GIT_SSH_COMMAND with ssh -i"           "GIT_SSH_COMMAND=\"ssh -i $KEY\" git pull | tail"
expect allow "rsync -e ssh -i"                       "rsync -e \"ssh -i $KEY\" a b | tail"
# a credential named anywhere else on the line still counts
expect deny  "the key read after an age -i"          "age -d -i $KEY f.age; cat $KEY"
expect deny  "cat of the key piped to age"           "cat $KEY | age -e -r x"
expect deny  "grep -i is not an identity flag"       "grep -i x $KEY"
expect deny  "sed -i on the key"                     "sed -i s/a/b/ $KEY"
expect deny  "an unlisted tool with -i"              "mytool -i $KEY | head"
expect deny  "the key as input as well as identity"  "age -d -i $KEY $KEY | head"

# --- 5. same answers under every awk ------------------------------------------------
cases=(
  "age -d -i /k f.age | cat"
  "ssh -o IdentityFile=/k host cat x"
  "ssh-add /k && ssh-add -l | grep e"
  "openssl pkey -in /k -pubout | head"
  "openssl pkey -in /k | head"
  "kubectl --kubeconfig /c config view --raw | head"
  "KUBECONFIG=/c kubectl get pods | grep R"
  "rsync -e \"ssh -i /k\" a b | tail"
  "cat /k | age -e -r x"
  "echo a; age -d -i /k f; cat /k"
)
ref=""
for cand in awk gawk mawk "busybox awk" original-awk; do
  bin=${cand%% *}
  have "$bin" || continue
  out=""
  for c in "${cases[@]}"; do
    # shellcheck disable=SC2086
    out="$out$(printf '%s' "$c" | $cand -v reg="$REG" -f "$HOOKS/cred-use-strip.awk")"$'\n'
  done
  if [ -z "$ref" ]; then ref="$out"; refname="$cand"; ok
  elif [ "$out" = "$ref" ]; then ok
  else bad "the stripper under '$cand' differs from '$refname'"; fi
done
[ -n "$ref" ] || bad "no awk found"
printf '%s' "$ref" | grep -q 'age -d f.age' && ok || bad "the stripper dropped the age identity (got: $(printf '%s' "$ref" | head -n 1))"

# --- 6. fallback: never denies less ------------------------------------------------
H="$T/hooks"; cp -R "$HOOKS" "$H"
SHAPE="age -d -i $KEY f.age | head"
HOOK="$H/credfile-guard.sh" expect allow "copy of the hooks starts out allowing the shape" "$SHAPE"
mv "$H/cred-use-registry.tsv" "$H/cred-use-registry.tsv.off"
HOOK="$H/credfile-guard.sh" expect deny "a missing registry denies the shape again" "$SHAPE"
mv "$H/cred-use-registry.tsv.off" "$H/cred-use-registry.tsv"
mv "$H/cred-use-strip.awk" "$H/cred-use-strip.awk.off"
HOOK="$H/credfile-guard.sh" expect deny "a missing awk script denies the shape again" "$SHAPE"
mv "$H/cred-use-strip.awk.off" "$H/cred-use-strip.awk"
printf 'this is not a registry\nneither is this\n' > "$H/cred-use-registry.tsv"
HOOK="$H/credfile-guard.sh" expect deny "an unparsable registry denies the shape again" "$SHAPE"
cp "$REG" "$H/cred-use-registry.tsv"
HOOK="$H/credfile-guard.sh" expect deny "GUARDS_CRED_IDENTITY_USE=0 denies the shape again" "$SHAPE" GUARDS_CRED_IDENTITY_USE=0

echo "cred-use-registry: $pass passed, $fail failed, $skipped canaries skipped"
[ "$fail" -eq 0 ]
