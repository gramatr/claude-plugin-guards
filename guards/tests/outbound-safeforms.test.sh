#!/usr/bin/env bash
# guards/tests/outbound-safeforms.test.sh — the documented "safe forms" for
# passing a credential to curl, wget and HTTPie (docs/OUTBOUND-SAFE-FORMS.md).
#
# Runs the REAL clients against a localhost capture listener
# (capture-listener.py) and, per case, asserts:
#   - the fabricated value ARRIVED where the docs say (a named header, or the body);
#   - the value does NOT occur in the command string (what the agent types);
#   - whether the value is visible in the client's argv while it runs (read from
#     /proc/<pid>/cmdline mid-request; Linux only, reported SKIP elsewhere);
#   - whether the client's verbose output (curl -v, wget -d, http --verbose)
#     echoes it.
# The doc's rows and this file's case ids must match one to one.
#
# A client that is not installed is reported as SKIP, never as a pass. HTTPie is
# `http` on PATH, or set HTTPIE_CMD (for example "uv run --no-project --with
# httpie http"). Every credential is generated here at run time; HOME and the
# client config locations point at a throwaway directory, nothing real is read.
# No hook is involved. Needs: bash, python3, and whichever clients are present.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOC="$HERE/../../docs/OUTBOUND-SAFE-FORMS.md"
T="$(mktemp -d)"
PID=""
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$T"' EXIT

# Clean slate: no inherited proxy or client config can change what is tested.
unset CURL_HOME WGETRC XDG_CONFIG_HOME http_proxy https_proxy HTTP_PROXY HTTPS_PROXY \
  all_proxy ALL_PROXY HTTPIE_CONFIG_DIR
export NO_PROXY=127.0.0.1 no_proxy=127.0.0.1
export HOME="$T/home"
mkdir -p "$HOME" "$T/cap" "$T/f" "$T/nhome" "$T/chome"
D="$T/cap"
F="$T/f"

# Fabricated credential, built at run time. USERPW and the Basic form derive from it.
RAND="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TOK="FAKECRED-$RAND"
USERNAME=alice
USERPW="$USERNAME:$TOK"
B64="$(printf '%s' "$USERPW" | base64 | tr -d '\n')"
B64_SINGLE="$(printf '%s' "$TOK:$TOK" | base64 | tr -d '\n')"
export TOK USERPW F D
NH="$T/nhome"; CH="$T/chome"; export NH CH

HTTPIE="${HTTPIE_CMD:-http}"
export HTTP="$HTTPIE"

python3 -I "$HERE/capture-listener.py" "$D" >/dev/null 2>&1 &
PID=$!
for _ in $(seq 1 50); do [ -s "$D/port" ] && break; sleep 0.1; done
PORT="$(cat "$D/port")"
U="http://127.0.0.1:$PORT"
export U

# Credential-bearing files, all inside the throwaway directory.
printf 'Authorization: Bearer %s\n' "$TOK" > "$F/hdr.txt"
printf 'header = "Authorization: Bearer %s"\n' "$TOK" > "$F/curl.cfg"
cp "$F/curl.cfg" "$CH/.curlrc"
printf 'machine 127.0.0.1 login %s password %s\n' "$USERNAME" "$TOK" > "$F/netrc"
cp "$F/netrc" "$NH/.netrc"
printf '{"token": "%s"}' "$TOK" > "$F/body.json"
printf 'header = Authorization: Bearer %s\n' "$TOK" > "$F/wgetrc"
printf '127.0.0.1\tFALSE\t/\tFALSE\t0\tsess\t%s\n' "$TOK" > "$F/cookies.txt"
# wget calls the askpass program with the prompt as $1: one program, two answers.
printf '#!/bin/sh\ncase "$1" in\n  *sername*) printf "%%s\\n" "%s" ;;\n  *) printf "%%s\\n" "%s" ;;\nesac\n' \
  "$USERNAME" "$TOK" > "$F/askpass-branching.sh"
# The negative case: a program that only knows the secret answers the username prompt with it too.
printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$TOK" > "$F/askpass-single.sh"
chmod 600 "$F"/*; chmod 700 "$F/askpass-branching.sh" "$F/askpass-single.sh"
chmod 600 "$NH/.netrc" "$CH/.curlrc"

pass=0; failn=0; skip=0
IDS=()
ok()   { pass=$((pass+1)); printf '  PASS  %s\n' "$1"; }
bad()  { failn=$((failn+1)); printf '  FAIL  %s\n' "$1"; }
skp()  { skip=$((skip+1)); printf '  SKIP  %s\n' "$1"; }
check() { # check LABEL CONDITION-EXIT-CODE
  if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi
}

have_client() { # have_client curl|wget|http
  case "$1" in
    http) command -v "${HTTPIE%% *}" >/dev/null 2>&1 ;;
    *)    command -v "$1" >/dev/null 2>&1 ;;
  esac
}

echo "client versions"
if have_client curl; then echo "  curl  $(curl --version | head -1)"; else echo "  curl  not installed"; fi
if have_client wget; then echo "  wget  $(wget --version 2>&1 | head -1)"; else echo "  wget  not installed"; fi
if have_client http; then
  # shellcheck disable=SC2086
  echo "  http  HTTPie $($HTTPIE --version 2>&1 | tail -1)"
else
  echo "  http  not installed"
fi

HAVE_PROC=0
[ -r "/proc/$$/cmdline" ] && HAVE_PROC=1

# argv_scan: while a client is in flight, does any process whose command line
# mentions the listener port carry the value (plain or Basic form) in its argv?
# Sets ARGV_SEEN (a client process was found) and ARGV_HAS.
argv_scan() {
  ARGV_SEEN=0; ARGV_HAS=0
  local f c
  for f in /proc/[0-9]*/cmdline; do
    c="$({ tr '\0' ' ' < "$f"; } 2>/dev/null)" || continue
    case "$c" in
      *"127.0.0.1:$PORT"*)
        ARGV_SEEN=1
        case "$c" in *"$TOK"*|*"$B64"*) ARGV_HAS=1 ;; esac ;;
    esac
  done
}

reset_cap() { rm -f "$D"/req.* "$D/inflight"; }

# where_arrived NAME VALUE: does a header NAME carrying VALUE appear in any request?
hdr_has() { cat "$D"/req.*.hdr 2>/dev/null | grep -i "^$1:" | grep -qF -- "$2"; }
body_has() { cat "$D"/req.*.body 2>/dev/null | grep -qF -- "$1"; }
anywhere_has() { # the value in any header or body
  { cat "$D"/req.*.hdr "$D"/req.*.body 2>/dev/null; } | grep -qF -- "$1"
}

# run_case ID CLIENT PLACE ARGV VERBOSE DESC CMD
#   PLACE    hdr:NAME  value (plain) in header NAME
#            b64:NAME  Basic form of user:value in header NAME
#            body      value in the request body
#            none      value (plain or Basic) nowhere in the request
#   ARGV     yes|no    value visible in the client's argv while it runs
#   VERBOSE  yes|no    verbose output echoes the value (skip: not asserted)
#   CMD      run with bash -c; $V holds the client's quiet flag, or its verbose flag
#            on the verbose run; /slow becomes /fast on the verbose run.
run_case() {
  local id="$1" client="$2" place="$3" argv="$4" verb="$5" desc="$6" cmd="$7"
  IDS+=("$id")
  if ! have_client "$client"; then skp "$id: $client not installed ($desc)"; return; fi

  case "$cmd" in
    *"$TOK"*|*"$B64"*) bad "$id: command text contains the value"; return ;;
  esac
  ok "$id: command text does not contain the value"

  local quiet="" loud=""
  case "$client" in
    curl) quiet="-s"; loud="-sv" ;;
    wget) quiet="-q"; loud="-d" ;;
    http) quiet=""; loud="--verbose" ;;
  esac

  # Run 1: quiet, held open by the listener so argv can be read.
  reset_cap
  V="$quiet" bash -c "$cmd" >/dev/null 2>&1 &
  local cpid=$! n
  if [ "$HAVE_PROC" -eq 1 ]; then
    for n in $(seq 1 100); do [ -e "$D/inflight" ] && break; sleep 0.1; done
    argv_scan
  fi
  wait "$cpid"

  case "$place" in
    hdr:*) hdr_has "${place#hdr:}" "$TOK"; check "$id: value arrived in header ${place#hdr:}" $? ;;
    b64:*) hdr_has "${place#b64:}" "$B64"; check "$id: Basic credential arrived in header ${place#b64:}" $? ;;
    body)  body_has "$TOK"; check "$id: value arrived in the body" $? ;;
    none)  anywhere_has "$TOK" || anywhere_has "$B64"; r=$?
           [ "$r" -ne 0 ]; check "$id: value did not arrive" $? ;;
  esac

  if [ "$HAVE_PROC" -eq 1 ]; then
    if [ "$ARGV_SEEN" -ne 1 ]; then
      bad "$id: no client process found to read argv from"
    elif [ "$argv" = yes ]; then
      [ "$ARGV_HAS" -eq 1 ]; check "$id: value IS visible in argv" $?
    else
      [ "$ARGV_HAS" -eq 0 ]; check "$id: value is not in argv" $?
    fi
  else
    skp "$id: argv check needs /proc (Linux)"
  fi

  # Run 2: verbose output.
  reset_cap
  V="$loud" bash -c "${cmd//\/slow/\/fast}" > "$T/verbose.out" 2>&1
  if grep -qF -e "$TOK" -e "$B64" "$T/verbose.out"; then vhas=0; else vhas=1; fi
  if [ "$verb" = skip ]; then
    :
  elif [ "$verb" = yes ]; then
    [ "$vhas" -eq 0 ]; check "$id: verbose output echoes the value" $?
  else
    [ "$vhas" -ne 0 ]; check "$id: verbose output does not echo the value" $?
  fi
}

# skip_case ID DESC REASON: a documented row that is deliberately not run here.
skip_case() {
  IDS+=("$1")
  skp "$1: $2 ($3)"
}

echo "curl"
run_case curl-var-header curl hdr:Authorization yes yes "variable in a header" \
  'curl $V -H "Authorization: Bearer $TOK" $U/slow'
run_case curl-oauth2-bearer curl hdr:Authorization yes yes "--oauth2-bearer" \
  'curl $V --oauth2-bearer "$TOK" $U/slow'
run_case curl-u-userpw curl b64:Authorization yes yes "-u with a variable" \
  'curl $V -u "$USERPW" $U/slow'
run_case curl-K-file curl hdr:Authorization no yes "-K config file" \
  'curl $V -K $F/curl.cfg $U/slow'
run_case curl-K-stdin curl hdr:Authorization no yes "-K - from stdin" \
  'curl $V -K - $U/slow < $F/curl.cfg'
run_case curl-curlrc curl hdr:Authorization no yes "CURL_HOME/.curlrc" \
  'CURL_HOME=$CH curl $V $U/slow'
run_case curl-netrc-file curl b64:Authorization no yes "--netrc-file" \
  'curl $V --netrc-file $F/netrc $U/slow'
run_case curl-H-at-file curl hdr:Authorization no yes "-H @headers.txt" \
  'curl $V -H @$F/hdr.txt $U/slow'
run_case curl-cookie-file curl hdr:Cookie no yes "-b cookiefile" \
  'curl $V -b $F/cookies.txt $U/slow'
run_case curl-d-at-file curl body no no "-d @file" \
  'curl $V -d @$F/body.json $U/slow'
run_case curl-stdin-body curl body no no "--data-binary @- from stdin" \
  'curl $V --data-binary @- $U/slow < $F/body.json'
run_case curl-T-file curl body no no "-T file" \
  'curl $V -T $F/body.json $U/slow'
run_case curl-F-file curl body no no "-F f=@file" \
  'curl $V -F f=@$F/body.json $U/slow'
run_case curl-cmdsubst-header curl hdr:Authorization yes yes "NOT safe: \$(cat file) in a header" \
  'curl $V -H "Authorization: Bearer $(cut -d" " -f3 $F/hdr.txt)" $U/slow'
run_case curl-data-raw-at curl none no no "--data-raw @file sends the literal text" \
  'curl $V --data-raw @$F/body.json $U/slow'
if have_client curl; then
  body_has "@$F/body.json"; check "curl-data-raw-at: the literal '@path' text was sent as the body" $?
fi
skip_case curl-8.3-unverified "--json, --variable, --expand-*" "curl 8.3+ forms, not verified here"

echo "wget"
run_case wget-var-header wget hdr:Authorization yes yes "variable in --header" \
  'wget $V -O- --header="Authorization: Bearer $TOK" $U/slow'
run_case wget-user-password wget b64:Authorization yes yes "--user and --password" \
  'wget $V -O- --user='"$USERNAME"' --password="$TOK" $U/auth'
run_case wget-config wget hdr:Authorization no yes "--config file" \
  'wget $V -O- --config=$F/wgetrc $U/slow'
run_case wget-wgetrc-env wget hdr:Authorization no yes "WGETRC" \
  'WGETRC=$F/wgetrc wget $V -O- $U/slow'
run_case wget-netrc wget b64:Authorization no yes ".netrc in HOME, after a 401 challenge" \
  'HOME=$NH wget $V -O- $U/auth'
run_case wget-askpass wget b64:Authorization no yes "--use-askpass, program branches on the prompt" \
  'wget $V -O- --use-askpass=$F/askpass-branching.sh $U/auth'
run_case wget-askpass-single-secret wget none no skip "NEGATIVE: one-answer askpass program fails" \
  'wget $V -O- --use-askpass=$F/askpass-single.sh $U/auth'
if have_client wget; then
  # The failure mode: the secret is sent as the username too, so the server never sees user:secret.
  hdr_has Authorization "$B64_SINGLE"
  check "wget-askpass-single-secret: the single secret answered the username prompt too" $?
fi
run_case wget-post-file wget body no no "--post-file" \
  'wget $V -O- --post-file=$F/body.json $U/slow'
run_case wget-body-file-stdin wget body no no "--body-file=/dev/stdin" \
  'wget $V -O- --method=POST --body-file=/dev/stdin $U/slow < $F/body.json'
run_case wget-load-cookies wget hdr:Cookie no yes "--load-cookies" \
  'wget $V -O- --load-cookies=$F/cookies.txt $U/slow'

echo "HTTPie"
run_case http-auth-header http hdr:Authorization yes yes "Authorization header item" \
  '$HTTP --ignore-stdin $V GET $U/slow "Authorization:Bearer $TOK"'
run_case http-a-userpw http b64:Authorization yes yes "-a with a variable" \
  '$HTTP --ignore-stdin $V -a "$USERPW" GET $U/slow'
run_case http-field-at-file http body no yes "name=@file" \
  '$HTTP --ignore-stdin $V POST $U/slow t=@$F/body.json'
run_case http-stdin-file http body no yes "< file on stdin" \
  '$HTTP $V POST $U/slow < $F/body.json'
run_case http-netrc http b64:Authorization no yes ".netrc in HOME" \
  'HOME=$NH $HTTP --ignore-stdin $V GET $U/slow'

echo "docs"
if [ -f "$DOC" ]; then
  rows="$(grep -c '^| `' "$DOC")"
  [ "$rows" -eq "${#IDS[@]}" ]
  check "doc has one table row per case id (rows=$rows, cases=${#IDS[@]})" $?
  for id in "${IDS[@]}"; do
    n="$(grep -c "^| \`$id\` " "$DOC")"
    [ "$n" -eq 1 ] || { bad "doc: case id $id appears in $n rows, want 1"; }
  done
else
  bad "docs/OUTBOUND-SAFE-FORMS.md is missing"
fi

echo "passed=$pass failed=$failn skipped=$skip"
[ "$failn" -eq 0 ] && echo "OK" || echo "FAILED"
exit "$failn"
