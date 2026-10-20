#!/usr/bin/env bash
# VENDORED COPY of app/scan.sh in https://github.com/gramatr/guards-unified. Change it there first, then copy it here;
# CI (scan-sh-drift) fails if this file differs from the server copy apart from these two header lines.
# core/scan.sh — tool-agnostic secret scan + redaction.
#
# Reads arbitrary text on stdin, scans it with gitleaks, and writes the
# same text back to stdout with any detected secrets replaced by
# ***REDACTED:SECRET***. Exits 0 always (scanning failures must not
# break the caller's pipeline — see README "fail-open vs fail-closed").
#
# IMPORTANT distinction: "fail-open" below means "gitleaks itself isn't
# available, so we don't know whether there's a secret — pass the text
# through unchanged." It does NOT mean "we found a secret but can't
# redact it, so pass it through anyway" — that would be the exact leak
# this script exists to prevent. Once gitleaks has confirmed findings,
# redaction happens with plain bash string substitution (no secondary
# interpreter dependency to fail silently on).
#
# On stderr: one line per finding ("REDACTED rule=<id> line=<n>"), for
# adapters that want to log/count without touching stdout.
#
# If SECRET_GUARD_FINDINGS_JSON is set, writes a JSON array of findings
# there (RuleID/StartLine/Fingerprint — no Secret/Match values) for
# adapters that want to report findings via core/report.sh without
# re-scanning the text themselves.
#
# Requires: gitleaks (>=8.x), jq.

set -uo pipefail

INPUT_FILE="$(mktemp)"
REPORT_FILE="$(mktemp)"
trap 'rm -f "$INPUT_FILE" "$REPORT_FILE"' EXIT

cat > "$INPUT_FILE"

WITHHELD='***REDACTED:SECRET*** (secret-guard could not safely redact this output; withheld)'

# --- Deterministic private-key pass, independent of gitleaks ------------
# A private key must never depend on gitleaks having a good run: it
# intermittently reported no finding for an input it detects when replayed
# (observed about once per few hundred scans in CI, with its stderr
# discarded below), and its private-key rule needs the END marker, so a
# truncated key (head, clipped output) was never detected at all. So: match
# BEGIN ... PRIVATE KEY----- plus whatever base64 / escaped-newline /
# whitespace body follows, END marker optional, and redact it here. Runs
# even if gitleaks or jq is missing.
# Known limit: legacy encrypted PEM with Proc-Type/DEK-Info header lines
# stops at the first dash in those headers; gitleaks still covers that.
PEM_RE='-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[A-Za-z0-9+/=\\[:space:]]*(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----)?'
PEM_HITS=0
PEM_TEXT="$(cat "$INPUT_FILE")"
while [[ "$PEM_TEXT" =~ $PEM_RE ]] && [ "$PEM_HITS" -lt 100000 ]; do
  m="${BASH_REMATCH[0]}"
  PEM_TEXT="${PEM_TEXT/"$m"/***REDACTED:SECRET***}"
  PEM_HITS=$((PEM_HITS + 1))
done
EXTRA_HITS=$PEM_HITS
EXTRA_RULES=""   # space-separated RuleIDs reported alongside gitleaks' findings
if [ "$PEM_HITS" -gt 0 ]; then
  echo "REDACTED rule=private-key-fallback hits=$PEM_HITS" >&2
  EXTRA_RULES="private-key-fallback"
fi

# --- Context pass: redact by what a value is NEXT TO, not what it looks like
# gitleaks' generic rules assume a value's shape (base64/hex charset,
# an entropy floor, one line). Real credentials routinely break that: a
# password full of punctuation, a short human-chosen one, a password inside
# a connection string. Context is the stronger signal: a value right after
# a secret-ish key name, inside URL userinfo, or after an Authorization
# scheme is a secret whatever it looks like.
# Bias is deliberately toward over-redaction: a leaked credential is
# costly, a redacted harmless value is not. Pure bash, so it also works
# when gitleaks or jq are missing and in the plugin's backend-down path.
#
# Each rule is an ERE with a prefix group (kept), a value group (replaced)
# and an optional suffix group (kept). Known limits: a double-quoted value
# is redacted up to the closing quote, an unquoted one up to whitespace or
# a quote; a quoted value containing the same quote unescaped is cut short.
CTX_HITS=0
CTX_TEXT="$PEM_TEXT"
# A coloured key name (ESC[32mDB_PASSWORD ESC[0m=...) defeats every rule
# below, and CLI tools colour output by default. Zero-width characters in a
# key name and fullwidth '=' / ':' defeat them just as well. Match on a copy
# with ANSI sequences and zero-width characters stripped and the fullwidth
# delimiters mapped to ASCII; keep the original text unless something was
# actually redacted.
CTX_ORIG="$CTX_TEXT"
CTX_TEXT="$(printf '%s' "$CTX_TEXT" | LC_ALL=C sed -E \
  -e $'s/\x1b\\[[0-9;?]*[ -\\/]*[@-~]//g' \
  -e $'s/\xe2\x80[\x8b-\x8d]//g' -e $'s/\xe2\x81\xa0//g' -e $'s/\xef\xbb\xbf//g' \
  -e $'s/\xef\xbc\x9d/=/g' -e $'s/\xef\xbc\x9a/:/g')"

# Values that are references or placeholders, not secrets.
ctx_placeholder() {
  [[ "$1" =~ ^(\$|\<|\{|%\(|\*\*\*|\.\.\.) ]] && return 0
  [[ "$1" =~ ^(x+|\*+|\.+|-+|_+|true|false|null|none|nil|yes|no|undefined|empty|redacted|changeme|change-me|example|todo|tbd|string|password|secret|token)$ ]] && return 0
  # An absolute path that exists is a path, not a password. This is what
  # `env`, `printenv PWD`, `export -p` and a "pwd: /path/to/dir" line print: the
  # key PWD is a real password alias (ODBC "Pwd=..."), but its value here is
  # the working directory (found live: those lines were redacted).
  [[ "$1" == /* ]] && [ -e "$1" ] && return 0
  return 1
}
# ctx_names_secret_ref KEY: a credential word, one or more further segments,
# then a descriptor segment (id, ref, arn, ...) at the end. snake/kebab/dotted
# and ALL_CAPS go through a lowercased copy; camelCase needs the case-sensitive
# match (the caller runs with nocasematch on) so that "secretValid" does not
# read as "secret" + "Id".
ctx_names_secret_ref() {
  local kl="${1,,}" nc=0 rc=1
  local sfx='(name|ref|id|type|path|file|version|count|ttl|namespace|store|manager|provider|url|arn)s?'
  if [[ "$kl" =~ (secret|token|credential)s?[a-z0-9_.-]{1,40}[_.-]${sfx}$ ]]; then
    return 0
  fi
  shopt -q nocasematch && nc=1
  shopt -u nocasematch
  local camel='([Ss]ecret|[Tt]oken|[Cc]redential)s?[A-Za-z0-9_.-]{0,40}[a-z0-9](Name|Ref|Id|Type|Path|File|Version|Count|Ttl|Namespace|Store|Manager|Provider|Url|Arn)s?$'
  [[ "$1" =~ $camel ]] && rc=0
  [ "$nc" = 1 ] && shopt -s nocasematch
  return $rc
}
# Keys that merely NAME or describe a secret (secretName, token_type, ...).
ctx_describes_secret() {
  [[ "$1" =~ (secret|token|credential)s?[_.-]?(name|ref|id|type|path|file|version|count|ttl|namespace|store|manager|provider|url|arn)$ ]] && return 0
  [[ "$1" =~ (secretkeyref|secretref|secretkey_?ref) ]] && return 0
  # The same naming suffix after extra segments (client_secret_bws_id,
  # secret_vault_id, token_store_ref, credential_provider_arn,
  # clientSecretBwsId): the key names an identifier or reference OF a secret.
  # The LAST segment must be the descriptor, so client_secret_value,
  # secret_key and AUTH_TOKEN, whose last segment is the credential or a
  # value word, still redact.
  ctx_names_secret_ref "$1" && return 0
  # A setting about a credential rather than a credential: the name ends in a
  # unit, limit, switch or mode word (SCAN_SECRET_MAX_BYTES, a "..._CRED_ASK"
  # switch, a "..._TOKEN_TIMEOUT" value). Docs and commit messages show these
  # all the time and their values are numbers or words, never the credential.
  [[ "$1" =~ [_.-](bytes|size|length|limit|max|min|timeout|secs|seconds|ms|port|depth|mode|ask|enabled|disabled)$ ]] && return 0
  # A tokenizer is not a token: a variable named tokenizer holding the result of
  # a model loader is in every ML codebase. Skip the key only if it has no other
  # credential word once the tokeniz* part is removed (tokenizer_secret still
  # redacts).
  if [[ "$1" =~ tokeni[sz](er|ers|ation|ed|ing)? ]]; then
    local rest="${1/${BASH_REMATCH[0]}/}"
    [[ "$rest" =~ ($KW) ]] || return 0
  fi
  return 1
}

# ctx_code_shape KEY BEFORE PFX VAL AFTER: an UNQUOTED value that is source
# code, not a credential: a call (getToken(ctx)), an identifier or member chain
# (accessToken, this.cfg.apiToken), or a type (string, Promise<Token>), on a
# line that is clearly code. Found live: ordinary TypeScript such as an object
# property holding a variable, a declaration assigned a function result, or a field typed
# `string` was redacted. A value that is only a word or number (hunter2), an
# env/INI/YAML/shell assignment, a CLI flag and any quoted value never qualify,
# so env-file, INI, YAML and shell assignments with a plain word (or a word
# with a digit) still redact, as does a string literal assigned to a
# token-named constant.
ctx_code_shape_cs() {
  local key="$1" before="$2" pfx="$3" val="$4" after="$5"
  local lb="${before##*$'\n'}" la="${after%%$'\n'*}" core="$4" delim="" line
  local endp='[],;)}]$' codep=';|=>|\)[[:blank:]]*\{'
  while [[ "$core" =~ $endp ]]; do core="${core%?}"; done
  [[ "$pfx" =~ :[[:blank:]]*$ ]] && delim="colon"
  [[ "$pfx" =~ [[:blank:]]=[[:blank:]]+$ ]] && delim="${delim:-spaced}"
  [ -n "$delim" ] || return 1
  line="$lb$pfx$val$la"
  # The key sits inside a quoted string (JSON string content, a log message, a
  # shell string): that is text, not code. An opening quote just before the key
  # that follows a colon or equals sign starts a string value; one that follows
  # anything else is a quoted key ("token": x) and is not counted.
  local lq="$lb" dq sq
  if [[ "$lq" == *[\"\'] ]]; then
    [[ "$lq" =~ [:=][[:blank:]]*[\"\']$ ]] || lq="${lq%?}"
  fi
  dq="${lq//[^\"]/}"; sq="${lq//[^\']/}"
  if [ $(( ${#dq} % 2 )) -eq 1 ] || [ $(( ${#sq} % 2 )) -eq 1 ]; then return 1; fi
  # a value that ends at a quote sits inside a string (a JSON body, a quoted
  # command), not in code
  [[ "$la" =~ ^[\"\'] ]] && return 1
  # `= await fn(...)`, `= new Foo(...)`: the word itself is a keyword
  [[ "$core" =~ ^(await|new|typeof|yield)$ && "$la" =~ ^[[:blank:]]+[A-Za-z_\$] ]] && return 0
  # a call: the value runs straight into an opening parenthesis
  [[ "$val" =~ ^[A-Za-z_\$][A-Za-z0-9_\$.?!]*\( ]] && return 0
  local ident='^[A-Za-z_$][A-Za-z0-9_$]*([?!]?\.[A-Za-z_$][A-Za-z0-9_$]*)*[?!]?$'
  # after a declaration or modifier keyword (const, readonly, private, ...)
  local kw='(const|let|var|readonly|private|public|protected|final|val|static|abstract|declare|async|await|return|def)'
  if [[ "$lb" =~ (^|[^A-Za-z0-9_\$.-])(export[[:space:]]+)?${kw}([[:space:]]+${kw})*[[:space:]]+$ ]] \
    && [[ "$core" =~ $ident || "$core" =~ ^[A-Za-z_\$][A-Za-z0-9_\$.\<\>\[\],\|\&]*$ ]]; then
    return 0
  fi
  [ "$delim" = colon ] || [ "$delim" = spaced ] || return 1
  # Property position: the key is the first thing on its line, or follows an
  # opening bracket or a comma (an object literal, an argument list), possibly
  # after modifier keywords. A key in the middle of a sentence or a log line
  # ("... INFO retry password: x") is not a property.
  local prop=0
  local lbp="${lb%[\"\']}"
  [[ "$lbp" =~ (^|[\{\(\[,])[[:blank:]]*((readonly|private|public|protected|static|abstract|declare)[[:blank:]]+)*$ ]] && prop=1
  local cue=0
  [[ "$line" =~ $codep ]] && cue=1
  # a type: primitive names anywhere after a colon; others need code around
  if [ "$delim" = colon ]; then
    [[ "$core" =~ ^(string|number|boolean|unknown|any|void|object|never|bigint|symbol)(\[\])?$ ]] && return 0
    if [ "$prop" = 1 ] && { [ "$cue" = 1 ] || [[ "$val" =~ [,\;]$ ]]; }; then
      [[ "$core" =~ ^(Promise|Record|Array|Map|Set|Partial|Readonly|ReadonlyArray|Omit|Pick)\< ]] && return 0
      [[ "$core" =~ ^([A-Z][a-z]{2,})+(\[\])?$ ]] && return 0
    fi
  fi
  # a variable or member chain: needs a separator (so a plain word such as
  # hunter2 never qualifies) or to repeat the key, and code punctuation or a
  # trailing , ; ) }
  if [[ "$core" =~ $ident ]]; then
    local k="${key,,}" c="${core,,}" shaped=0
    k="${k//[_.-]/}"; c="${c//[_.-]/}"
    [ "$c" = "$k" ] && shaped=1
    [[ "$core" != *[0-9]* && ( "$core" == *[_.]* || "$core" =~ ^[a-z]{2,}([A-Z][a-z]{2,})+$ ) ]] && shaped=1
    if [ "$shaped" = 1 ] && { [ "$cue" = 1 ] || [[ "$val" =~ $endp ]]; }; then
      [ "$delim" = colon ] && [ "$prop" = 1 ] && return 0
      [ "$delim" = spaced ] && [[ "$val" =~ \;$ ]] && return 0
    fi
  fi
  return 1
}

# The patterns above are case-sensitive (a PascalCase type name, a camelCase
# variable); the caller runs with nocasematch on, so switch it off here.
ctx_code_shape() {
  local nc=0 rc=1
  shopt -q nocasematch && nc=1
  shopt -u nocasematch
  ctx_code_shape_cs "$@" && rc=0
  [ "$nc" = 1 ] && shopt -s nocasematch
  return $rc
}

# ctx_redact RE PREFIX_IDX VALUE_IDX SUFFIX_IDX(0=none) KEY_IDX(0=none) RULE_ID [QUOTE]
# QUOTE (" or '): the rule's value opens with that quote; see the wrapped-key
# check below.
ctx_redact() {
  local re="$1" pi="$2" vi="$3" si="$4" ki="$5" rule="$6" qg="${7:-}"
  local rest="$CTX_TEXT" out="" m pre pfx val sfx key tmp sent lead cb
  # A sentinel byte that does not occur in the text, so the matched span can
  # be located without a leading-glob pattern (see below).
  for sent in $'\x01' $'\x02' $'\x03' $'\x04'; do
    [[ "$rest" == *"$sent"* ]] || break
  done
  while [[ "$rest" =~ $re ]]; do
    m="${BASH_REMATCH[0]}"
    [ -n "$m" ] || break
    pfx="${BASH_REMATCH[$pi]}"
    val="${BASH_REMATCH[$vi]}"
    sfx=""; [ "$si" -gt 0 ] && sfx="${BASH_REMATCH[$si]}"
    key=""; [ "$ki" -gt 0 ] && key="${BASH_REMATCH[$ki]}"
    # Split rest into pre | m | tail WITHOUT ${rest%%"$m"*} / ${rest#*"$m"}:
    # a leading-* glob makes bash try every prefix length, which made one
    # redaction quadratic in input size (1 MB with one secret: 447 s, past
    # the service's 15 s timeout, i.e. a fail-open). Replacing the first
    # literal occurrence with a sentinel is linear.
    tmp="${rest/"$m"/$sent}"
    pre="${tmp%%"$sent"*}"
    out+="$pre"
    # Prose that wraps a key word in quotes WITH its colon ("token:" or
    # 'password:') ends the key's own quote right where a quoted value would
    # open, so the text up to the NEXT quote on the line looked like a value.
    # It is the key's closing quote when the key is preceded by that same
    # quote and the colon follows the key directly (a real key has its closing
    # quote before the colon: "password": "x", "password":"x"). Emit the
    # prefix as-is and carry on from the would-be value. Only for a colon:
    # nested shell quoting, "PASSWORD="x" cmd", is a real value.
    if [ -n "$qg" ] && [[ "$pfx" == *:"$qg" ]]; then
      cb="${pfx: -3:1}"
      lead="${pfx:0:1}"
      [[ "$lead" == [A-Za-z0-9_.-] ]] && lead="${out: -1}"
      if [ "$lead" = "$qg" ] && [ "$cb" != '"' ] && [ "$cb" != "'" ] && [[ "$cb" != [[:blank:]] ]]; then
        out+="$pfx"
        rest="${val}${sfx}${tmp:$((${#pre} + 1))}"
        continue
      fi
    fi
    if ctx_placeholder "$val" || { [ -n "$key" ] && ctx_describes_secret "$key"; } \
      || { [ -z "$qg" ] && [ -n "$key" ] && ctx_code_shape "$key" "$out$pre" "$pfx" "$val" "${tmp:$((${#pre} + 1))}"; } \
      || { [[ "$key" =~ ^(tokens|secrets|passwords|credentials|passphrases)$ ]] && [[ "$val" == \`* ]]; }; then
      # last clause: a bare plural heading followed by a markdown code span
      # ("Query-string tokens: `access_token=`") is prose, not a value.
      out+="$m"
    else
      out+="${pfx}***REDACTED:SECRET***${sfx}"
      CTX_HITS=$((CTX_HITS + 1))
      case " $EXTRA_RULES " in *" $rule "*) ;; *) EXTRA_RULES="${EXTRA_RULES:+$EXTRA_RULES }$rule" ;; esac
    fi
    rest="${tmp:$((${#pre} + 1))}"
  done
  CTX_TEXT="$out$rest"
}

# count_groups STR: number of capture groups in an ERE fragment.
count_groups() {
  local s="${1//\\(/}"
  s="${s//[!(]/}"
  printf '%s' "${#s}"
}

# ctx_rule RULE KEYRE DELIMRE VALRE [SUFRE [QUOTE]]: a "key <delim> value" rule.
# Builds ((KEYRE)DELIM)(VAL)[(SUF)] and works out the group indexes.
ctx_rule() {
  local rule="$1" keyre="$2" delim="$3" val="$4" suf="${5:-}" qg="${6:-}" gk gd gv vi si=0 re
  gk=$(count_groups "$keyre"); gd=$(count_groups "$delim"); gv=$(count_groups "$val")
  vi=$((3 + gk + gd))
  re="((${keyre})${delim})(${val})"
  if [ -n "$suf" ]; then re+="(${suf})"; si=$((vi + 1 + gv)); fi
  ctx_redact "$re" 1 "$vi" "$si" 2 "$rule" "$qg"
}

# ctx_plain RULE PREFIXRE VALRE [SUFRE]: no key name, just context around a value.
ctx_plain() {
  local rule="$1" prefix="$2" val="$3" suf="${4:-}" gp gv vi si=0 re
  gp=$(count_groups "$prefix"); gv=$(count_groups "$val")
  vi=$((2 + gp))
  re="(${prefix})(${val})"
  if [ -n "$suf" ]; then re+="(${suf})"; si=$((vi + 1 + gv)); fi
  ctx_redact "$re" 1 "$vi" "$si" 0 "$rule"
}

# Access-key IDs are semi-public identifiers by convention; the secret half
# is the enforced boundary. Redact IDs too only when
# SECRET_GUARD_REDACT_KEY_IDS=1.
shopt -s nocasematch
KW='secret|passw(or)?d|pwd|passphrase|token|api[_-]?key|apikey|private[_-]?key|credential'
if [ "${SECRET_GUARD_REDACT_KEY_IDS:-0}" = "1" ]; then
  KW="${KW}|access[_-]?key|client[_-]?id"
fi
KEYCH='[A-Za-z0-9_.-]'
# Key names where the keyword is a WHOLE segment (so "compass" never matches
# "pass"): PW, PWD, PASS, CRED, CREDS, PAT, client-key-data.
ALIAS='pw|pwd|pass|creds?|pat|client-key-data'
KEY_A="${KEYCH}*(${KW})${KEYCH}*"
KEY_B="(^|[^A-Za-z0-9_.-])(${KEYCH}*[_.-])?(${ALIAS})([_.-]${KEYCH}*)?"
KEY_ANY="(${KEY_A}|(${KEYCH}*[_.-])?(${ALIAS})([_.-]${KEYCH}*)?)"
# Blanks only, never newlines: a line that ends in "secret:" or "token:" is a
# heading, not a key, and the next line's first word is not its value. With
# [[:space:]] here a sentence ending in "secret:" redacted the first word of
# the following line (found live, in the Bash output of the v0.2.2 check).
DELIM='["'"'"']?[[:blank:]]*[:=][[:blank:]]*'
# A quoted value stays on its line: quote marks that merely wrap a key word
# ("token:" in prose) must not swallow every line up to the next quote.
NLC=$'\n'
V_DQ="(\\\\[^${NLC}]|[^\"\\\\${NLC}]){4,}"
V_SQ="(\\\\[^${NLC}]|[^'\\\\${NLC}]){4,}"
V_BARE='[^[:space:]"'"'"']{4,}'

# --- Very long unbroken runs: mask them for the context rules ----------------
# The key patterns start with a run of name characters, so on one long
# unbroken run (a base64 blob, a hash, a minified bundle without spaces) every
# start position is tried against the whole run: a 20 KB run took 10 s and the
# publish guard denied the commit as "did not finish". No key name is that
# long, so runs of 256+ name characters are swapped for a short placeholder for
# the context rules and put back afterwards. A value that IS such a run (a
# long token after a key) is still redacted: the placeholder is a 4+ character
# value. At most 200 distinct runs are masked per input.
CTX_RUN_MIN=256
CTX_RUNS=()
ctx_mask_runs() {
  local run i=0
  CTX_RUNS=()
  [[ "$CTX_TEXT" == *"~~R"* ]] && return 0
  while IFS= read -r run; do
    [ -n "$run" ] || continue
    CTX_RUNS[i]="$run"
    CTX_TEXT="${CTX_TEXT//"$run"/"~~R${i}~~"}"
    i=$((i + 1))
  done < <(printf '%s' "$CTX_TEXT" | grep -oE "[A-Za-z0-9_.-]{${CTX_RUN_MIN},}" 2>/dev/null | sort -u | head -n 200)
}
ctx_unmask_runs() {
  local i
  for i in "${!CTX_RUNS[@]}"; do
    CTX_TEXT="${CTX_TEXT//"~~R${i}~~"/"${CTX_RUNS[i]}"}"
  done
  CTX_RUNS=()
}
ctx_mask_runs

# --- key <delim> value, in the three quoting styles, for both key families
for KEYRE in "$KEY_A" "$KEY_B"; do
  ctx_rule secret-lead-in "$KEYRE" "${DELIM}\"" "$V_DQ" '"' '"'
  ctx_rule secret-lead-in "$KEYRE" "${DELIM}'" "$V_SQ" "'" "'"
  ctx_rule secret-lead-in "$KEYRE" "$DELIM" "$V_BARE"
done

# --- the one next-line form that is a value, not a heading ------------------
# YAML puts a scalar on the line after its key:
#       password:
#         <value>
# The key rules above allow blanks after the delimiter, never a newline (a line
# ending in "secret:" is usually a heading and the next line's first word is not
# its value). This rule recovers the YAML form narrowly: the key line must be
# ONLY the key and a colon (optionally "- "), so prose like "Rotate the secret:"
# never qualifies, and the next line must be ONE bare token with no colon and
# nothing after it, so a nested key ("name: x"), a command or a sentence never
# qualifies. Tradeoff: "Password:" alone on a line followed by one word still
# redacts that word.
NL=$'\n'
ctx_plain secret-lead-in "(^|${NL})[[:blank:]]*(-[[:blank:]]+)?[\"']?${KEY_A}[\"']?:[[:blank:]]*${NL}[[:blank:]]+" '[^[:space:]:"'"'"']{4,}' "${NL}|\$"

# --- URLs: scheme://user:PASSWORD@host, secret-ish query parameters
ctx_plain url-password '://[^/[:space:]:@]*:' '[^[:space:]@/]{3,}' '@'
ctx_plain url-query-secret '[?&](password|passwd|pwd|secret|token|access_token|api_key|apikey|x-amz-signature|x-amz-security-token)=' '[^&[:space:]"'"'"']{4,}'

# --- HTTP: Authorization and Cookie headers
ctx_plain auth-header 'authorization:[[:space:]]*(basic|bearer|token|digest)[[:space:]]+' '[^[:space:]"'"'"']{8,}'
ctx_plain cookie-header '(^|[^A-Za-z-])(set-)?cookie:[[:space:]]*' '[^[:cntrl:]]{8,}'

# --- Command-line flags. Space-separated and glued
# forms; --password=VALUE is already covered by the key rules above.
ctx_plain cli-password-flag '(^|[[:space:]])--(password|passwd|pass|token|secret|api-key|apikey|client-secret|access-token|auth-token)[[:space:]]+' '[^[:space:]-][^[:space:]]{3,}'
ctx_plain cli-password-flag '(mysql|mysqldump|mysqladmin|mariadb)[^|;&]*[[:space:]]-p' '[^[:space:]-][^[:space:]]{2,}'
ctx_plain cli-password-flag 'redis-cli[^|;&]*[[:space:]]-a[[:space:]]+' '[^[:space:]]{4,}'
ctx_plain cli-password-flag 'sshpass[[:space:]]+-p[[:space:]]*' '[^[:space:]]{4,}'
ctx_plain cli-password-flag 'docker[[:space:]]+login[^|;&]*[[:space:]]-p[[:space:]]+' '[^[:space:]]{4,}'
ctx_plain cli-password-flag 'mc[[:space:]]+alias[[:space:]]+set[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+' '[^[:space:]]{4,}'

# --- Credential files: .netrc and .pgpass
ctx_plain netrc-password '(^|[[:space:]])machine[[:space:]]+[^[:space:]]+([[:space:]]+(login|account)[[:space:]]+[^[:space:]]+)*[[:space:]]+password[[:space:]]+' '[^[:space:]]+'
ctx_plain pgpass-password '(^|[[:space:]])[A-Za-z0-9_.*-]+:[0-9*]+:[A-Za-z0-9_.*-]+:[A-Za-z0-9_.@-]+:' '[^[:space:]]{4,}'

# --- Key and value on separate lines or in one JSON object
ctx_plain k8s-env-value '(^|[^A-Za-z0-9_.-])name:[[:space:]]*["'"'"']?'"${KEY_ANY}"'["'"'"']?[[:space:]]+value:[[:space:]]*["'"'"']?' '[^[:space:]"'"'"']{4,}'
ctx_plain json-key-value '"(name|key)"[[:space:]]*:[[:space:]]*"'"${KEY_ANY}"'"[[:space:]]*,[[:space:]]*"value"[[:space:]]*:[[:space:]]*"' '[^"]{4,}' '"'

ctx_unmask_runs

# --- Vendor token shapes gitleaks' default ruleset lacks (P2)
ctx_plain azure-client-secret '(^|[^A-Za-z0-9_~.-])' '[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{34}'
ctx_plain gcloud-oauth-token '(^|[^A-Za-z0-9_-])' 'ya29\.[A-Za-z0-9_-]{20,}'
ctx_plain gcloud-oauth-token '(^|[^A-Za-z0-9_-])' '1//0[A-Za-z0-9_-]{30,}'
ctx_plain bcrypt-hash '(^|[^A-Za-z0-9$])\$2[aby]\$[0-9]{2}\$' '[./A-Za-z0-9]{53}'
shopt -u nocasematch

# --- Secrets hiding in base64 ---------------------------------
# A value under an innocent key name ({"conn": "cG9zdGdyZXM6Ly8..."}, a
# Kubernetes Secret, a config map) is invisible to every key-name rule. Decode
# long base64-looking tokens and run the DETERMINISTIC passes on the decoded
# text (no gitleaks, no further decoding); if a secret is found, the whole
# token is redacted. Cheap by construction: hex digests (git hashes, sha256)
# are skipped without decoding, binary decodes (images, archives) are dropped
# by a printable-ratio test, and at most 25 tokens of 44-65536 characters are
# tried per scan. SECRET_GUARD_B64=0 turns it off.
if [ "${SECRET_GUARD_B64:-1}" = "1" ] && [ -z "${SECRET_GUARD_B64_DEPTH:-}" ]; then
  b64_tmp="$(mktemp)"
  # Candidates come from ONE grep: a bounded repeat like {44,4096} in bash's own
  # regex engine costs seconds per call (measured +2.9 s on a 24 KB scan).
  while IFS= read -r b64_cand; do
    [ "${#b64_cand}" -le 65536 ] || continue
    [[ "$b64_cand" =~ ^[0-9a-fA-F]+$ ]] && continue          # hex digest, not base64
    [[ "$b64_cand" =~ ^[A-Za-z]+$ ]] && continue             # one long word
    b64_std="${b64_cand//-/+}"; b64_std="${b64_std//_//}"
    while [ $(( ${#b64_std} % 4 )) -ne 0 ]; do b64_std+="="; done
    printf '%s' "$b64_std" | base64 -d > "$b64_tmp" 2>/dev/null || continue
    b64_len="$(wc -c < "$b64_tmp")"
    [ "$b64_len" -ge 16 ] || continue
    b64_print="$(LC_ALL=C tr -cd '[:print:][:space:]' < "$b64_tmp" | wc -c)"
    [ $(( b64_print * 100 )) -ge $(( b64_len * 95 )) ] || continue   # mostly printable text only
    b64_dec="$(cat "$b64_tmp")"
    b64_out="$(printf '%s' "$b64_dec" | SECRET_GUARD_B64_DEPTH=1 SECRET_GUARD_SKIP_GITLEAKS=1 SECRET_GUARD_ENV_VALUES=0 bash "$0" 2>/dev/null)"
    if [ "$b64_out" != "$b64_dec" ]; then
      CTX_TEXT="${CTX_TEXT//"$b64_cand"/***REDACTED:SECRET***}"
      CTX_HITS=$((CTX_HITS + 1))
      case " $EXTRA_RULES " in *" base64-secret "*) ;; *) EXTRA_RULES="${EXTRA_RULES:+$EXTRA_RULES }base64-secret" ;; esac
    fi
  done < <(printf '%s' "$CTX_TEXT" | grep -oE '[A-Za-z0-9+/_-]{44,}={0,2}' 2>/dev/null | sort -u | head -n 25)
  rm -f "$b64_tmp"
fi

# --- Known secret VALUES from the environment ---
# A bare value with no key name or prefix (`echo $DB_PASSWORD`, an env dump)
# is not detectable by any rule, but the process that is about to emit it
# often HAS it in its environment. When SECRET_GUARD_ENV_VALUES=1, exact-
# match redact the values of environment variables whose NAMES look secret.
# Opt-in because it only makes sense where the scanner shares the session's
# environment (the plugin's hooks and fallback), not in the service container.
# Skipped: values under 8 chars, placeholders, and names that denote a
# location or label (_FILE, _PATH, _DIR, _URL, _NAME, _ID, _TYPE, _HOST, _USER).
if [ "${SECRET_GUARD_ENV_VALUES:-0}" = "1" ]; then
  while IFS= read -r envname; do
    [[ "$envname" =~ (SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_KEY|CREDENTIAL|(^|_)(PW|PWD|PASS)($|_)) ]] || continue
    [[ "$envname" =~ (_FILE|_PATH|_DIR|_URL|_URI|_NAME|_ID|_TYPE|_HOST|_PORT|_USER)$ ]] && continue
    # PWD / OLDPWD are the shell's current directories, not passwords: their
    # names match the PW alias and the live check found every mention of the
    # working directory in Bash output redacted.
    case "$envname" in PWD|OLDPWD) continue ;; esac
    envval="${!envname}"
    [ "${#envval}" -ge 8 ] || continue
    ctx_placeholder "$envval" && continue
    # A value that is an existing file or directory is a path, not a secret.
    [ -e "$envval" ] && continue
    if [[ "$CTX_TEXT" == *"$envval"* ]]; then
      CTX_TEXT="${CTX_TEXT//"$envval"/***REDACTED:SECRET***}"
      CTX_HITS=$((CTX_HITS + 1))
      case " $EXTRA_RULES " in *" env-value "*) ;; *) EXTRA_RULES="${EXTRA_RULES:+$EXTRA_RULES }env-value" ;; esac
    fi
  done < <(compgen -e)
fi

# Nothing redacted: hand back the original (ANSI intact, trailing newline kept).
if [ "$CTX_HITS" -eq 0 ]; then
  CTX_TEXT="$CTX_ORIG"
fi

if [ "$CTX_HITS" -gt 0 ]; then
  echo "REDACTED rule=context hits=$CTX_HITS rules=$EXTRA_RULES" >&2
fi
PEM_TEXT="$CTX_TEXT"
EXTRA_HITS=$((PEM_HITS + CTX_HITS))

# extra_findings_json: the extra rules as JSON array members, no jq needed.
extra_findings_json() {
  local r out=""
  for r in $EXTRA_RULES; do
    out+="${out:+,}{\"RuleID\":\"$r\",\"StartLine\":0,\"Fingerprint\":\"\"}"
  done
  printf '%s' "$out"
}

# emit_unflagged: output for the paths where gitleaks found nothing (or
# could not run). Preserves the input byte-for-byte unless the private-key
# or context pass changed something, and reports those passes as findings.
emit_unflagged() {
  if [ "$EXTRA_HITS" -gt 0 ]; then
    if [ -n "${SECRET_GUARD_FINDINGS_JSON:-}" ]; then
      printf '[%s]' "$(extra_findings_json)" > "$SECRET_GUARD_FINDINGS_JSON"
    fi
    printf '%s' "$PEM_TEXT"
  else
    cat "$INPUT_FILE"
  fi
}

# SECRET_GUARD_SKIP_GITLEAKS=1: run only the deterministic passes above
# (private-key, context rules, env values) and skip gitleaks. For callers that
# already got gitleaks' answer from the warm service (/v1/scan/secret) and only
# need the passes that need the local environment. Saves the gitleaks process
# start (about 230 ms on a laptop, about 20 ms in the container).
if [ "${SECRET_GUARD_SKIP_GITLEAKS:-0}" = "1" ]; then
  emit_unflagged
  exit 0
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "secret-guard: gitleaks not found on PATH, skipping scan (fail-open — unknown whether a secret is present)" >&2
  emit_unflagged
  exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "secret-guard: jq not found on PATH, skipping scan (fail-open — unknown whether a secret is present)" >&2
  emit_unflagged
  exit 0
fi

# One retry if gitleaks itself errors, so a transient failure is not
# silently read as "no secrets". Its stderr is kept to the log line only.
run_gitleaks() {
  gitleaks detect --no-git -s "$INPUT_FILE" --report-format json --report-path "$REPORT_FILE" --exit-code 0 >/dev/null 2>&1
}
if ! run_gitleaks; then
  echo "secret-guard: gitleaks exited non-zero, retrying once" >&2
  : > "$REPORT_FILE"
  run_gitleaks || echo "secret-guard: gitleaks failed twice; relying on the private-key pass only" >&2
fi

# gitleaks' generic-api-key rule reads any "secret_*"/"token_*" key with a
# quoted value as a credential, including a key that only names an identifier
# or reference (client_secret_bws_id: "...", secretName: "..."). Drop those
# findings with the same key-name check the context pass uses, so the two
# passes agree. Only generic-api-key; a vendor-shaped rule match stays.
if [ -s "$REPORT_FILE" ] && [ "$(jq -r 'length' "$REPORT_FILE" 2>/dev/null)" != "0" ]; then
  DROP_IDX=""
  shopt -s nocasematch
  while IFS=$'\t' read -r idx mtch; do
    [[ "$mtch" =~ ([A-Za-z0-9_.-]*($KW)[A-Za-z0-9_.-]*) ]] || continue
    ctx_describes_secret "${BASH_REMATCH[1]}" && DROP_IDX="${DROP_IDX:+$DROP_IDX,}$idx"
  done < <(jq -r 'to_entries[] | select(.value.RuleID == "generic-api-key") | [.key, ((.value.Match // "") | gsub("[\t\n\r]"; " "))] | @tsv' "$REPORT_FILE" 2>/dev/null)
  shopt -u nocasematch
  if [ -n "$DROP_IDX" ]; then
    jq -c --argjson d "[$DROP_IDX]" 'to_entries | map(select(.key as $k | $d | index($k) | not)) | map(.value)' \
      "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
  fi
fi

# gitleaks writes "[]" (not "null") when there are no findings; treat all
# three as "nothing found" so clean input passes through byte-for-byte.
if [ ! -s "$REPORT_FILE" ] || [ "$(cat "$REPORT_FILE")" = "null" ] \
  || [ "$(jq -r 'length' "$REPORT_FILE" 2>/dev/null)" = "0" ]; then
  emit_unflagged
  exit 0
fi

# Findings confirmed from here on — redact unconditionally, no fallback
# path that could pass a known secret through unredacted.
# One jq call for all findings: two jq processes per finding cost about
# 20 ms each, so 300 findings took 5 s of pure logging.
jq -r '.[] | "REDACTED rule=\(.RuleID // "unknown") line=\(.StartLine // "?")"' "$REPORT_FILE" >&2

if [ -n "${SECRET_GUARD_FINDINGS_JSON:-}" ]; then
  jq -c '[.[] | {RuleID: (.RuleID // "unknown"), StartLine: .StartLine, Fingerprint: (.Fingerprint // "")}]' \
    "$REPORT_FILE" > "$SECRET_GUARD_FINDINGS_JSON"
fi

# Start from the private-key-pass output (identical to the input when it
# found nothing).
TEXT="$PEM_TEXT"

# Replace longest secrets first so overlapping/substring matches don't
# clobber each other's placeholders. Plain bash substring substitution,
# NOT regex -- but the pattern MUST be quoted: an unquoted ${TEXT//$s/..}
# treats $s as a glob, so a backslash, *, ? or [ in the secret (an
# escaped-newline PEM inside JSON, a password with punctuation) silently
# stops matching and the "redaction" is a no-op while the verdict still
# says found.
#
# Secrets are NUL-delimited, not newline-delimited: a multi-line secret
# (a PEM block) must be replaced as ONE unit, not as its lines.
SECRETS_FILE="$(mktemp)"
FRAGMENTS_FILE="$(mktemp)"
trap 'rm -f "$INPUT_FILE" "$REPORT_FILE" "$SECRETS_FILE" "$FRAGMENTS_FILE"' EXIT

jq -j '[.[] | .Secret // empty] | unique | sort_by(-length) | .[] | (., "\u0000")' \
  "$REPORT_FILE" > "$SECRETS_FILE"
# Per-line fragments (16+ chars) of every secret, as a second pass: the
# whole-secret replace above can miss when the scanner's reported span
# and the text differ by line endings (CRLF). Short fragments are skipped
# so ordinary words are never clobbered.
jq -j '[.[] | .Secret // empty | split("\n")[] | rtrimstr("\r") | select(length >= 16)] | unique | sort_by(-length) | .[] | (., "\u0000")' \
  "$REPORT_FILE" > "$FRAGMENTS_FILE"

while IFS= read -r -d '' secret; do
  [ -n "$secret" ] && TEXT="${TEXT//"$secret"/***REDACTED:SECRET***}"
done < "$SECRETS_FILE"
while IFS= read -r -d '' frag; do
  [ -n "$frag" ] && TEXT="${TEXT//"$frag"/***REDACTED:SECRET***}"
done < "$FRAGMENTS_FILE"

# Verify, fail CLOSED. A finding was confirmed above, so if any reported
# secret (or 16+ char line of one) is still present, withhold the whole
# output instead of passing known secret material through.
LEAKED=0
while IFS= read -r -d '' secret; do
  if [ -n "$secret" ] && [[ "$TEXT" == *"$secret"* ]]; then LEAKED=1; fi
done < "$SECRETS_FILE"
while IFS= read -r -d '' frag; do
  if [ -n "$frag" ] && [[ "$TEXT" == *"$frag"* ]]; then LEAKED=1; fi
done < "$FRAGMENTS_FILE"
if [ "$LEAKED" -eq 1 ]; then
  echo "secret-guard: redaction did not remove a confirmed secret, withholding the whole output (fail-closed)" >&2
  printf '%s' "$WITHHELD"
  exit 0
fi

# The private-key and context passes count as findings even when gitleaks
# reported others, so adapters reading the findings JSON see them.
if [ "$EXTRA_HITS" -gt 0 ] && [ -n "${SECRET_GUARD_FINDINGS_JSON:-}" ]; then
  jq -c --argjson extra "[$(extra_findings_json)]" '. + $extra' "$SECRET_GUARD_FINDINGS_JSON" \
    > "$SECRET_GUARD_FINDINGS_JSON.tmp" && mv "$SECRET_GUARD_FINDINGS_JSON.tmp" "$SECRET_GUARD_FINDINGS_JSON"
fi

printf '%s' "$TEXT"
