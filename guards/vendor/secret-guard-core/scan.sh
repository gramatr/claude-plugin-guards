#!/usr/bin/env bash
# VENDORED COPY — source of truth is gramatr/secret-guard's core/scan.sh. Sync manually.
# Local changes ahead of upstream: quoted redaction pattern, fail-closed verify, linear-time span split, deterministic private-key, context and base64 passes, SECRET_GUARD_SKIP_GITLEAKS, env-value pass that skips PWD/paths (guards-unified, guards-coordination#1/#3/#5/#9/#10/#11).
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
# truncated key (head, clipped output) was never detected at all
# (guards-coordination#5/#10). So: match BEGIN ... PRIVATE KEY----- plus
# whatever base64 / escaped-newline / whitespace body follows, END marker
# optional, and redact it here. Runs even if gitleaks or jq is missing.
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
# scheme is a secret whatever it looks like (guards-coordination#1/#9).
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
  return 1
}
# Keys that merely NAME or describe a secret (secretName, token_type, ...).
ctx_describes_secret() {
  [[ "$1" =~ (secret|token|credential)s?[_.-]?(name|ref|id|type|path|file|version|count|ttl|namespace|store|manager|provider|url|arn)$ ]] && return 0
  [[ "$1" =~ (secretkeyref|secretref|secretkey_?ref) ]] && return 0
  return 1
}

# ctx_redact RE PREFIX_IDX VALUE_IDX SUFFIX_IDX(0=none) KEY_IDX(0=none) RULE_ID
ctx_redact() {
  local re="$1" pi="$2" vi="$3" si="$4" ki="$5" rule="$6"
  local rest="$CTX_TEXT" out="" m pre pfx val sfx key tmp sent
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
    if ctx_placeholder "$val" || { [ -n "$key" ] && ctx_describes_secret "$key"; } \
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

# ctx_rule RULE KEYRE DELIMRE VALRE [SUFRE]: a "key <delim> value" rule.
# Builds ((KEYRE)DELIM)(VAL)[(SUF)] and works out the group indexes.
ctx_rule() {
  local rule="$1" keyre="$2" delim="$3" val="$4" suf="${5:-}" gk gd gv vi si=0 re
  gk=$(count_groups "$keyre"); gd=$(count_groups "$delim"); gv=$(count_groups "$val")
  vi=$((3 + gk + gd))
  re="((${keyre})${delim})(${val})"
  if [ -n "$suf" ]; then re+="(${suf})"; si=$((vi + 1 + gv)); fi
  ctx_redact "$re" 1 "$vi" "$si" 2 "$rule"
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
# is the enforced boundary (guards-coordination#3). Redact IDs too only when
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
DELIM='["'"'"']?[[:space:]]*[:=][[:space:]]*'
V_DQ='(\\.|[^"\\]){4,}'
V_SQ="(\\\\.|[^'\\\\]){4,}"
V_BARE='[^[:space:]"'"'"']{4,}'

# --- key <delim> value, in the three quoting styles, for both key families
for KEYRE in "$KEY_A" "$KEY_B"; do
  ctx_rule secret-lead-in "$KEYRE" "${DELIM}\"" "$V_DQ" '"'
  ctx_rule secret-lead-in "$KEYRE" "${DELIM}'" "$V_SQ" "'"
  ctx_rule secret-lead-in "$KEYRE" "$DELIM" "$V_BARE"
done

# --- URLs: scheme://user:PASSWORD@host, secret-ish query parameters
ctx_plain url-password '://[^/[:space:]:@]*:' '[^[:space:]@/]{3,}' '@'
ctx_plain url-query-secret '[?&](password|passwd|pwd|secret|token|access_token|api_key|apikey|x-amz-signature|x-amz-security-token)=' '[^&[:space:]"'"'"']{4,}'

# --- HTTP: Authorization and Cookie headers
ctx_plain auth-header 'authorization:[[:space:]]*(basic|bearer|token|digest)[[:space:]]+' '[^[:space:]"'"'"']{8,}'
ctx_plain cookie-header '(^|[^A-Za-z-])(set-)?cookie:[[:space:]]*' '[^[:cntrl:]]{8,}'

# --- Command-line flags (guards-coordination#10). Space-separated and glued
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

# --- Vendor token shapes gitleaks' default ruleset lacks (P2)
ctx_plain azure-client-secret '(^|[^A-Za-z0-9_~.-])' '[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{34}'
ctx_plain gcloud-oauth-token '(^|[^A-Za-z0-9_-])' 'ya29\.[A-Za-z0-9_-]{20,}'
ctx_plain gcloud-oauth-token '(^|[^A-Za-z0-9_-])' '1//0[A-Za-z0-9_-]{30,}'
ctx_plain bcrypt-hash '(^|[^A-Za-z0-9$])\$2[aby]\$[0-9]{2}\$' '[./A-Za-z0-9]{53}'
shopt -u nocasematch

# --- Secrets hiding in base64 (guards-coordination#11) ---------------------
# A value under an innocent key name ({"conn": "cG9zdGdyZXM6Ly8..."}, a
# Kubernetes Secret, a config map) is invisible to every key-name rule. Decode
# long base64-looking tokens and run the DETERMINISTIC passes on the decoded
# text (no gitleaks, no further decoding); if a secret is found, the whole
# token is redacted. Cheap by construction: hex digests (git hashes, sha256)
# are skipped without decoding, binary decodes (images, archives) are dropped
# by a printable-ratio test, and at most 25 tokens of 44-4096 characters are
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

# --- Known secret VALUES from the environment (guards-coordination#11) ---
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
# says found (guards-coordination#4/#5).
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
