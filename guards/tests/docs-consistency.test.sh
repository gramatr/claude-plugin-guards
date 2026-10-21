#!/usr/bin/env bash
# guards/tests/docs-consistency.test.sh -- the docs say what the hooks do.
#
# A hook that is registered in hooks.json but missing from the docs, a hook count
# that no longer matches, or a setting the script reads that CONFIGURATION.md does
# not list, all went unnoticed until someone read the page. This checks:
#   1. every script registered in hooks.json has a row in the hook table of
#      docs/HOOKS.md and in the table of guards/README.md, and every guard (not the
#      self-heal) has a row in the failure-mode matrix;
#   2. HOOKS.md and README.md state the number of registered hooks, in words;
#   3. every GUARDS_*, CREDFILE_* and SS_SERVICE_TIMEOUT setting that
#      outbound-guard.sh reads is listed in docs/CONFIGURATION.md;
#   4. LIMITS.md has an "Outbound commands" section and no longer says curl is not
#      covered; HOOKS.md has the outbound guard in the ask-versus-deny table.
# A negative control mutates a copy of the docs and expects the checks to fail.
# Needs bash, jq, grep.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

word_of() {
  case "$1" in
    1) echo one ;; 2) echo two ;; 3) echo three ;; 4) echo four ;; 5) echo five ;;
    6) echo six ;; 7) echo seven ;; 8) echo eight ;; 9) echo nine ;; 10) echo ten ;;
    11) echo eleven ;; 12) echo twelve ;; *) echo "$1" ;;
  esac
}

# check_docs ROOT -> runs every check against ROOT/docs and ROOT/guards, counting into pass/fail.
check_docs() {
  local root="$1" hooks hooksmd readme conf limits scripts n w s v
  hooks="$root/guards/hooks/hooks.json"
  hooksmd="$root/docs/HOOKS.md"
  readme="$root/guards/README.md"
  conf="$root/docs/CONFIGURATION.md"
  limits="$root/docs/LIMITS.md"
  scripts="$(jq -r '[.hooks[][].hooks[].args[0]] | .[] | split("/") | last' "$hooks" | sort -u)"
  n="$(printf '%s\n' "$scripts" | grep -c .)"
  w="$(word_of "$n")"

  for s in $scripts; do
    if grep -E "^\|.*\`(hooks|bin)/$s\`" "$hooksmd" > /dev/null; then ok; else bad "docs/HOOKS.md hook table has no row for $s"; fi
    if grep -E "^\|.*\`(hooks|bin)/$s\`" "$readme" > /dev/null; then ok; else bad "guards/README.md hook table has no row for $s"; fi
    case "$s" in
      *selfheal*) ;;
      *)
        if grep -E "^\|.*\(\`$s\`\)" "$hooksmd" > /dev/null; then ok; else bad "docs/HOOKS.md failure-mode matrix has no row for $s"; fi ;;
    esac
  done

  if grep -q "registers $w hooks" "$hooksmd"; then ok; else bad "docs/HOOKS.md does not say it registers $w hooks (hooks.json has $n)"; fi
  if grep -q "^## The $w hooks" "$readme"; then ok; else bad "guards/README.md heading is not 'The $w hooks' (hooks.json has $n)"; fi
  if grep -q "$w hooks and one MCP server" "$readme"; then ok; else bad "guards/README.md intro does not say '$w hooks and one MCP server'"; fi
  rows="$(grep -c -E '^\| [0-9]+ \| `' "$readme")"
  if [ "$rows" -eq "$n" ]; then ok; else bad "guards/README.md hook table has $rows numbered rows, hooks.json has $n"; fi

  for v in $(grep -o -E '\$\{?(GUARDS_[A-Z_]+|CREDFILE_[A-Z_]+|SS_SERVICE_TIMEOUT)' "$root/guards/hooks/outbound-guard.sh" | tr -d '${' | sort -u); do
    case "$v" in GUARDS_DEADLINE_INNER) continue ;; esac
    if grep -q "\`$v\`" "$conf"; then ok; else bad "docs/CONFIGURATION.md does not list $v, which outbound-guard.sh reads"; fi
  done

  if grep -q '^## Outbound commands' "$limits"; then ok; else bad "docs/LIMITS.md has no 'Outbound commands' section"; fi
  if grep -q 'does not cover `curl`' "$limits"; then bad "docs/LIMITS.md still says curl is not covered"; else ok; fi
  if grep -q '^| Outbound guard, ' "$hooksmd"; then ok; else bad "docs/HOOKS.md ask-versus-deny table has no outbound guard row"; fi
}

check_docs "$REPO"

# --- negative control: a copy where the docs have drifted ------------------------
N="$(mktemp -d)"
trap 'rm -rf "$N"' EXIT
mkdir -p "$N/docs" "$N/guards/hooks"
cp "$REPO"/docs/HOOKS.md "$REPO"/docs/LIMITS.md "$REPO"/docs/CONFIGURATION.md "$N/docs/"
cp "$REPO"/guards/README.md "$N/guards/README.md"
cp "$REPO"/guards/hooks/hooks.json "$REPO"/guards/hooks/outbound-guard.sh "$N/guards/hooks/"
grep -v 'hooks/outbound-guard.sh' "$N/docs/HOOKS.md" > "$N/docs/HOOKS.md.tmp" && mv "$N/docs/HOOKS.md.tmp" "$N/docs/HOOKS.md"
sed -i.bak 's/registers eight hooks/registers seven hooks/' "$N/docs/HOOKS.md"
grep -v 'GUARDS_OUTBOUND_ASK' "$N/docs/CONFIGURATION.md" > "$N/docs/CONFIGURATION.md.tmp" && mv "$N/docs/CONFIGURATION.md.tmp" "$N/docs/CONFIGURATION.md"
grep -v '^## Outbound commands' "$N/docs/LIMITS.md" > "$N/docs/LIMITS.md.tmp" && mv "$N/docs/LIMITS.md.tmp" "$N/docs/LIMITS.md"
before_fail=$fail
check_docs "$N" > "$N/neg.out" 2>&1
neg_fail=$((fail - before_fail))
fail=$before_fail   # the control's failures are expected; count only whether it caught them
if [ "$neg_fail" -ge 4 ]; then ok; else bad "negative control: the checks caught only $neg_fail of the 4 planted drifts"; fi

# The marketplace front page and license (a reader of the marketplace sees the repo root, an
# installer gets only guards/): README at the root, the same MIT text in both places, the
# license named in the manifest, and no version field in the manifest (installs track main and
# are identified by commit; see docs/TRADEOFFS.md).
[ -s "$REPO/README.md" ] && ok || bad "the repository root has a README.md"
grep -q 'LICENSE' "$REPO/README.md" && ok || bad "the root README points at the license"
grep -q '^MIT License' "$REPO/LICENSE" && ok || bad "LICENSE is the MIT text"
if grep -q -E '^(---|This license covers)' "$REPO/LICENSE"; then bad "LICENSE holds only the license text (notes belong in NOTICE, or GitHub reports 'other')"; else ok; fi
cmp -s "$REPO/LICENSE" "$REPO/guards/LICENSE" && ok || bad "guards/LICENSE equals LICENSE, so the installed plugin carries the license"
cmp -s "$REPO/NOTICE" "$REPO/guards/NOTICE" && ok || bad "guards/NOTICE equals NOTICE"
if command -v jq > /dev/null 2>&1; then
  [ "$(jq -r '.plugins[0].license // ""' "$REPO/.claude-plugin/marketplace.json")" = MIT ] && ok || bad "marketplace.json names the plugin license"
  [ "$(jq -r '[.. | objects | select(has("version"))] | length' "$REPO/.claude-plugin/marketplace.json")" = 0 ] && ok || bad "marketplace.json has no version field"
fi

# The limits of the identity-use exemption are written down where the setting is (coordination#87).
grep -F 'GUARDS_CRED_IDENTITY_USE' "$REPO/docs/CONFIGURATION.md" | grep -q 'decrypted' && ok || bad "CONFIGURATION.md says the exemption does not cover a tool's decrypted output"
grep -F 'GUARDS_CRED_IDENTITY_USE' "$REPO/docs/CONFIGURATION.md" | grep -q 'rewrite' && ok || bad "CONFIGURATION.md says ssh-keygen -p can rewrite a key"
grep -q 'exempts the credential, not the tool' "$REPO/docs/LIMITS.md" && ok || bad "LIMITS.md states the limits of the use-only registry"

echo "docs-consistency: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
