#!/usr/bin/env bash
# guards/hooks/credclass-lib.sh -- sourced by the hooks; not run directly.
#
# WHY: the question "is this path credential material?" is shared. credfile-guard
# asks it of Read/Grep/Bash file arguments; the outbound-command guard asks the
# same of paths a command would send out. One definition, so the two cannot drift.
# Moved here unchanged from credfile-guard.sh; this file only defines functions
# and does nothing when sourced.
#
# Needs from the caller (read when a function runs, not when sourced):
#   CWD              directory relative paths resolve against (resolve_path)
#   SNIFF_MAX_BYTES  how much of a file the private-key content sniff reads
#   PRIVATE_KEY_RE   ERE matching a PEM/OpenSSH private-key header
#   GUARDS_CRED_SNIFF_STRICT  optional; 1 = any header makes the file a key (the behavior before coordination#86)
#   HOME             for ~ and $HOME expansion
# Needs on PATH: head, grep, tr, readlink (realpath -m is used when it works;
# realpath-lib.sh resolves symlinks without it, as on stock macOS).
# Defines: resolve_path, sensitive_reason, key_header_is_a_key, sensitive_dir_reason, is_ask_class.

# shellcheck source=guards/hooks/realpath-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/realpath-lib.sh" || return 1

# resolve PATH -> absolute, ~ and $HOME expanded, symlinks followed if
# the target exists. Prints nothing for an empty argument.
resolve_path() {
  local p="$1"
  [ -n "$p" ] || return 0
  case "$p" in
    \~) p="$HOME" ;;
    \~/*) p="$HOME/${p#\~/}" ;;
    '$HOME'|'${HOME}') p="$HOME" ;;
    '$HOME/'*) p="$HOME/${p#'$HOME/'}" ;;
    '${HOME}/'*) p="$HOME/${p#'${HOME}/'}" ;;
  esac
  case "$p" in
    /*) ;;
    *) p="$CWD/$p" ;;
  esac
  gd_realpath "$p"
}

# sensitive_reason PATH -> prints a short reason and returns 0 if PATH
# is credential material, else returns 1. PATH must already be resolved.
sensitive_reason() {
  local p="$1" base lower
  base="${p##*/}"
  lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"

  case "$p" in
    */.ssh/*)
      case "$lower" in
        *.pub|known_hosts|known_hosts.old|config|authorized_keys|authorized_keys2) ;;
        *) printf 'SSH key material under ~/.ssh'; return 0 ;;
      esac ;;
    */.aws/credentials) printf 'AWS credentials file'; return 0 ;;
    */.kube/config|*/.kube/*.kubeconfig) printf 'kubeconfig'; return 0 ;;
    */.config/gcloud/*credentials*|*/.config/gcloud/*.json) printf 'gcloud credentials'; return 0 ;;
    */.docker/config.json) printf 'docker registry auth'; return 0 ;;
    */.gnupg/private-keys-v1.d/*|*/.gnupg/secring.*) printf 'GPG private keyring'; return 0 ;;
  esac

  case "$lower" in
    .netrc|_netrc) printf '.netrc credentials'; return 0 ;;
    .pgpass) printf '.pgpass credentials'; return 0 ;;
    .git-credentials) printf 'git credential store'; return 0 ;;
    .npmrc|.pypirc) printf 'package-registry token file'; return 0 ;;
    kubeconfig|*.kubeconfig) printf 'kubeconfig'; return 0 ;;
    .env.example|.env.sample|.env.template|.env.dist|*.env.example|*.env.sample|*.env.template) ;;
    .env|.env.*|*.env) printf 'environment file (.env)'; return 0 ;;
    id_rsa|id_dsa|id_ecdsa|id_ed25519) printf 'SSH private key'; return 0 ;;
    *.p12|*.pfx|*.jks|*.keystore|*.kdbx) printf 'keystore / password database'; return 0 ;;
    *.tfstate|*.tfstate.backup) printf 'terraform state (contains secrets)'; return 0 ;;
    *service-account*.json|*serviceaccount*.json|*credentials*.json|*client_secret*.json)
      printf 'service-account / client-secret JSON'; return 0 ;;
  esac

  # Content sniff, any name. grep -q: nothing is printed. A header anywhere is the cheap first test;
  # when it matches, key_header_is_a_key decides whether the file holds a key or only quotes the header.
  if [ -f "$p" ] && [ -r "$p" ]; then
    if head -c "$SNIFF_MAX_BYTES" -- "$p" 2>/dev/null | grep -qaE -e "$PRIVATE_KEY_RE"; then
      if key_header_is_a_key "$p"; then
        printf 'file contains a private key'; return 0
      fi
    fi
  fi
  return 1
}

# key_header_is_a_key FILE -> 0 when FILE (which holds a private-key header) looks like a key, 1 when the
# header is only quoted in prose (coordination#86: a design note or runbook that names the header).
# A file is a key when ANY header occurrence
#   - starts its line (after blanks and a markdown quote or list prefix): a PEM block, or a truncated one;
#   - ends its line, or is followed by a literal \n (a key inside JSON), or by base64 with no space;
# or when a header appears anywhere and a line of 40 or more base64 characters stands alone (the body).
# A header followed by a space and words in the middle of a line (a sentence naming it) does not count.
# Fail closed: an awk that cannot run (exit 2 or more), or GUARDS_CRED_SNIFF_STRICT=1, treats the file as a key.
key_header_is_a_key() {
  [ "${GUARDS_CRED_SNIFF_STRICT:-0}" = 1 ] && return 0
  head -c "$SNIFF_MAX_BYTES" -- "$1" 2>/dev/null | LC_ALL=C awk -v re="$PRIVATE_KEY_RE" '
    {
      line = $0
      if (match(line, re)) {
        hdr = 1
        before = substr(line, 1, RSTART - 1)
        after = substr(line, RSTART + RLENGTH)
        if (before ~ /^[ \t>*+-]*$/) key = 1
        else if (after ~ /^[ \t\r]*$/) key = 1
        else if (after ~ /^\\[nr]/) key = 1
        else if (after ~ /^[A-Za-z0-9+\/=]/) key = 1
      }
      if (length(line) >= 40 && line ~ /^[A-Za-z0-9+\/]+=*[ \t\r]*$/) body = 1
    }
    END { if (key || (hdr && body)) exit 0; exit 1 }'
  case $? in
    0) return 0 ;;
    1) return 1 ;;
    *) return 0 ;;
  esac
}

# sensitive_dir_reason DIR -> for Grep/Bash over a whole credential dir.
sensitive_dir_reason() {
  case "$1/" in
    */.ssh/|*/.aws/|*/.kube/|*/.gnupg/|*/.config/gcloud/|*/.docker/)
      printf 'credential directory'; return 0 ;;
  esac
  return 1
}

# Private keys and credential stores are never worth reading: DENY. Config
# files that merely CONTAIN credentials (a .env you are debugging) are ASK.
# GUARDS_CRED_ASK=0 makes everything a hard deny, and so does a permission mode
# with no person to answer the prompt (see ask() above).
is_ask_class() {
  case "$1" in
    "environment file (.env)"|"kubeconfig"|"package-registry token file"|"terraform state (contains secrets)"|"glob targets .env files") return 0 ;;
  esac
  return 1
}
