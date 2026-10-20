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
#   HOME             for ~ and $HOME expansion
# Needs on PATH: head, grep, tr, readlink (realpath -m is used when it works;
# realpath-lib.sh resolves symlinks without it, as on stock macOS).
# Defines: resolve_path, sensitive_reason, sensitive_dir_reason, is_ask_class.

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

  # Content sniff, any name. grep -q: nothing is printed.
  if [ -f "$p" ] && [ -r "$p" ]; then
    if head -c "$SNIFF_MAX_BYTES" -- "$p" 2>/dev/null | grep -qaE -e "$PRIVATE_KEY_RE"; then
      printf 'file contains a private key'; return 0
    fi
  fi
  return 1
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
