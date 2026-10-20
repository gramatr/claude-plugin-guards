#!/usr/bin/env bash
# guards/hooks/realpath-lib.sh -- sourced by the hooks; not run directly.
#
# WHY: the hooks ask "where does this path really point?" (a symlink to a
# credentials file must be seen as that file). They used `realpath -m`, a GNU
# option. macOS `realpath` has no -m ("illegal option"), so the call failed and
# the raw path was used: a symlink to ~/.aws/credentials was not recognised. This
# resolves the same way without that option.
#
# gd_realpath PATH
#   Prints PATH made absolute (relative to the current directory), with every
#   symlink resolved and `.` and `..` collapsed. A component that does not exist
#   is kept as is, like `realpath -m`. Uses `realpath -m` when it works and the
#   pure-bash walk below when it does not. A symlink loop (more than 40 links)
#   prints PATH unchanged. Always returns 0.
# gd_realpath_pure PATH
#   The pure-bash walk alone (the tests compare it with `realpath -m`).
#
# Bash 3.2 compatible (stock macOS): no associative arrays, no mapfile, no case
# conversion. Needs only readlink without options. Defines functions, runs nothing.

gd_realpath_pure() {
  local p="$1" resolved rest comp target links=0
  case "$p" in
    /*) resolved=""; rest="${p#/}" ;;
    *) resolved="$(pwd -P)"; resolved="${resolved%/}"; rest="$p" ;;
  esac
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"
    if [ "$comp" = "$rest" ]; then rest=""; else rest="${rest#*/}"; fi
    case "$comp" in
      "" | .) continue ;;
      ..) resolved="${resolved%/*}"; continue ;;
    esac
    if [ -L "$resolved/$comp" ]; then
      links=$((links + 1))
      if [ "$links" -gt 40 ]; then
        printf '%s' "$p"
        return 0
      fi
      target="$(readlink "$resolved/$comp" 2> /dev/null)" || { resolved="$resolved/$comp"; continue; }
      case "$target" in
        /*) resolved=""; rest="${target#/}${rest:+/$rest}" ;;
        *) rest="$target${rest:+/$rest}" ;;
      esac
    else
      resolved="$resolved/$comp"
    fi
  done
  printf '%s' "${resolved:-/}"
  return 0
}

gd_realpath() {
  local p="$1"
  [ -n "$p" ] || return 0
  realpath -m -- "$p" 2> /dev/null && return 0
  gd_realpath_pure "$p"
}
