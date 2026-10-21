# cred-use-strip.awk -- drop the credential a tool only USES from a Bash command line.
#
# Used by credfile-guard.sh before it looks for sensitive paths (issue gramatr/guards-coordination#78).
# The rules are data: cred-use-registry.tsv (columns documented there).
#
#   printf '%s' "$command" | awk -v reg=cred-use-registry.tsv -f cred-use-strip.awk
#
# Prints the command with the used credentials removed (words joined by single spaces; the separators
# | ; & ( ) and backtick are kept). Exit 3 with no output when the registry has no usable row, so the
# caller scans the line as written.
#
# Portable on purpose: POSIX awk only (gawk, mawk, busybox awk, BSD/one-true awk on macOS). No
# interval expressions, no gensub, no \s, no delete of whole arrays. Linear in the line length.

function lower_has_prefix(s, p) {
  return tolower(substr(s, 1, length(p))) == tolower(p)
}

# does the flag token x equal f, or (for a long flag) start with f=
function flag_is(x, f) {
  if (x == f) return 1
  if (substr(f, 1, 2) == "--" && substr(x, 1, length(f) + 1) == f "=") return 1
  return 0
}

# apply row r to the words nm[1..nt] of one simple command, the tool word being at i
function apply_row(r, i, nt,    k, j, c, items, ni, u, fl, pf, p) {
  # subcommand restriction
  if (subs[r] != "-") {
    c = ""
    for (j = i + 1; j <= nt; j++) {
      if (nm[j] != "" && substr(nm[j], 1, 1) != "-") { c = nm[j]; break }
    }
    ni = split(subs[r], items, ",")
    k = 0
    for (j = 1; j <= ni; j++) if (items[j] == c) k = 1
    if (!k) return
  }
  # every needed flag must be present
  if (needs[r] != "-") {
    ni = split(needs[r], items, ",")
    for (u = 1; u <= ni; u++) {
      k = 0
      for (j = i + 1; j <= nt; j++) if (flag_is(nm[j], items[u])) k = 1
      if (!k) return
    }
  }
  # any forbidden flag turns the row off
  if (forbid[r] != "-") {
    ni = split(forbid[r], items, ",")
    for (u = 1; u <= ni; u++) {
      for (j = i + 1; j <= nt; j++) if (flag_is(nm[j], items[u])) return
    }
  }
  ni = split(use[r], items, ",")
  for (u = 1; u <= ni; u++) {
    p = items[u]
    if (p == "@operand") {
      for (j = i + 1; j <= nt; j++) if (nm[j] != "" && substr(nm[j], 1, 1) != "-") rem[j] = 1
    } else if (substr(p, 1, 4) == "env:") {
      fl = substr(p, 5) "="
      for (j = 1; j <= nt; j++) if (substr(nm[j], 1, length(fl)) == fl) rem[j] = 1
    } else if (index(p, ":") > 0) {
      # flag whose next word starts with a given prefix, or the glued form
      fl = substr(p, 1, index(p, ":") - 1)
      pf = substr(p, index(p, ":") + 1)
      for (j = i + 1; j <= nt; j++) {
        if (nm[j] == fl && j < nt && lower_has_prefix(nm[j + 1], pf)) { rem[j] = 1; rem[j + 1] = 1 }
        else if (lower_has_prefix(nm[j], fl pf)) rem[j] = 1
      }
    } else {
      for (j = i + 1; j <= nt; j++) {
        if (nm[j] == p && j < nt) { rem[j] = 1; rem[j + 1] = 1 }
        else if (substr(p, 1, 2) == "--" && substr(nm[j], 1, length(p) + 1) == p "=") rem[j] = 1
      }
    }
  }
}

# strip one simple command
function strip(seg,    nt, t, i, j, x, base, r, out, first, sep) {
  nt = split(seg, t, /[ \t]+/)
  for (i = 1; i <= nt; i++) {
    x = t[i]
    gsub(/^["']+/, "", x)
    gsub(/["']+$/, "", x)
    nm[i] = x
    rem[i] = 0
  }
  for (i = 1; i <= nt; i++) {
    # the tool word may sit after a quote inside a word: core.sshCommand="ssh  GIT_SSH_COMMAND="ssh
    base = t[i]
    sub(/^.*["']/, "", base)
    sub(/.*\//, "", base)
    if (base == "") continue
    for (r = 1; r <= nrows; r++) if (tool[r] == base) apply_row(r, i, nt)
  }
  out = ""
  first = 1
  for (i = 1; i <= nt; i++) {
    if (rem[i] || t[i] == "") continue
    if (first) sep = ""; else sep = " "
    out = out sep t[i]
    first = 0
  }
  return out
}

BEGIN {
  nrows = 0
  while ((getline line < reg) > 0) {
    if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
    if (split(line, f, "\t") < 6) continue
    nrows++
    tool[nrows] = f[1]
    subs[nrows] = f[2]
    use[nrows] = f[3]
    needs[nrows] = f[4]
    forbid[nrows] = f[5]
  }
  close(reg)
  if (nrows == 0) { failed = 1; exit 3 }
}

{
  line = $0
  gsub(/\$\(/, "(", line)
  out = ""
  while (match(line, /[|;&()`]/)) {
    out = out strip(substr(line, 1, RSTART - 1)) substr(line, RSTART, 1)
    line = substr(line, RSTART + 1)
  }
  out = out strip(line)
  print out
}

END { if (failed) exit 3 }
