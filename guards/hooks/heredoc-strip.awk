# heredoc-strip.awk -- drop the body of a heredoc that only WRITES data (issue gramatr/guards-coordination#98).
#
# Used by credfile-guard.sh before it looks for sensitive paths. A heredoc that feeds a data sink
# (`cat > file <<EOF`, `cat >> file <<'EOF'`, `tee file <<EOF`) carries text, not a read, so a
# credential path named in that text must not count. A heredoc that feeds anything else keeps its body:
# `python3 - <<EOF`, `bash <<EOF`, `sed ... <<EOF` and the like can open the key, and `cat KEY <<EOF`
# keeps the key path on the command line itself, which is not part of the body.
#
#   printf '%s' "$command" | awk -f heredoc-strip.awk
#
# Prints the command with the stripped bodies (and their terminator lines) removed. The line that
# starts the heredoc is always kept. Unsure means keep: an unterminated heredoc, a delimiter that
# cannot be read, a line with a pipe into another command, or an interpreter word anywhere on the
# line all leave the body in place, so the fallback only ever scans more, never less.
#
# Portable on purpose: POSIX awk only (gawk, mawk, busybox awk, BSD/one-true awk on macOS). No
# interval expressions, no gensub, no \s. Linear in the command length.

# does the line look like a data sink? Called with the line padded by a space on both sides.
function is_sink(s,    t) {
  t = " " s " "
  # an interpreter or a shell anywhere on the line: the body may be run or read
  if (t ~ /[ \t;&|(`$=](python[0-9.]*|perl|ruby|node|nodejs|deno|bun|php|lua|Rscript|osascript|bash|sh|zsh|dash|ksh|fish|awk|gawk|mawk|sed|ed|ex|vi|vim|eval|source|xargs|sudo|env|exec|nice|timeout|ssh|docker|kubectl)[ \t;&|)`]/) return 0
  # a pipe: the heredoc text may be piped into a reader, so keep it
  if (t ~ /\|/) return 0
  # tee writes its standard input to files
  if (t ~ /[ \t;&(]tee[ \t]/) return 1
  # cat with an output redirect (> or >>, but not a here-string or an input redirect)
  if (t ~ /[ \t;&(]cat[ \t]/ && t ~ /[^<&0-9]>>?[ \t]*[^ \t&>]/) return 1
  return 0
}

# the heredoc delimiter on this line, or "" when there is none (a here-string <<< does not count)
function delim_of(s,    off, i, r, q, d) {
  off = 0
  r = s
  while ((i = index(r, "<<")) > 0) {
    if (substr(r, i + 2, 1) == "<") { r = substr(r, i + 3); continue }
    r = substr(r, i + 2)
    break
  }
  if (i == 0) return ""
  dash = 0
  if (substr(r, 1, 1) == "-") { r = substr(r, 2); dash = 1 }
  sub(/^[ \t]+/, "", r)
  q = substr(r, 1, 1)
  if (q == "'" || q == "\"") {
    r = substr(r, 2)
    if (index(r, q) == 0) return ""
    d = substr(r, 1, index(r, q) - 1)
  } else {
    d = r
    sub(/[ \t;&|()<>].*$/, "", d)
  }
  return d
}

BEGIN { inh = 0; dash = 0; ORS = "\n" }

{
  if (inh) {
    line = $0
    cmp = line
    if (dash) sub(/^\t+/, "", cmp)
    if (cmp == term) { inh = 0; if (!strip) print line; next }
    if (!strip) print line
    next
  }
  print $0
  if (index($0, "<<") > 0) {
    d = delim_of($0)
    if (d != "") { inh = 1; term = d; strip = is_sink($0); pend = $0 }
  }
}

# an unterminated heredoc that was being stripped: the body is already gone and cannot be put back,
# so tell the caller to fall back to the line as written
END { if (inh && strip) exit 3 }
