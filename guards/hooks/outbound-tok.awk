# outbound-tok.awk -- command-text tokenizer for the outbound command guard (#49, U2).
# POSIX awk only: no gawk extensions, no regex interval expressions ({n,m}: mawk
# lacks them), and no "word (expr)" (one-true-awk reads it as a function call).
# outbound-lib.sh runs it; see guards/tests/outbound-parse.test.sh.
#
# Reads ONE shell command (whole input, RS=\001), tokenises it with shell quoting
# rules, finds outbound-client invocations and prints VALUE-FREE records, tab
# separated:
#   C <client>                    a client invocation was found
#   F <client> <flag> <path>      a file operand that will be read and sent
#   S <client> <kind> <arg>       stdin / pipe / substitution source: kind =
#                                 envdump|envdump-filtered|pipearg|redir|subst|stdin-op
#   L <client> <class> <flag>     a literal-credential candidate in the command text
#                                 (class sure|ambig); names the FLAG, never the value
#   U <client> <what>             an operand the parser knows it cannot resolve
#   X <what>                      parser gave up (depth cap, size cap, unbalanced quoting)
# Only PATHS ever appear on F/S lines, never header, body or token text: an operand
# that looks like a credential is reported as an L record instead, and control
# characters are stripped so a path cannot forge a record.

BEGIN {
  RS = "\001"
  split("curl wget http https xh nc ncat netcat scp rsync sftp ssh ftp telnet socat", _c, " ")
  for (i in _c) CLIENT[_c[i]] = 1
  split("env printenv set export declare typeset", _e, " ")
  for (i in _e) ENVDUMP[_e[i]] = 1
  split("sudo doas env command builtin exec nohup nice time timeout stdbuf setsid ionice xargs watch", _w, " ")
  for (i in _w) WRAP[_w[i]] = 1
  split("bash sh dash zsh ksh", _s, " ")
  for (i in _s) SHELL[_s[i]] = 1
  split("if then else elif fi do done while until for case esac { } ! time", _k, " ")
  for (i in _k) KW[_k[i]] = 1
  MAXLEN = 8192; MAXDEPTH = 3
  # curl short options that take an argument; long options that take an argument
  split("A b c C d D e E F H K m o P Q r t T u U w x X y Y z", _a, " ")
  for (i in _a) CSHORT[_a[i]] = 1
  split("data data-ascii data-binary data-raw data-urlencode form form-string upload-file header user oauth2-bearer cookie cookie-jar config proxy-user proxy-header request output write-out url url-query json cert key pass cacert capath netrc-file referer user-agent connect-timeout max-time proxy resolve interface tlspassword tlsuser ftp-account login-options aws-sigv4 dump-header trace trace-ascii limit-rate retry range", _l, " ")
  for (i in _l) CLONG[_l[i]] = 1
  split("e i O o a P t T w Q l A R D X I B U", _ws, " ")
  for (i in _ws) WSHORT[_ws[i]] = 1
  NSEG = 0
  nsure = split("ghp_[A-Za-z0-9]+:24 gho_[A-Za-z0-9]+:24 github_pat_[A-Za-z0-9_]+:30 AKIA[A-Z0-9]+:20 ASIA[A-Z0-9]+:20 xox[abprs]-[A-Za-z0-9-]+:14 sk-[A-Za-z0-9_-]+:23 glpat-[A-Za-z0-9_-]+:22 AIza[A-Za-z0-9_-]+:34 eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+:30", SURELIST, " ")
}

{ if (length($0) > MAXLEN) { print "X\tsize-cap"; exit } ; run($0, 0) }

function base(w,   t) { t = w; sub(/^\\/, "", t); sub(/.*\//, "", t); return t }
function isassign(w) { return (w ~ /^[A-Za-z_][A-Za-z0-9_]*=/) }

# ---------------------------------------------------------------- lexer
function endword() {
  if (!inw) return
  K = ++sn[SEG]
  tx[SEG, K] = W; ex[SEG, K] = EX; ty[SEG, K] = NEXTTY
  if (NEXTTY == "H") { hd_delim[++NHD] = W; hd_seg[NHD] = SEG; hd_strip[NHD] = HDSTRIP }
  NEXTTY = "W"; W = ""; inw = 0; EX = 0
}
function addop(o) {   # redirect operator token
  endword()
  K = ++sn[SEG]; tx[SEG, K] = o; ty[SEG, K] = "R"; ex[SEG, K] = 0
  NEXTTY = "T"
  if (o == "<<" || o == "<<-") { NEXTTY = "H"; HDSTRIP = (o == "<<-") }
}
function endseg(o) {
  endword(); NEXTTY = "W"
  SEG = ++NSEG; sn[SEG] = 0; opb[SEG] = o
}
function pushsub(s) { NSUB[SEG]++; SUBS[SEG, NSUB[SEG]] = s }
# balanced capture: s at position p points just after an opening "(" ; returns inner text, sets CAPEND
function capparen(s, p,   d, n, ch, q) {
  d = 1; n = length(s); q = ""
  for (CAPEND = p; CAPEND <= n; CAPEND++) {
    ch = substr(s, CAPEND, 1)
    if (q != "") { if (ch == "\\" && q == "\"") CAPEND++; else if (ch == q) q = ""; continue }
    if (ch == "\\") { CAPEND++; continue }
    if (ch == "'" || ch == "\"") { q = ch; continue }
    if (ch == "(") d++
    else if (ch == ")") { d--; if (d == 0) return substr(s, p, CAPEND - p) }
  }
  CAPEND = n + 1; GAVEUP = 1
  return substr(s, p)
}
function ansic(s, p,   n, ch, out, hx, v) {   # $'...' body from p; sets CAPEND after closing '
  n = length(s); out = ""
  for (CAPEND = p; CAPEND <= n; CAPEND++) {
    ch = substr(s, CAPEND, 1)
    if (ch == "'") { CAPEND++; return out }
    if (ch == "\\") {
      CAPEND++; ch = substr(s, CAPEND, 1)
      if (ch == "n") out = out "\n"; else if (ch == "t") out = out "\t"
      else if (ch == "x") { hx = tolower(substr(s, CAPEND + 1, 2)); v = index("0123456789abcdef", substr(hx, 1, 1)) - 1; v = v * 16 + index("0123456789abcdef", substr(hx, 2, 1)) - 1; out = out sprintf("%c", v); CAPEND += 2 }
      else if (ch ~ /[0-7]/) { hx = substr(s, CAPEND, 3); v = 0; for (j = 1; j <= length(hx) && substr(hx, j, 1) ~ /[0-7]/; j++) v = v * 8 + substr(hx, j, 1); out = out sprintf("%c", v); CAPEND += j - 2 }
      else out = out ch
      continue
    }
    out = out ch
  }
  GAVEUP = 1
  return out
}
function lex(s,   n, i, c, nx, j, k, inner, ch, d, fd) {
  n = length(s); i = 1; W = ""; inw = 0; EX = 0; NEXTTY = "W"
  SEG = ++NSEG; sn[SEG] = 0; opb[SEG] = ""; LFIRST = SEG
  NHD = 0; LEXID++
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "\\") {
      nx = substr(s, i + 1, 1)
      if (nx == "\n") { i += 2; continue }
      W = W nx; inw = 1; i += 2; continue
    }
    if (c == "'") {
      j = index(substr(s, i + 1), "'")
      if (j == 0) { W = W substr(s, i + 1); inw = 1; GAVEUP = 1; i = n + 1; continue }
      W = W substr(s, i + 1, j - 1); inw = 1; i += j + 1; continue
    }
    if (c == "\"") {
      inw = 1; k = i + 1
      while (k <= n) {
        ch = substr(s, k, 1)
        if (ch == "\\") { nx = substr(s, k + 1, 1); if (nx ~ /[$`"\\]/) W = W nx; else if (nx != "\n") W = W ch nx; k += 2; continue }
        if (ch == "\"") break
        if (ch == "$" && substr(s, k + 1, 1) == "(") {
          inner = capparen(s, k + 2); W = W "$(" inner ")"; EX = 1; pushsub(inner); k = CAPEND + 1; continue
        }
        if (ch == "$") { W = W ch; EX = 1; k++; continue }
        if (ch == "`") {
          j = index(substr(s, k + 1), "`"); if (j == 0) { GAVEUP = 1; W = W substr(s, k); k = n + 1; break }
          inner = substr(s, k + 1, j - 1); W = W "`" inner "`"; EX = 1; pushsub(inner); k += j + 1; continue
        }
        W = W ch; k++
      }
      if (k > n) GAVEUP = 1
      i = k + 1; continue
    }
    if (c == "$") {
      nx = substr(s, i + 1, 1)
      if (nx == "'") { W = W ansic(s, i + 2); inw = 1; i = CAPEND; continue }
      if (nx == "(") {
        if (substr(s, i + 2, 1) == "(") { inner = capparen(s, i + 3); W = W "$((" inner ")"; EX = 1; inw = 1; i = CAPEND + 2; continue }
        inner = capparen(s, i + 2); W = W "$(" inner ")"; EX = 1; inw = 1; pushsub(inner); i = CAPEND + 1; continue
      }
      if (nx == "{") { j = index(substr(s, i + 2), "}"); if (j == 0) { GAVEUP = 1; W = W substr(s, i); i = n + 1; inw = 1; continue } W = W substr(s, i, j + 2); EX = 1; inw = 1; i += j + 2; continue }
      W = W c; EX = 1; inw = 1; i++; continue
    }
    if (c == "`") {
      j = index(substr(s, i + 1), "`"); if (j == 0) { GAVEUP = 1; W = W substr(s, i); i = n + 1; inw = 1; continue }
      inner = substr(s, i + 1, j - 1); W = W "`" inner "`"; EX = 1; inw = 1; pushsub(inner); i += j + 1; continue
    }
    if (c == " " || c == "\t" || c == "\r") { endword(); i++; continue }
    if (c == "\n") {
      endword()
      for (k = 1; k <= NHD; k++) {   # read pending here-document bodies
        if (hd_done[LEXID, k]) continue
        body = ""; i++
        while (i <= n) {
          j = index(substr(s, i), "\n"); if (j == 0) { line = substr(s, i); i = n + 1 } else { line = substr(s, i, j - 1); i += j }
          chk = line; if (hd_strip[k]) sub(/^\t+/, "", chk)
          if (chk == hd_delim[k]) break
          body = body line "\n"
        }
        HB[hd_seg[k]] = HB[hd_seg[k]] body; hd_done[LEXID, k] = 1; i--   # i-- : loop adds 1 below
      }
      endseg("\n"); i++; continue
    }
    if (c == ";") { endseg(";"); i++; if (substr(s, i, 1) == ";") i++; continue }
    if (c == "&") {
      nx = substr(s, i + 1, 1)
      if (nx == "&") { endseg("&&"); i += 2; continue }
      if (nx == ">") { addop("&>"); i += 2; continue }
      endseg("&"); i++; continue
    }
    if (c == "|") {
      nx = substr(s, i + 1, 1)
      if (nx == "|") { endseg("||"); i += 2; continue }
      if (nx == "&") { endseg("|"); i += 2; continue }
      endseg("|"); i++; continue
    }
    if (c == "(" || c == ")" ) { endseg(c); i++; continue }
    if (c == "<" || c == ">") {
      nx = substr(s, i + 1, 1)
      if (inw && W ~ /^[0-9]+$/) { W = ""; inw = 0 }   # fd prefix
      if (nx == "(") { inner = capparen(s, i + 2); endword(); W = c "(" inner ")"; inw = 1; EX = 1; pushsub(inner); i = CAPEND + 1; endword(); continue }
      if (c == "<" && nx == "<" && substr(s, i + 2, 1) == "<") { addop("<<<"); i += 3; continue }
      if (c == "<" && nx == "<" && substr(s, i + 2, 1) == "-") { addop("<<-"); i += 3; continue }
      if (c == "<" && nx == "<") { addop("<<"); i += 2; continue }
      if (c == ">" && nx == ">") { addop(">>"); i += 2; continue }
      if (c == ">" && (nx == "&" || nx == "|")) { addop(">" nx); i += 2; continue }
      if (c == "<" && nx == ">") { addop("<>"); i += 2; continue }
      addop(c); i++; continue
    }
    W = W c; inw = 1; i++
  }
  endword()
  LLAST = SEG
}

# ---------------------------------------------------------------- policy
function run(s, depth,   f, l, i, k2) {
  if (depth > MAXDEPTH) { print "X\tdepth-cap"; return }
  GAVEUP = 0
  lex(s)
  f = LFIRST; l = LLAST
  if (GAVEUP) print "X\tunbalanced-quoting"
  for (i = f; i <= l; i++) {
    proc(i, f, depth)
    for (k2 = 1; k2 <= NSUB[i]; k2++) run(SUBS[i, k2], depth + 1)   # a client inside $( ), backticks or <( )
  }
}

# literal credential candidate in text TXT (already known not to contain an expansion)
function issure(txt,   i, parts, np) {
  for (i = 1; i <= nsure; i++) {
    np = split(SURELIST[i], parts, ":")
    if (match(txt, parts[1]) && RLENGTH >= parts[2] + 0) return 1
  }
  return 0
}
function lit(client, flag, txt, hdr,   cls) {
  if (txt == "") return
  cls = ""
  if (txt ~ /-----BEGIN [A-Z ]*PRIVATE KEY/) cls = "sure"
  else if (issure(txt)) cls = "sure"
  else if (hdr && txt ~ /^[ ]*(([Pp]roxy-)?[Aa]uthorization|[Xx]-[A-Za-z-]*([Tt]oken|[Kk]ey|[Ss]ecret)|[Cc]ookie)[ ]*:[ ]*[^ ]+/ && txt !~ /:[ ]*(Bearer|Basic|Token)?[ ]*$/) cls = "ambig"
  else if (!hdr && txt ~ /(^|[&?;, {"'])[A-Za-z0-9_.-]*([Pp]assw(or)?d|[Pp]wd|[Ss]ecret|[Tt]oken|[Aa]pi[_-]?[Kk]ey|[Cc]redential)[A-Za-z0-9_.-]*["']?[=:][ ]*["']?[^ "'&$][^ "'&][^ "'&][^ "'&][^ "'&][^ "'&]+/) cls = "ambig"
  if (cls != "") print "L\t" client "\t" cls "\t" flag
}
function litopt(client, flag, v,   cls) {   # a value-taking credential option (--oauth2-bearer, --password)
  cls = "ambig"
  if (issure(v)) cls = "sure"
  print "L\t" client "\t" cls "\t--" flag
}
function lituser(client, flag, v, e) {   # user:password operand
  if (e) return
  if (v ~ /^[^:]+:.+/) {
    if (issure(v)) print "L\t" client "\tsure\t" flag
    else print "L\t" client "\tambig\t" flag
  }
}
function urlcheck(client, v, e) {
  if (v ~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/@:]+:[^\/@]+@/ && !(e && v ~ /:\/\/[^\/@:]+:\$[^\/@]*@/)) print "L\t" client "\tambig\turl-userinfo"
  if (v ~ /[?&](access_token|token|api_key|apikey|key|secret|password|sig|signature|X-Amz-Signature|X-Amz-Security-Token)=[^&$][^&$][^&$][^&$][^&$][^&$][^&$][^&$]+/) print "L\t" client "\tambig\turl-query"
}
# clean(s): strip control characters so an operand can never forge a record.
function clean(s) { gsub(/[\001-\037\177]/, " ", s); return s }
# emitsrc(client, kind, arg, pathonly): an S record for a stdin/pipe/substitution operand.
# A credential-shaped operand becomes an L record (it is a literal, not a path); with
# pathonly unset, an operand that does not look like a path (no dot, tilde or slash, or
# an assignment) is dropped, because it is data (echo word) not a file name.
function emitsrc(client, kind, a, pathonly) {
  if (a == "") return
  if (issure(a)) { print "L\t" client "\tsure\t" kind "-literal"; return }
  if (!pathonly && (a !~ "[.~/]" || a ~ "[=:]")) return
  print "S\t" client "\t" kind "\t" clean(a)
}
function filearg(client, flag, p, e) {
  if (p == "" ) return
  if (issure(p)) { print "L\t" client "\tsure\t" flag; return }
  if (p == "-" ) { print "S\t" client "\tstdin-op\t-"; return }
  if (e && p ~ /\$|`/ && p !~ /^(\$HOME|\$\{HOME\})(\/|$)/) { print "U\t" client "\tvariable-path"; return }
  print "F\t" client "\t" flag "\t" clean(p)
}

function stdin_sources(sid, f, client,   p, j, k, cb, a, t, base0, hb) {
  # redirects on the client segment itself
  for (k = 1; k <= sn[sid]; k++) {
    if (ty[sid, k] == "R" && (tx[sid, k] == "<" || tx[sid, k] == "<>")) filearg(client, "stdin", tx[sid, k + 1], ex[sid, k + 1])
    if (ty[sid, k] == "R" && tx[sid, k] == "<<<") { if (!ex[sid, k + 1]) lit(client, "here-string", tx[sid, k + 1], 0) }
  }
  if (HB[sid] != "") { t = HB[sid]; gsub(/\n/, " ", t); lit(client, "here-doc", t, 0) }
  # pipeline predecessors
  p = sid; filtered = 0
  while (p - 1 >= f && opb[p] == "|") {
    p--
    cb = cmdword(p)
    base0 = base(CW)
    if (base0 in ENVDUMP) {
      # no-argument env/printenv/set/export, or only options (export -p, declare -x): the whole environment
      dump = 1; for (j = 1; j <= CWN; j++) if (CA[j] !~ /^-/) dump = 0
      if (dump) {
        kd = "\tenvdump\t"
        if (filtered) kd = "\tenvdump-filtered\t"
        print "S\t" client kd base0
      }
    } else if (base0 ~ /^(grep|egrep|fgrep|awk|gawk|sed|cut|jq|head|tail|sort|tr|wc|uniq|rg)$/) filtered = 1
    for (j = 1; j <= CWN; j++) {
      if (CA[j] ~ /^-/) continue
      if (ex[p, CAIDX[j]] && CA[j] ~ /\$|`/ ) { if (CA[j] !~ /^(\$HOME|\$\{HOME\})(\/|$)/) continue }
      emitsrc(client, "pipearg", CA[j], 0)
    }
    for (k = 1; k <= sn[p]; k++) if (ty[p, k] == "R" && tx[p, k] == "<") emitsrc(client, "redir", tx[p, k + 1], 1)
  }
  # command substitutions inside this segment's words
  for (k = 1; k <= NSUB[sid]; k++) subst_sources(client, SUBS[sid, k], 0)
}
function subst_sources(client, text, d,   f0, l0, i, c0, b0, j) {
  if (d > 2) return
  lex(text); f0 = LFIRST; l0 = LLAST
  for (i = f0; i <= l0; i++) {
    c0 = cmdword(i); b0 = base(CW)
    if (b0 in ENVDUMP) { dump = 1; for (j = 1; j <= CWN; j++) if (CA[j] !~ /^-/) dump = 0; if (dump) print "S\t" client "\tenvdump\t" b0 }
    for (j = 1; j <= CWN; j++) {
      if (CA[j] ~ /^-/) continue
      if (ex[i, CAIDX[j]] && CA[j] ~ /\$|`/ && CA[j] !~ /^(\$HOME|\$\{HOME\})(\/|$)/) continue
      emitsrc(client, "subst", CA[j], 0)
    }
    for (j = 1; j <= sn[i]; j++) if (ty[i, j] == "R" && tx[i, j] == "<") emitsrc(client, "subst", tx[i, j + 1], 1)
  }
}

# cmdword(sid): sets CW (command word), CA[1..CWN] (non-redirect args after it), CAIDX[j]=token index. Returns 1 if found.
function cmdword(sid,   k, m, w, b, skip, idx) {
  CW = ""; CWN = 0; lastwrap = ""
  m = 0
  for (k = 1; k <= sn[sid]; k++) {
    if (ty[sid, k] == "R") { k++; continue }      # skip redirect and its target
    if (ty[sid, k] != "W") continue
    m++; TW[m] = tx[sid, k]; TI[m] = k
  }
  idx = 1
  while (idx <= m) {
    w = TW[idx]; b = base(w)
    if (isassign(w) || (b in KW)) { idx++; continue }
    if (b in WRAP && b != "xargs") {
      lastwrap = b; idx++
      # skip options of the wrapper; value-taking ones for common wrappers
      while (idx <= m && TW[idx] ~ /^-/) {
        if (b == "sudo" && TW[idx] ~ /^-[ugCphTrtD]$/) idx++
        if (b == "env" && TW[idx] ~ /^-[uSC]$/) idx++
        if (b == "nice" && TW[idx] == "-n") idx++
        if (b == "ionice" && TW[idx] ~ /^-[cnp]$/) idx++
        if (b == "timeout" && TW[idx] ~ /^-[ks]$/) idx++
        idx++
      }
      if (b == "timeout") idx++                      # DURATION
      if (b == "nice" && TW[idx] ~ /^[0-9]+$/) idx++
      while (idx <= m && isassign(TW[idx])) idx++    # env VAR=1 cmd
      continue
    }
    if (b == "xargs") {
      idx++
      while (idx <= m && TW[idx] ~ /^-/) { if (TW[idx] ~ /^-[IniPdLEsa]$/) idx++; idx++ }
      continue
    }
    break
  }
  if (idx > m) { if (lastwrap == "env") { CW = "env"; return 1 } ; return 0 }
  CW = TW[idx]
  for (k = idx + 1; k <= m; k++) { CWN++; CA[CWN] = TW[k]; CAIDX[CWN] = TI[k] }
  return 1
}

function proc(sid, f, depth,   cb, b, client, j, a, v, e, nxt, ch, opt, rest, rv, i2, c2) {
  if (!cmdword(sid)) return
  b = base(CW)
  # shells and eval: recurse on the script string
  if (b in SHELL) {
    for (j = 1; j <= CWN; j++) if (CA[j] ~ /^-[A-Za-z]*c[A-Za-z]*$/ && j < CWN) { run(CA[j + 1], depth + 1); return }
    return
  }
  if (b == "eval") { rest = ""; for (j = 1; j <= CWN; j++) rest = rest " " CA[j]; run(rest, depth + 1); return }
  if (!(b in CLIENT)) return
  client = b
  print "C\t" client
  # snapshot args (stdin_sources reuses CA)
  n = CWN; for (j = 1; j <= n; j++) { AR[j] = CA[j]; AI[j] = CAIDX[j] }
  stdin_sources(sid, f, client)
  if (client == "curl") curl_args(sid, n)
  else if (client == "wget") wget_args(sid, n)
  else if (client == "http" || client == "https" || client == "xh") httpie_args(sid, n)
  else if (client == "scp" || client == "rsync" || client == "sftp") copy_args(sid, n, client)
  else generic_args(sid, n, client)
}

function curl_opt(sid, flag, v, e, client) {
  if (flag ~ /^(d|data|data-ascii|data-binary|json)$/) {
    if (substr(v, 1, 1) == "@") filearg("curl", "--" flag, substr(v, 2), e)
    else if (!e) lit("curl", "--" flag, v, 0)
  } else if (flag == "data-raw") { if (!e) lit("curl", "--data-raw", v, 0) }
  else if (flag == "data-urlencode") {
    if (v ~ /^[^=@]*@/) { sub(/^[^=@]*@/, "", v); filearg("curl", "--data-urlencode", v, e) }
    else if (!e) lit("curl", "--data-urlencode", v, 0)
  } else if (flag ~ /^(F|form)$/) {
    if (v ~ /=[@<]/) { sub(/^[^=]*=[@<]/, "", v); sub(/;.*/, "", v); filearg("curl", "--form", v, e) }
    else if (!e) lit("curl", "--form", v, 0)
  } else if (flag ~ /^(T|upload-file)$/) {
    filearg("curl", "--upload-file", v, e)
  } else if (flag ~ /^(H|header|proxy-header)$/) {
    if (substr(v, 1, 1) == "@") filearg("curl", "--header", substr(v, 2), e)
    else if (!e) lit("curl", "--header", v, 1)
  } else if (flag ~ /^(u|user|U|proxy-user)$/) { lituser("curl", "--user", v, e) }
  else if (flag ~ /^(oauth2-bearer|pass|tlspassword)$/) { if (!e && v != "") litopt("curl", flag, v) }
  else if (flag ~ /^(b|cookie)$/) { if (v ~ /=/ && !e) lit("curl", "--cookie", "Cookie: " v, 1) }
}
function curl_args(sid, n,   j, a, flag, v, e, k, ch, hasv, rest, ci) {
  for (j = 1; j <= n; j++) {
    a = AR[j]; e = ex[sid, AI[j]]
    if (a ~ /^--[A-Za-z]/) {
      flag = substr(a, 3)
      if (flag in CLONG) { j++; v = AR[j]; e = ex[sid, AI[j]]; curl_opt(sid, flag, v, e) }
      continue
    }
    if (a ~ /^-[A-Za-z0-9]/) {
      for (k = 2; k <= length(a); k++) {
        ch = substr(a, k, 1)
        if (ch in CSHORT) {
          rest = substr(a, k + 1)
          if (rest != "") { v = rest; e = ex[sid, AI[j]] } else { j++; v = AR[j]; e = ex[sid, AI[j]] }
          curl_opt(sid, ch, v, e)
          break
        }
      }
      continue
    }
    urlcheck("curl", a, e)
  }
}
function wget_opt(sid, flag, v, e) {
  if (flag ~ /^(post-file|body-file)$/) filearg("wget", "--" flag, v, e)
  else if (flag ~ /^(post-data|body-data)$/) { if (!e) lit("wget", "--" flag, v, 0) }
  else if (flag == "header") { if (!e) lit("wget", "--header", v, 1) }
  else if (flag ~ /^(password|http-password|ftp-password|proxy-password)$/) { if (!e && v != "") litopt("wget", flag, v) }
  else if (flag ~ /^(e|execute)$/) { if (!e && v ~ /^[ ]*header[ ]*=/) { sub(/^[ ]*header[ ]*=/, "", v); lit("wget", "--execute", v, 1) } }
}
function wget_args(sid, n,   j, a, flag, v, e, eq, k, ch, rest) {
  for (j = 1; j <= n; j++) {
    a = AR[j]; e = ex[sid, AI[j]]
    if (a ~ /^--[A-Za-z]/) {
      flag = substr(a, 3); eq = index(flag, "=")
      if (eq) { v = substr(flag, eq + 1); flag = substr(flag, 1, eq - 1); wget_opt(sid, flag, v, e) }
      else if (flag ~ /^(post-file|body-file|post-data|body-data|header|password|http-password|ftp-password|proxy-password|user|http-user|execute|config|input-file|load-cookies|output-document|method|certificate|private-key|ca-certificate|output-file|append-output|directory-prefix|user-agent|referer|bind-address|ftp-user|proxy-user)$/) { j++; wget_opt(sid, flag, AR[j], ex[sid, AI[j]]) }
      continue
    }
    if (a ~ /^-[A-Za-z0-9]/) {
      for (k = 2; k <= length(a); k++) {
        ch = substr(a, k, 1)
        if (ch in WSHORT) { rest = substr(a, k + 1); if (rest != "") v = rest; else { j++; v = AR[j] } ; wget_opt(sid, ch, v, e); break }
      }
      continue
    }
    urlcheck("wget", a, e)
  }
}
function httpie_args(sid, n,   j, a, e, v, cl) {
  for (j = 1; j <= n; j++) {
    a = AR[j]; e = ex[sid, AI[j]]
    if (a ~ /^(-a|--auth)$/) { j++; lituser("http", "--auth", AR[j], ex[sid, AI[j]]); continue }
    if (a ~ /^--auth=/) { v = a; sub(/^--auth=/, "", v); lituser("http", "--auth", v, e); continue }
    if (a ~ /^-/) continue
    if (a ~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\//) { urlcheck("http", a, e); continue }
    if (a ~ /^[^=:@]+(=|:=)@/) { v = a; sub(/^[^=:@]+(=|:=)@/, "", v); filearg("http", "field=@", v, e); continue }
    if (a ~ /^[^=:@]+@[^=]/) { v = a; sub(/^[^=:@]+@/, "", v); filearg("http", "field@", v, e); continue }
    if (!e && a ~ /^[Aa]uthorization:./) lit("http", "header", a, 1)
    else if (!e && a ~ /^[^=:]+==?.+/) lit("http", "field", a, 0)
  }
}
function is_remote(w) { return (w ~ /^([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:([^\/]|\/([^\/]|$))/ || w ~ /^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:/ || w ~ /^(scp|sftp|rsync|ssh):\/\//) }
function copy_args(sid, n, client,   j, a, np, dest_remote, pos) {
  np = 0
  for (j = 1; j <= n; j++) { a = AR[j]; if (a ~ /^-/) { if (a ~ /^-[eiFoJlPcSBLfT]$/ && AR[j] != "") j++; continue } np++; PA[np] = a; PE[np] = ex[sid, AI[j]] }
  if (np < 2) return
  if (!is_remote(PA[np]) && client != "sftp") return    # download direction: nothing local is sent
  for (j = 1; j < np; j++) { if (is_remote(PA[j])) continue; filearg(client, "source", PA[j], PE[j]) }
}
function generic_args(sid, n, client,   j, a) {
  # nc/ncat/telnet/ssh/ftp/socat: only stdin carries data (handled in stdin_sources). Literal creds in args:
  for (j = 1; j <= n; j++) { a = AR[j]; if (!ex[sid, AI[j]]) urlcheck(client, a, 0) }
  if (client == "ssh" || client == "ncat" || client == "nc" || client == "netcat") {
    for (j = 1; j < n; j++) if (AR[j] == "-P" && !ex[sid, AI[j + 1]]) print "L\t" client "\tambig\t-P"
  }
}
