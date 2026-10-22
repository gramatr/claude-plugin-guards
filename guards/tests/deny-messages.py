#!/usr/bin/env python3
"""Extract every deny, ask and withhold message string from guards/hooks/*.sh.

Used by deny-messages.test.sh (coordination#100) and by docs-consistency to keep the prefix table
in docs/AGENTS-GUIDE.md equal to what the hooks actually print.

A message is the double-quoted shell string that follows one of these starts:
  deny "...   emit_pre deny "...   emit deny "...   emit_pre ask "...   emit ask "...
  DENY_MSG="...   DENY_MSG+="...   ASK_MSG="...   LIT_MSG="...
  msg="guards ...   (the withhold notices; only when the string starts with "guards " or "Blocked by guards")
The scanner understands backslash escapes and $(...) command substitutions with quotes inside them.
It reads source text only; nothing is executed.
"""

import re
import sys
from pathlib import Path

START = re.compile(
    r"(?:\bemit_pre\s+(?:deny|ask)\s+|\bemit\s+(?:deny|ask)\s+|(?<![A-Za-z_])deny\s+|\bnote_deny\s+"
    r'|\b(?:DENY_MSG|ASK_MSG|LIT_MSG)\+?=|\b(?:ASK_MSG|DENY_MSG)="\$LIT_MSG"\s*;;|\bmsg=)"'
)


def read_string(src: str, i: int):
    """src[i] is the opening quote. Return (text, index after the closing quote) or None."""
    j = i + 1
    depth = 0
    inner = None  # quote char while inside a quoted string within $( ... )
    out = []
    while j < len(src):
        c = src[j]
        if c == "\\" and j + 1 < len(src):
            out.append(src[j : j + 2])
            j += 2
            continue
        if depth == 0:
            if c == '"':
                return "".join(out), j + 1
            if c == "$" and src[j + 1 : j + 2] == "(":
                depth = 1
                out.append("$(")
                j += 2
                continue
        else:
            if inner:
                if c == inner:
                    inner = None
            elif c in "\"'":
                inner = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
        out.append(c)
        j += 1
    return None


def messages(path: Path):
    src = path.read_text()
    found = []
    for m in START.finditer(src):
        q = m.end() - 1
        # skip commented lines
        ls = src.rfind("\n", 0, m.start()) + 1
        if src[ls : m.start()].lstrip().startswith("#"):
            continue
        r = read_string(src, q)
        if r is None:
            continue
        text, _ = r
        line = src.count("\n", 0, q) + 1
        is_msg_var = src[m.start() : m.start() + 4] == "msg="
        if is_msg_var and not re.match(r"guards |Blocked by guards ", text):
            continue
        found.append((line, text))
    return found


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "guards/hooks")
    for p in sorted(root.glob("*.sh")):
        for line, text in messages(p):
            print(f"{p.name}:{line}\t{text.replace(chr(10), ' / ')}")


if __name__ == "__main__":
    main()
