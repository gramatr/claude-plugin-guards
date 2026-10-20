"""
guards/mcp/guards_tools.py — tools and prompts that let a coding agent work
WITH the guards instead of against them (registered by server.py).

Every tool is value-free: it never returns a raw matched credential value.
Text that came from a user's file or command is returned only after the
vendored scanner (vendor/secret-guard-core/scan.sh) has redacted it, and a
final backstop (`_value_free`) re-scans every string of every result.

There is deliberately NO tool here that disables, bypasses or weakens a
guard. The overrides (GUARDS_ALLOW_PUBLISH_SECRETS, GUARDS_ALLOW_CRED_READ,
...) belong to the person who starts Claude Code; `guards_status` only
REPORTS when one is set.

Pure functions apart from the subprocess/file/HTTP calls they name, so the
tests exercise them directly with temp files and a stubbed `httpx`.
"""

import functools
import json
import math
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(HERE)  # the `guards/` directory
HOOKS_DIR = os.path.join(PLUGIN_ROOT, "hooks")
SCAN_SH = os.path.join(PLUGIN_ROOT, "vendor", "secret-guard-core", "scan.sh")

MARKER = "guards:synthetic"
WITHHELD = "***REDACTED:SECRET*** (withheld by guards tools: could not be checked)"
SEP = "\n@@guards-tools-sep@@\n"
MAX_TEXT = 512 * 1024
MAX_FILE = 2 * 1024 * 1024


def _state_dir() -> str:
    """Where the tools keep what they write (0700), next to the self-heal state."""
    d = os.environ.get("GUARDS_STATE_DIR") or os.path.join(
        os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
        "gramatr-guards",
    )
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _state_file(sub: str, prefix: str, suffix: str) -> str:
    d = os.path.join(_state_dir(), sub)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, path = tempfile.mkstemp(
        prefix=f"{prefix}-{time.strftime('%Y%m%dT%H%M%S')}-", suffix=suffix, dir=d
    )
    os.close(fd)  # mkstemp creates it 0600
    return path


# ---------------------------------------------------------------- scanner ---


def _scan(text: str, timeout: int = 60) -> dict:
    """Run the vendored scan.sh. Returns {ok, redacted, rules, lines}; lines are
    1-based numbers of lines the scanner changed. Never raises."""
    if not os.path.isfile(SCAN_SH):
        return {"ok": False, "redacted": WITHHELD, "rules": [], "lines": []}
    env = dict(os.environ)
    env.pop("SECRET_GUARD_FINDINGS_JSON", None)
    try:
        p = subprocess.run(
            ["bash", SCAN_SH],
            input=text.encode("utf-8", "replace"),
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {"ok": False, "redacted": WITHHELD, "rules": [], "lines": []}
    out = p.stdout.decode("utf-8", "replace")
    stderr = p.stderr.decode("utf-8", "replace")
    rules = sorted(
        {
            r
            for x in re.findall(r"\brules?=([A-Za-z0-9_.,-]+)", stderr)
            for r in x.split(",")
            if r
        }
    )
    src, dst = text.rstrip("\n").split("\n"), out.rstrip("\n").split("\n")
    if p.returncode != 0:
        return {"ok": False, "redacted": WITHHELD, "rules": rules, "lines": []}
    if len(src) == len(dst):
        lines = [i + 1 for i, (a, b) in enumerate(zip(src, dst)) if a != b]
    else:  # a multi-line redaction (a private key): every line is suspect
        lines = (
            list(range(1, len(src) + 1))
            if out.rstrip("\n") != text.rstrip("\n")
            else []
        )
    return {"ok": True, "redacted": out, "rules": rules, "lines": lines}


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _rebuild(obj, it):
    if isinstance(obj, str):
        return next(it)
    if isinstance(obj, dict):
        return {k: _rebuild(v, it) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rebuild(v, it) for v in obj]
    return obj


def _shape_scrub(text: str) -> str:
    """Replace high-confidence credential shapes; needs no gitleaks."""
    for _name, rx in _REAL_SHAPES:
        text = rx.sub("***REDACTED:SECRET***", text)
    return _B64_RE.sub(
        lambda m: (
            "***REDACTED:SECRET***"
            if re.search(r"\d", m.group(0)) and re.search(r"[A-Za-z]", m.group(0))
            else m.group(0)
        ),
        text,
    )


def _value_free(result):
    """Backstop: every string in a tool result is shape-scrubbed, then goes through the scanner once more."""
    result = _rebuild(result, iter([_shape_scrub(x) for x in _strings(result)]))
    strs = list(_strings(result))
    if not strs:
        return result
    r = _scan(SEP.join(strs))
    parts = r["redacted"].split(SEP)
    if not r["ok"] or len(parts) != len(strs):
        parts = [WITHHELD] * len(strs)
    return _rebuild(result, iter(parts))


def _tool(fn):
    """Wrap a tool so its result always passes the value-free backstop."""

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        return _value_free(fn(*a, **kw))

    return wrapper


def _git_root(cwd: str) -> str | None:
    try:
        p = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (
        os.path.realpath(p.stdout.strip())
        if p.returncode == 0 and p.stdout.strip()
        else None
    )


# ------------------------------------------------------------ helpers ---

def _find_reason(obj):
    if isinstance(obj, dict):
        if isinstance(obj.get("permissionDecisionReason"), str):
            return obj
        for v in obj.values():
            r = _find_reason(v)
            if r:
                return r
    return None


# ------------------------------------------------------- 2. explain_block ---

_RULE_LIST_RE = re.compile(r"rule\(s\):\s*([A-Za-z0-9_.,\- ]+?)\)")
# One entry of the hook's "Where" list: "  1. the staged diff, file a/b.py, line 12: <redacted line>"
_WHERE_RE = re.compile(r"^\s*(\d+)\. (.+?), line (\d+): ", re.M)
_AMBIGUOUS = {
    "secret-lead-in",
    "url-password",
    "url-query-secret",
    "auth-header",
    "cookie-header",
    "cli-password-flag",
    "netrc-password",
    "pgpass-password",
    "k8s-env-value",
    "json-key-value",
    "azure-client-secret",
    "gcloud-oauth-token",
    "bcrypt-hash",
    "generic-api-key",
}
_NEVER = (
    "Do not look for a way around the guard: the overrides (GUARDS_ALLOW_*) belong "
    "to the person running the session, not to you, and typing one in front of a "
    "command does nothing."
)
_SOURCE_KINDS = (
    ("the staged diff", "staged diff"),
    ("(named by the command)", "named file"),
    ("the command text", "command text"),
    ("input (JSON on one line)", "tool input"),
)


def _source_kind(label: str) -> str:
    for needle, kind in _SOURCE_KINDS:
        if needle in label:
            return kind
    return "unknown"


def _where(text: str) -> list[dict]:
    """The hook's located entries, without the redacted line text."""
    out = []
    for m in _WHERE_RE.finditer(text):
        label = m.group(2)
        kind = _source_kind(label)
        entry = {"n": int(m.group(1)), "source": kind, "line": int(m.group(3))}
        if kind == "staged diff":
            f = re.match(r"the staged diff, file (.+)$", label)
            entry["file"] = f.group(1) if f else ""
        elif kind == "named file":
            f = re.match(r"file (.+) \(named by the command\)$", label)
            entry["file"] = f.group(1) if f else ""
        out.append(entry)
    return out


@_tool
def explain_block(message: str) -> dict:
    """Turn a guard deny or ask message (or the decision JSON text) into a diagnosis and next steps.

    Value-free: only rule IDs, sources, files and line numbers are returned,
    never a matched line. See docs/AGENTS-GUIDE.md.
    """
    text = message
    try:
        found = _find_reason(json.loads(message))
        if found:
            text = found["permissionDecisionReason"]
    except ValueError:
        pass
    low = text.lower()
    rules: list[str] = []
    m = _RULE_LIST_RE.search(text)
    if m:
        rules = [
            r
            for r in m.group(1).replace(",", " ").split()
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", r)
        ]
    hard = [r for r in rules if r not in _AMBIGUOUS]
    where = _where(text)
    kinds = {w["source"] for w in where}

    guard = "unknown"
    asked = False
    diag: str
    steps: list[str]
    if "publish-guard" in low:
        guard = "publish-guard"
        if "did not finish in time" in low:
            diag = (
                "The local scan ran out of time, so the publish was denied fail-closed "
                "(this is not a finding). Very long single lines (minified or generated "
                "files, one-line JSON) are the slow case."
            )
            steps = [
                "Leave such a file out of the commit, or split the long lines; publish a shorter text.",
                "guards:synthetic is for fake fixture lines, not a way past a size limit.",
                "Run guards_status to see whether the service is down.",
            ]
        elif "no secret scanner could run" in low:
            diag = (
                "No scanner could run at all, so the publish was denied fail-closed "
                "(this is not a finding)."
            )
            steps = [
                "Run guards_status: it shows whether the service, jq and the vendored scanner are available.",
                "Tell the user to repair the install; do not work around it.",
            ]
        else:
            asked = "may contain a credential" in low and "blocked by" not in low
            if hard:
                diag = (
                    f"A high-confidence detector fired ({', '.join(hard)}): a private key, "
                    "a vendor token format, or a value from this session's environment. "
                    "These are always denied."
                )
                steps = [
                    "Remove the value and describe its SHAPE only (length, character classes, the tool that made it).",
                    "A fixture must not look like a real vendor token: build it at run time from pieces so the source has no literal.",
                ]
            else:
                diag = (
                    "A context rule fired: a key name or URL shape next to a value. "
                    "Real credentials and look-alike fixtures both trigger it, and so can a "
                    "key that only NAMES a secret (secret_vault_id, token_store_ref)."
                )
                steps = [
                    "If the match is only a key NAME and the value is not a credential, it is a false positive: rename or reword the key and use report_false_positive.",
                ]
            if asked:
                diag += " This is an ask: a person answers it, you cannot."
                steps.append(
                    "Do not approve it yourself. If the text holds a real value, rewrite it to describe the shape."
                )
            if "no person to answer" in low:
                steps.append(
                    "This session has no person to answer an approval prompt, so an ambiguous match is a deny instead of an ask (expected in auto mode)."
                )
            if "staged diff" in kinds:
                steps.append(
                    "For a deliberately fake fixture line in the staged diff: put guards:synthetic on the SAME line in that file's comment syntax (mark_synthetic does it), then git add the file again."
                )
            if kinds - {"staged diff"}:
                steps.append(
                    "The marker does NOT cover the command text (so not a -m message), PR or issue bodies, or files named by --body-file, -F or cat: rewrite that text to describe the shape, and put long text in a file with prepare_publication."
                )
            if not where:
                steps.append(
                    "The hook did not locate the match (it fired without changing the text): read the rule above and check_before_publish the pieces."
                )
            if "diff is larger than" in low:
                diag += " The diff was cut at the size cap; only the first part was scanned."
            steps.append(
                "After fixing, run check_before_publish on the same command or text for the located answer."
            )
    elif "credfile-guard" in low:
        guard = "credfile-guard"
        if "jq is not installed" in low:
            diag = "credfile-guard needs jq and it is missing; the call was denied fail-closed."
            steps = ["Ask the user to install jq."]
        else:
            diag = "The call would print credential material into the transcript."
            steps = [
                "Check a key exists or works without reading it: test -f PATH, ssh-keygen -l -f PATH, ssh -i PATH.",
                "If you only need the variable names of an .env-style file, ask the user, or read a .env.example.",
            ]
    elif "sendmessage-guard" in low:
        guard = "sendmessage-guard"
        diag = "A secret in an outgoing message was redacted (or the backend was unreachable so only the local scan ran). This is a notice, not a deny."
        steps = ["Send the shape, not the value.", "Run guards_status if the backend note appears."]
    elif "mcp-output-guard" in low:
        guard = "mcp-output-guard"
        diag = "Credential material in an MCP tool result was replaced by redaction markers. This is intentional and not an error."
        steps = ["Work from the redacted result; ask the user for the value out of band if you truly need it."]
    elif "userpromptsubmit" in low or "your prompt" in low:
        guard = "userpromptsubmit-guard"
        diag = "The user's prompt contained a secret; the guard only noted it (advisory)."
        steps = ["Do not repeat the value in commits, issues, PRs or files; treat it as exposed and suggest rotation."]
    else:
        diag = "This text does not match a known guard message."
        steps = [
            "Run check_before_publish on the exact command or text to get the hook's own answer.",
            "Run guards_status to see which hooks are registered.",
        ]
    steps.append(_NEVER)
    return {
        "guard": guard,
        "decision": "ask" if asked else ("deny" if guard in ("publish-guard", "credfile-guard") else "notice"),
        "sources": sorted(kinds) or ["unknown"],
        "where": where,
        "rules": rules,
        "diagnosis": diag,
        "next_steps": steps,
        "recognized": guard != "unknown",
    }


# ------------------------------------------------- 3. prepare_publication ---

_KINDS = {
    "commit-message": ("commit", ".txt"),
    "pr-body": ("pr", ".md"),
    "issue-body": ("issue", ".md"),
}


@_tool
def prepare_publication(kind: str, title: str, body: str) -> dict:
    """Write commit/PR/issue text to a file, scan it, and get the command that uses the file.

    kind: "commit-message", "pr-body" or "issue-body". Long text passed inline
    on a command line is what trips the guard; a file is scanned the same way
    but is easy to inspect and fix. If the scanner would redact anything, the
    file holds the REDACTED text (the raw value is never written), the
    verdict is "would-redact" and `ready` is false: rewrite those lines to
    describe the shape, then call this again.
    """
    if kind not in _KINDS:
        return {"error": "kind must be commit-message, pr-body or issue-body"}
    if "\n" in title or "\r" in title or not title.strip():
        return {"error": "title must be a single non-empty line"}
    if len((title + body).encode("utf-8", "replace")) > MAX_TEXT:
        return {"error": f"text is over {MAX_TEXT} bytes"}
    short, suffix = _KINDS[kind]
    content = (
        f"{title}\n\n{body}\n"
        if kind == "commit-message"
        else body
        if body.endswith("\n")
        else body + "\n"
    )
    body_scan, title_scan = _scan(content), _scan(title)
    if not body_scan["ok"] or not title_scan["ok"]:
        return {
            "error": "the scanner could not run, so nothing was written; run guards_status"
        }
    path = _state_file("publications", short, suffix)
    changed = bool(body_scan["lines"] or title_scan["lines"])
    with open(path, "w", encoding="utf-8") as f:
        f.write(body_scan["redacted"])
    src_lines, red_lines = content.split("\n"), body_scan["redacted"].split("\n")
    shown = [
        {"line": n, "redacted_line": red_lines[n - 1] if n <= len(red_lines) else ""}
        for n in body_scan["lines"]
    ][:50]
    q, t = (
        shlex.quote(path),
        shlex.quote(title_scan["redacted"] if title_scan["lines"] else title),
    )
    command = {
        "commit-message": f"git commit -F {q}",
        "pr-body": f"gh pr create --title {t} --body-file {q}",
        "issue-body": f"gh issue create --title {t} --body-file {q}",
    }[kind]
    res = {
        "path": path,
        "verdict": "would-redact" if changed else "clean",
        "ready": not changed,
        "redacted_lines": shown,
        "title_would_be_redacted": bool(title_scan["lines"]),
        "rules": sorted(set(body_scan["rules"]) | set(title_scan["rules"])),
        "command": command,
        "lines_total": len(src_lines),
    }
    if changed:
        res["next"] = (
            "The file holds the scanner-redacted text. Rewrite the listed lines to describe the shape (length, character classes, the tool that produced it), then call prepare_publication again."
        )
    else:
        res["next"] = (
            "Run the command as given, then (optionally) check it first with check_before_publish."
        )
    return res


# ------------------------------------------------------- 4. guards_status ---

_PERMISSION_RULES = {
    "ask_modes": ["default", "acceptEdits", "plan"],
    "deny_modes": "every other mode (auto, bypassPermissions, dontAsk, unknown): an ambiguous publish match is a deny, because nobody can answer an ask",
}
_ENV_FLAGS = (
    "GUARDS_ALLOW_PUBLISH_SECRETS",
    "GUARDS_ALLOW_CRED_READ",
    "GUARDS_MCP_SCAN",
    "GUARDS_PUBLISH_ASK",
    "GUARDS_CRED_ASK",
)


def _plugin_version() -> str:
    for p in (
        os.path.join(PLUGIN_ROOT, "VERSION"),
        os.path.join(PLUGIN_ROOT, "..", "VERSION"),
    ):
        try:
            with open(p, encoding="utf-8") as f:
                v = f.read().strip()
            if re.fullmatch(r"[0-9A-Za-z.+-]{1,32}", v):
                return v
        except OSError:
            continue
    return "unknown"


def _registered_hooks() -> list[dict]:
    try:
        with open(os.path.join(HOOKS_DIR, "hooks.json"), encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return []
    out = []
    for event, groups in (cfg.get("hooks") or {}).items():
        for g in groups:
            for h in g.get("hooks", []):
                script = os.path.basename((h.get("args") or [h.get("command", "")])[-1])
                out.append(
                    {
                        "event": event,
                        "matcher": g.get("matcher", "*"),
                        "script": script,
                        "timeout": h.get("timeout"),
                    }
                )
    return out


@_tool
def guards_status() -> dict:
    """Which guards are active here, their versions, and anything degraded. Read-only."""
    endpoint = os.environ.get("GUARDS_ENDPOINT", "http://127.0.0.1:8700")
    service: dict = {"endpoint": endpoint, "up": False}
    try:
        r = httpx.get(f"{endpoint}/about", timeout=3.0)
        service["up"] = 200 <= r.status_code < 300
        service["http_status"] = r.status_code
        if service["up"]:
            try:
                j = r.json()
                v = (
                    j.get("version") or j.get("service_version") or j.get("app_version")
                    if isinstance(j, dict)
                    else None
                )
                service["version"] = str(v)[:32] if v is not None else "unknown"
            except ValueError:
                service["version"] = "unknown"
    except (httpx.HTTPError, httpx.InvalidURL, OSError) as e:
        service["error"] = type(e).__name__
    hooks = _registered_hooks()
    degraded = []
    if not shutil.which("jq"):
        degraded.append(
            "jq is missing: credfile-guard and publish-guard cannot read their payload and fail OPEN or closed per hook; install jq"
        )
    if not (
        shutil.which("gitleaks")
        or os.path.isfile(os.path.expanduser("~/.local/bin/gitleaks"))
    ):
        degraded.append(
            "gitleaks is missing: only the built-in private-key and context passes run locally; vendor token formats are not checked"
        )
    if not service["up"]:
        degraded.append(
            "the guards-unified service does not answer: secrets fall back to the local scanner; PII and injection findings are unavailable"
        )
    if not hooks:
        degraded.append(
            "hooks/hooks.json could not be read: cannot list the registered hooks"
        )
    if not os.path.isfile(SCAN_SH):
        degraded.append("the vendored scanner is missing")
    env = {k: os.environ[k][:8] for k in _ENV_FLAGS if k in os.environ}
    if (
        env.get("GUARDS_ALLOW_PUBLISH_SECRETS") == "1"
        or env.get("GUARDS_ALLOW_CRED_READ") == "1"
        or env.get("GUARDS_MCP_SCAN") == "0"
    ):
        degraded.append(
            "a guard is switched off by an environment override set by whoever started this session (see env_overrides)"
        )
    return {
        "plugin_version": _plugin_version(),
        "service": service,
        "hooks": hooks,
        "permission_mode_rules": _PERMISSION_RULES,
        "env_overrides": env,
        "degraded": degraded,
        "ok": not degraded,
    }


# ------------------------------------------------------- 5. mark_synthetic ---

_SLASH = {
    "ts",
    "tsx",
    "js",
    "jsx",
    "mjs",
    "cjs",
    "go",
    "java",
    "rs",
    "c",
    "h",
    "cpp",
    "cc",
    "hpp",
    "cs",
    "swift",
    "kt",
    "kts",
}
_HASH = {
    "py",
    "sh",
    "bash",
    "zsh",
    "yaml",
    "yml",
    "toml",
    "rb",
    "ini",
    "conf",
    "env",
    "tf",
}
_DASH = {"sql", "lua"}
_HTML = {"html", "htm", "md", "xml"}

# High-confidence real-credential shapes. The marker exists for fabricated
# fixtures; it must not launder something that looks like the real thing.
_REAL_SHAPES = [
    ("private-key header", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY")),
    ("aws access key id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "github token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
    ("slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{8,}")),
    ("sk- style key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("payment key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("gitlab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    ),
]
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _real_shape(line: str) -> str | None:
    for name, rx in _REAL_SHAPES:
        if rx.search(line):
            return name
    for m in _B64_RE.finditer(line):
        s = m.group(0)
        if re.search(r"\d", s) and re.search(r"[A-Za-z]", s):
            return "40+ character base64-like run"
    return None


def _comment_for(path: str, reason: str) -> str | None:
    base = os.path.basename(path)
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    if base == "Dockerfile" or base.startswith(".env") or base == "Makefile":
        ext = "env"
    text = f"{MARKER} - {reason}"
    if ext in _SLASH:
        return f"// {text}"
    if ext in _HASH:
        return f"# {text}"
    if ext in _DASH:
        return f"-- {text}"
    if ext in _HTML:
        return f"<!-- {text} -->"
    return None


@_tool
def mark_synthetic(path: str, lines: list[int], reason: str, cwd: str = "") -> dict:
    """Mark deliberately FAKE test-fixture lines with the guards:synthetic marker.

    The publish guard drops marked lines from a commit's staged diff. Use this
    only for fabricated values in source or test files you are committing.
    Refuses (and changes nothing) when: the reason is empty; the path is not
    inside the git repo of cwd; the file type has no known comment syntax; any
    requested line is out of range or looks like a real credential (private
    key header, AKIA/ASIA id, ghp_/gho_/github_pat_, xox*-, sk-, JWT, 40+
    character base64). Build vendor-shaped fakes at run time instead.
    Returns exactly the lines changed, scanner-redacted.
    """
    reason = (reason or "").strip()
    if not reason or len(reason) > 120 or "\n" in reason or "\r" in reason:
        return {
            "error": "reason is required: one line, at most 120 characters, saying why the value is fake"
        }
    if _real_shape(reason) or _scan(reason)["lines"]:
        return {"error": "reason must not contain anything credential-shaped"}
    if (
        not isinstance(lines, list)
        or not lines
        or len(lines) > 200
        or not all(
            isinstance(n, int) and not isinstance(n, bool) and n >= 1 for n in lines
        )
    ):
        return {"error": "lines must be 1 to 200 positive 1-based line numbers"}
    cwd = cwd or os.getcwd()
    root = _git_root(cwd) if os.path.isdir(cwd) else None
    if not root:
        return {"error": "cwd is not inside a git repository; nothing changed"}
    full = os.path.realpath(path if os.path.isabs(path) else os.path.join(cwd, path))
    if os.path.commonpath([root, full]) != root:
        return {"error": "path is outside the git repository of cwd; nothing changed"}
    if not os.path.isfile(full) or os.path.getsize(full) > MAX_FILE:
        return {"error": "path is not a regular file under 2 MB; nothing changed"}
    marker = _comment_for(full, reason)
    if marker is None:
        return {
            "error": f"no known comment syntax for {os.path.basename(full)}; the marker cannot be added (json has no comments: put the fixture in a source file that builds it)"
        }
    try:
        with open(full, encoding="utf-8", newline="") as f:
            content = f.read()
    except (UnicodeDecodeError, OSError):
        return {"error": "file is not readable UTF-8 text; nothing changed"}
    rows = content.splitlines(keepends=True)
    want = sorted(set(lines))
    if want[-1] > len(rows):
        return {
            "error": f"line {want[-1]} is past the end of the file ({len(rows)} lines); nothing changed"
        }
    refused = [
        {"line": n, "matches_shape": s} for n in want if (s := _real_shape(rows[n - 1]))
    ]
    if refused:
        return {
            "error": "refused: these lines look like a real credential and the marker must not launder one. Build the fake at run time (prefix + 'x' * n) so the source has no literal. Nothing changed.",
            "refused_lines": refused,
        }
    changed, already = [], []
    for n in want:
        row = rows[n - 1]
        body = row.rstrip("\r\n")
        eol = row[len(body) :]
        if MARKER in body:
            already.append(n)
            continue
        rows[n - 1] = f"{body}  {marker}{eol}"
        changed.append(n)
    if changed:
        mode = os.stat(full).st_mode
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(full), prefix=".guards-mark-")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write("".join(rows))
        os.chmod(tmp, mode & 0o7777)
        os.replace(tmp, full)
    shown = []
    for n in changed:
        r = _scan(rows[n - 1].rstrip("\r\n"))
        shown.append({"line": n, "now": r["redacted"]})
    return {
        "path": os.path.relpath(full, root),
        "changed": shown,
        "already_marked": already,
        "marker": MARKER,
    }


# ------------------------------------------------- 6. report_false_positive ---


def _entropy(s: str) -> float:
    return -sum(
        c / len(s) * math.log2(c / len(s)) for c in (s.count(ch) for ch in set(s))
    )


def _looks_unredacted(text: str) -> bool:
    for m in re.finditer(r"[A-Za-z0-9+/=_.-]{20,}", text):
        run = m.group(0)
        has_d, has_a = bool(re.search(r"\d", run)), bool(re.search(r"[A-Za-z]", run))
        if _entropy(run) >= 4.0 or (
            has_d and has_a and len(re.findall(r"\d", run)) >= 3
        ):
            return True
    return bool(_real_shape(text))


@_tool
def report_false_positive(rule: str, redacted_line: str, context: str = "") -> dict:
    """Write a value-free false-positive report to a local file for the user to forward.

    rule: the detector rule ID from the block message. redacted_line: the
    matching line WITH the value already replaced (use the redacted line the
    block message or prepare_publication shows). context: a sentence on what
    the line is (e.g. "test fixture for a login form"). Refuses input that
    still looks like it holds a credential. The public repos have Issues
    disabled, so this does not open one.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", rule or ""):
        return {
            "error": "rule must be a detector rule ID such as secret-lead-in (letters, digits, - _ .)"
        }
    for name, val, cap in (
        ("redacted_line", redacted_line, 500),
        ("context", context, 500),
    ):
        if not isinstance(val, str) or len(val) > cap or "\n" in val or "\r" in val:
            return {"error": f"{name} must be one line of at most {cap} characters"}
    if not redacted_line.strip():
        return {"error": "redacted_line is required"}
    for name, val in (("redacted_line", redacted_line), ("context", context)):
        if _looks_unredacted(val) or _scan(val)["lines"]:
            return {
                "error": f"{name} does not look redacted (it contains a long high-entropy run or something the scanner would redact). Replace the value with ***REDACTED*** first."
            }
    path = _state_file("reports", "false-positive", ".json")
    report = {
        "kind": "guards-false-positive",
        "value_free": True,
        "rule": rule,
        "redacted_line": redacted_line,
        "context": context,
        "plugin_version": _plugin_version(),
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),  # noqa: UP017
        "id": secrets.token_hex(4),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    return {
        "path": path,
        "forward": f"Guards false-positive report for rule {rule} (value-free), saved at {path}. Forward it to the maintainers of the guards plugin through private vulnerability reporting (the Security tab of github.com/gramatr/claude-plugin-guards, Report a vulnerability) or to the person who installed the plugin; the public repos have Issues disabled.",
    }


# ------------------------------------------------------------- prompts ---


def fix_a_block() -> str:
    """Steps for an agent whose command or edit was blocked by a guard."""
    return (
        "A guard blocked your call. Do this, in order:\n"
        "1. Call explain_block with the deny message (or its JSON). Read the source and rules it names.\n"
        "2. Call check_before_publish with the exact command, or the text you meant to publish, to get the hook's own located answer.\n"
        "3. Fix the TEXT, never the guard: describe the shape of a credential (length, character classes, the tool that made it), never the value, a prefix, or a rotated one.\n"
        "4. Long commit/PR/issue text goes in a file: prepare_publication, then use the command it returns.\n"
        "5. A deliberately fake fixture line in source you are COMMITTING takes the guards:synthetic marker (mark_synthetic). The marker does not apply to command text, bodies, or files named by a command.\n"
        "6. If you believe the match is a false positive, call report_false_positive with the rule and the REDACTED line, and tell the user the file path.\n"
        "7. Call guards_status if the message says no scanner could run.\n"
        "Never ask the user to set GUARDS_ALLOW_* and never look for a way around a guard."
    )


def safe_pr_body() -> str:
    """How to write a PR, issue or commit text that passes the publish guard."""
    return (
        "Write the PR body, issue body or commit message so it passes the publish guard the first time:\n"
        "- Say what changed, why, the files, and how to roll back. Name rules, files and line numbers, never values.\n"
        "- Describe credentials by shape only: 'a 40-character hex token', 'an AWS-style access key id'. No value, no prefix, no partial, no rotated one.\n"
        "- Avoid 'word: value' wording next to credential words (password, token, key, secret) in titles and bodies.\n"
        "- Do not paste long text inline. Call prepare_publication(kind, title, body); it writes a file, scans it and returns the command "
        "(git commit -F FILE, gh pr create --body-file FILE, gh issue create --body-file FILE).\n"
        "- If the verdict is would-redact, rewrite the listed lines and call it again.\n"
        "- Before running the command, check_before_publish(command) gives the hook's answer without publishing."
    )


def fake_fixture_checklist() -> str:
    """Checklist for writing test fixtures that look like credentials."""
    return (
        "Writing a test fixture that looks like a credential:\n"
        "1. Prefer building the value at run time from pieces (prefix + 'x' * 32) so the source holds no literal. Vendor-shaped literals "
        "(AKIA..., ghp_..., xoxb-..., sk-..., JWTs, PEM headers) cannot be marked, and mark_synthetic refuses them.\n"
        "2. A generic fake such as a password assignment in a test may stay literal, with guards:synthetic on the SAME line: call mark_synthetic(path, lines, reason) "
        "(the right comment syntax is chosen by file type).\n"
        "3. The marker only helps in a git commit's staged diff. Do not paste fixtures into commands, PR/issue bodies or message files; describe them instead.\n"
        "4. Make the fake obviously fake (example.invalid, 'not-a-real-secret'), never a rotated real one.\n"
        "5. Before committing: stage, then check_before_publish('git commit -m x', cwd) to see what the guard would say.\n"
        "6. A false positive on a real non-secret - call report_false_positive with the rule and the redacted line."
    )


TOOLS = (
    explain_block,
    prepare_publication,
    guards_status,
    mark_synthetic,
    report_false_positive,
)
PROMPTS = (fix_a_block, safe_pr_body, fake_fixture_checklist)


def register(mcp) -> None:
    """Register the tools and prompts on an MCPServer."""
    for t in TOOLS:
        mcp.tool()(t)
    for p in PROMPTS:
        mcp.prompt()(p)
