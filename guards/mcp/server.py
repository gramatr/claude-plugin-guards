#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=2", "httpx"]
# ///
"""
guards/mcp/server.py — MCP front-end for explicit tool-call access to
the unified guards backend (secret-guard + pii-guard + injection-guard
in one image, one process — see gramatr/guards-unified).

ONE tool, not three. Earlier versions of this file exposed
scan_secrets/scan_pii/classify_injection as three separate tools
against three separate daemons. That made sense when they WERE three
separate daemons on three separate ports; it stopped making sense once
the backend became one unified /v1/scan endpoint that already runs all
three detectors on every call and returns all three results in one
response. Splitting a single-request, single-response backend into
three client-side tool calls only adds round trips for no benefit — the
caller always wanted all three checked anyway (see
RESEARCH-SPIKE-classification.md and this repo's own README: secrets,
PII, and injection are three independent axes that don't gate each
other, which is exactly why there's no reason to call them separately).

Fulfills injection-guard's own README roadmap item: "MCP server
front-end for explicit tool-call access (vs. automatic hook-based
gating only)."

No new detection logic — this is a protocol adapter only. Fail-explicit,
not fail-open: unlike the hooks (which pass tool output through
unchanged if the backend is unreachable, so a session never silently
stalls), this tool returns an explicit {"error": ...} rather than a
false "clean" result, because a caller that explicitly asked for a scan
deserves to know it didn't happen rather than assume it passed.

Trusting this: the HOOKS (not this tool) are what actually protect a
session's tool output and agent-to-agent messages automatically; this
MCP tool is the explicit, on-demand path. For what the hooks guarantee,
what they don't, and a live-verified test of each (both with the
backend up and deliberately killed) — see this repo's README,
"Verified live: secret redaction across every surface."

Besides `scan`, the server carries the knowledge a coding agent needs to work
with the guards without help: its `instructions` (they land in the agent's
system prompt), four `guards://guide/...` resources, and the
`check_before_publish` tool, which runs the real publish-guard hook offline on
a would-be command, body or message.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx
from mcp.server.mcpserver import MCPServer

INSTRUCTIONS = """\
guards protects this session. Secrets in Bash and MCP output are redacted, reads of credential files are denied, and a commit, PR, issue or comment that looks like it contains a credential is blocked; the block names the matching line with the value redacted.

Rules:
1. Never put a real credential in a commit message, PR or issue body, comment or file. Describe its shape (length, character classes, which tool produced it).
2. guards:synthetic on the SAME line marks a deliberately fake fixture line. It only works for added lines of a git commit's staged diff.
3. Never disable or bypass the guards, and never ask the user to. Report a false positive (for example a key named secret_vault_id) instead.

Before publishing text, run the check_before_publish tool on it. Read guards://guide/publishing, guards://guide/false-positives, guards://guide/hooks and guards://guide/diagnosing-a-block (longer: docs/AGENTS-GUIDE.md).
"""

mcp = MCPServer("guards", instructions=INSTRUCTIONS)

# Tools and prompts that help an agent work with the guards (check before publishing,
# explain a block, mark fake fixtures); see guards_tools.py. None of them weakens a guard.
def _register_agent_tools() -> None:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import guards_tools

    guards_tools.register(mcp)


_register_agent_tools()

GUARDS_ENDPOINT = os.environ.get("GUARDS_ENDPOINT", "http://127.0.0.1:8700")


SCAN_TIMEOUT = 15.0


def _http_error(resp: "httpx.Response") -> str:
    """Describe a non-2xx answer from the backend, with its real status."""
    try:
        detail = resp.json().get("detail")
    except (ValueError, AttributeError):
        detail = None
    if resp.status_code == 413 and isinstance(detail, dict):
        return (
            f"guards backend refused the text: HTTP 413, {detail.get('bytes')} bytes is over the "
            f"{detail.get('limit_bytes')}-byte limit (server setting {detail.get('setting')}). "
            "Send a shorter text; nothing was scanned."
        )
    body = resp.text[:200].strip()
    return f"guards backend at {GUARDS_ENDPOINT} answered HTTP {resp.status_code}, nothing was scanned" + (f": {body}" if body else "")


@mcp.tool()
def scan(text: str) -> dict:
    """Scan text for leaked secrets, PII, and prompt-injection/jailbreak attempts — one call, all three checked.

    Returns, on success:
    {
      "findings": [
        {"type": "secret",    "verdict": "found"|"clean"|"error", "reason_code": [...] | null, "detail": {...}},
        {"type": "pii",       "verdict": "found"|"clean"|"error", "reason_code": [...] | null, "detail": {...}},
        {"type": "injection", "verdict": "malicious"|"clean"|"error", "reason_code": [...] | null, "detail": {...}}
      ],
      "redacted_text": "..."  # secrets then PII redacted in sequence; injection never alters text, flag only
    }
    Or {"error": str} if the backend is unreachable, answers with a non-2xx
    status (e.g. 413 for text over its size limit) or returns something that
    is not a scan result — callers must not treat an error as "clean."

    SCOPE, stated plainly because this is what the underlying tools
    themselves document: the injection finding is jailbreak/override
    detection ONLY — measured recall on indirect injection (malicious
    instructions embedded in data with no override language) is 6% on
    real tool-output attacks (InjecAgent, n=200). A "clean" injection
    verdict is not a safety guarantee for content an agent is about to
    act on. The pii finding covers Presidio's configured entity set
    only, not all PII.
    """
    try:
        resp = httpx.post(f"{GUARDS_ENDPOINT}/v1/scan", json={"text": text}, timeout=SCAN_TIMEOUT)
    except httpx.TimeoutException as e:
        return {"error": f"guards backend unreachable at {GUARDS_ENDPOINT}: timed out after {SCAN_TIMEOUT:g}s ({e})"}
    except (httpx.HTTPError, httpx.InvalidURL, OSError) as e:
        return {"error": f"guards backend unreachable at {GUARDS_ENDPOINT}: {e}"}

    if not 200 <= resp.status_code < 300:
        return {"error": _http_error(resp)}
    try:
        result = resp.json()
        findings = result["findings"]
    except (ValueError, KeyError, TypeError):
        findings = None
    if not isinstance(findings, list):
        # A 2xx whose body is not a scan result must not read as "clean".
        return {"error": f"guards backend at {GUARDS_ENDPOINT} answered HTTP {resp.status_code} without scan findings"}
    return result


# --- Guides: the same knowledge as docs/HOOKS.md and the hook scripts, in the
# form an agent can read mid-task. Every statement here is pinned by the hooks'
# code or tests (see guards/tests/publish-guard.test.sh); change both together.

GUIDE_PUBLISHING = """\
# Publishing with the guards on

The publish guard (a PreToolUse hook) checks these before they run:
- gh issue|pr|release|gist with create, comment, edit or review
- gh api with a body flag (-f, -F, --field, --raw-field, --input)
- git commit, including `git -C DIR commit`, `git -c k=v commit` and commits after `cd DIR`
- GitHub MCP write tools (create, update, comment, push, merge, review, edit, ...)
It does NOT inspect git push, curl, scripts that publish indirectly, other MCP servers or the web UI.

What is scanned: the whole command text (heredoc bodies and a git commit -m message included), the contents of files the command names (--body-file, --notes-file, --input, -F, `cat FILE`, gist files), and for git commit the lines the commit adds. With `git add ... && git commit` in one command the add is replayed on a copy of the index; with -a/--all it is the tracked changes against HEAD. Each source is capped at 512 KB (PUBLISH_GUARD_MAX_BYTES); the hook says when a diff was cut.

Rules for writing text that gets published:
1. Never include a real credential: not a prefix, not a partial, not a rotated or dead one. Describe the shape: length, character classes, which tool or command produced it.
2. Put long bodies and messages in a file, run check_before_publish on the text, then publish with --body-file or git commit -F.
3. For fixtures in a commit, see guards://guide/false-positives for the marker. It never covers a message or a body.

Longer guide for agents: docs/AGENTS-GUIDE.md in the plugin repository.

Outcome by permission mode: a private key, a vendor token format or a value from this session's environment is always denied. An ambiguous match (a secret-looking key name next to a value, a URL password, an auth header, ...) is a deny in auto, bypassPermissions and dontAsk, and asks the person in default, acceptEdits and plan. If no scanner can run, or the scan runs out of time, the publish is denied.
"""

GUIDE_FALSE_POSITIVES = """\
# False positives and the synthetic marker

The scanner reads a key name that contains a credential word (secret, password, token, credential, api key, private key, passphrase, and short aliases such as pw, pwd, pass, cred, pat) followed by a value of 4 or more characters as a credential. A name that only describes a secret is skipped:
- the credential word followed by a descriptor as the LAST segment: name, ref, id, type, path, file, version, count, ttl, namespace, store, manager, provider, url, arn (secret_name, client_secret_bws_id, clientSecretBwsId, secret_vault_id, token_store_ref, credential_provider_arn, secretKeyRef);
- a setting about a credential: a name ending in bytes, size, length, limit, max, min, timeout, secs, seconds, ms, port, depth, mode, ask, enabled or disabled; a tokenizer.
Placeholders are skipped too: values starting with $, <, {, ***, or ..., and words such as true, false, null, none, changeme, example, todo, string.
Ordinary source code is skipped too: an unquoted value that is a call, a variable, a member chain or a type name on a line of code (a call, an object property whose value is a variable, a field typed as a primitive). A string literal assigned to a credential-named variable, and unquoted values in env files, shell, YAML and INI, are not skipped.
A name whose last segment is the credential or a value word (AUTH_TOKEN, db_password, api_secret, client_secret_value, secret_key) is redacted. A rule that skips a name never excuses a real value.

When a block is a false positive:
1. On a key NAME: rename or reword the key if you can, and tell the user which key and which rule. Do not retry the same text.
2. Prose that names a credential word followed by a colon and a word reads as a key and a value. Reword: say "the token (24 characters)" instead.
3. A deliberately fake fixture line in a git commit: add `guards:synthetic` on the SAME line, in that file's comment syntax. It covers ONLY the added lines of the staged diff of a git commit, and not a real vendor credential or key: a private-key header, an AWS access key id, a GitHub, Slack, Stripe (sk_live_, rk_live_) or OpenAI (sk-proj-) key on a marked line is still denied. Documented example ids and any value containing EXAMPLE or FAKE are accepted; build other fake values at run time. JWT-shaped and ordinary fake values are fine. It does not cover the command text or a -m message, gh issue/pr bodies, or files named by --body-file, -F or cat. A line without the marker next to a marked one is still scanned.
4. Do not split, encode or otherwise disguise a value to get past the scan, and do not publish a real credential at all.
5. GUARDS_ALLOW_PUBLISH_SECRETS=1 is read from the environment Claude Code was STARTED from. Putting it in front of a command (`GUARDS_ALLOW_PUBLISH_SECRETS=1 git commit ...`) does nothing, and you cannot set it for the session. Never disable the guards or ask the user to; report the false positive and let them decide.
"""

GUIDE_HOOKS = """\
# The hooks

| Hook | When | What it does | If it cannot run |
|---|---|---|---|
| combined-hook | after every Bash call | redacts secrets in stdout and stderr, adds notes for PII and likely injection (first 2 KB only) | passes the output through (open) after a local fallback |
| mcp-output-guard | after MCP tool calls | redacts secrets in text results of recognised shapes | open; a text block over 512 KB is skipped |
| sendmessage-guard | before SendMessage | redacts secrets in message, summary, content | degrades to a local secret scan |
| credfile-guard | before Read, Grep, Bash | denies reads of SSH keys, cloud credentials, key stores and any file that holds a private-key header; asks about .env, kubeconfig, .npmrc, terraform state where a person can answer, denies otherwise | denies if it cannot finish |
| publish-guard | before gh publishes, gh api bodies, git commit, GitHub MCP writes | denies (or asks) when the text looks like it holds a credential, and says where | closed: denies |
| userpromptsubmit-guard | on your own prompt | adds a note if the prompt holds a secret; cannot redact | no note |

Secrets are redacted by the service (guards-unified) or, if it is down, by a local copy of the same scanner, so protection does not depend on the service. PII and injection are best-effort notes, not blocks. The guards run in the session's environment: a variable set inline on a command does not reach them. The credential-file guard has no per-call bypass by design; GUARDS_ALLOW_CRED_READ=1 in the environment Claude Code started from turns it off for the session, and that is the user's decision.
"""

GUIDE_DIAGNOSING = """\
# Diagnosing a block

A publish-guard block has three parts: the detector rule(s), a "Where" list, and what to do.

1. Read "Where". Each entry names the source (the command text, a file the command names, or the staged diff with file and line) and shows that line as the scanner redacts it: the key and its context are visible, the value is replaced by ***REDACTED:SECRET***. At most 5 entries are shown, with the total. Fix the first, then check again: others may follow.
2. Read the rule. secret-lead-in: a key name with a credential word next to a value. generic-api-key: a high-entropy value next to a key-like name. url-password, url-query-secret, auth-header, cookie-header, cli-password-flag, netrc-password, pgpass-password, k8s-env-value, json-key-value: a credential-shaped context. private-key-fallback or a private-key rule: key material (always denied). env-value: a value that is in this session's own environment (always denied). Other rule names are vendor token formats (always denied).
3. Decide: is it a real credential (remove it and describe the shape), a key NAME that only names an identifier (rename or report it), or a deliberately fake fixture line in a git commit (add the marker on the same line)? See guards://guide/false-positives for what the marker covers.
4. After changing the text, run check_before_publish on it. It runs the same hook offline and returns the same located explanation, never the value.
5. "the local secret scan did not finish in time": the input was too large or too match-heavy to scan within the limit (long lines and long unbroken runs are not the problem any more; thousands of matches in one text are). Split the text, or commit a large generated file separately.
6. "no secret scanner could run": the service is unreachable and the local scanner is missing. Tell the user; do not work around it.
7. "Where: the scanner could not point to a line": a rule matched without changing the text. Report it to the user with the rule name.

If the block names a line you did not write, it may come from a file the command names (--body-file, -F, cat), from the staged diff of another repository (check the directory the commit runs in) or from the unstaged state a `git commit -a` would take.
"""

GUIDES = {
    "publishing": ("Publishing with the guards on", GUIDE_PUBLISHING),
    "false-positives": ("False positives and the synthetic marker", GUIDE_FALSE_POSITIVES),
    "hooks": ("The hooks and what they do when they cannot run", GUIDE_HOOKS),
    "diagnosing-a-block": ("Diagnosing a block", GUIDE_DIAGNOSING),
}


def _register_guide(slug: str, title: str, body: str) -> None:
    @mcp.resource(f"guards://guide/{slug}", name=f"guide-{slug}", title=title, description=title, mime_type="text/markdown")
    def _guide() -> str:
        return body


for _slug, (_title, _body) in GUIDES.items():
    _register_guide(_slug, _title, _body)


# --- check_before_publish: the real publish-guard hook, run offline.

HOOK_TIMEOUT = 45
# The hook names its temp file in its explanation; show it as the caller's text.
_TEXT_LABEL_RE = re.compile(r"file \S*/body\.txt \(named by the command\)")
_COMMAND_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:(?:gh|git)\s+(?:-C\s+\S+\s+|-c\s+\S+\s+)*(?:issue|pr|release|gist|api|commit|add)\b|cd\s|pushd\s)"
)


def _hook_path() -> Path:
    override = os.environ.get("GUARDS_PUBLISH_GUARD_HOOK")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "hooks" / "publish-guard.sh"


def _run_hook(command: str, cwd: str) -> dict:
    """Run publish-guard.sh on a synthetic Bash payload; return {"decision", "inspected", "explanation"} or {"error"}."""
    hook = _hook_path()
    if not hook.is_file() or shutil.which("bash") is None:
        return {"error": f"cannot check: the publish-guard hook was not found at {hook} (or bash is missing); nothing was checked"}
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd, "permission_mode": "auto"})
    env = {k: v for k, v in os.environ.items() if k != "GUARDS_ALLOW_PUBLISH_SECRETS"}
    env["GUARDS_PUBLISH_GUARD_REPORT"] = "1"
    try:
        proc = subprocess.run(["bash", str(hook)], input=payload, capture_output=True, text=True, timeout=HOOK_TIMEOUT, env=env, check=False)
    except subprocess.TimeoutExpired:
        return {"error": f"cannot check: the publish-guard hook did not finish within {HOOK_TIMEOUT}s; nothing was checked"}
    except OSError as e:
        return {"error": f"cannot check: the publish-guard hook could not run ({e}); nothing was checked"}
    out = proc.stdout.strip()
    if proc.returncode not in (0, 2):
        return {"error": f"cannot check: the publish-guard hook exited with status {proc.returncode}; nothing was checked"}
    if not out:
        return {"decision": "allow", "inspected": False, "explanation": "The publish guard did not inspect this: it only checks gh issue/pr/release/gist publishes, gh api with a body, git commit and GitHub MCP writes."}
    try:
        specific = json.loads(out)["hookSpecificOutput"]
    except (ValueError, KeyError, TypeError):
        return {"error": "cannot check: the publish-guard hook answered something that is not a hook decision; nothing was checked"}
    decision = specific.get("permissionDecision")
    if decision in ("deny", "ask"):
        return {"decision": decision, "inspected": True, "explanation": specific.get("permissionDecisionReason", "")}
    note = specific.get("additionalContext", "")
    return {"decision": "allow", "inspected": True, "explanation": note or "The publish guard checked this and found nothing."}


@mcp.tool()
def check_before_publish(text_or_command: str, cwd: str = "", kind: str = "auto") -> dict:
    """Check text or a command with the publish guard BEFORE you run it. Offline; nothing is published.

    Pass either the exact shell command you are about to run (a gh issue/pr/
    release/gist publish, gh api with a body, git commit) or the text of a PR
    or issue body, comment or commit message. `kind` is "command", "text" or
    "auto" (a string that starts with gh/git/cd and a publish verb is a
    command; anything else is text). `cwd` is the directory the command would
    run in; for git commit it selects the repository whose staged diff is
    checked. Text is checked as a body file would be.

    Runs the same publish-guard.sh the session's hook runs, in the strict
    (auto) permission mode, so an ambiguous match is a deny here as it would be
    for an agent without a person. Returns {"decision": "allow"|"deny",
    "inspected": bool, "explanation": str}. On a deny the explanation says where
    each match is (source, file, line) with the line shown as the scanner
    redacts it, and what to do. It never contains the matched value. If the
    check could not run it returns {"error": ...}: that is not an allow.
    Marker semantics: guards:synthetic only covers added lines of the staged
    diff of a git commit, never the text you pass here.
    """
    if not isinstance(text_or_command, str) or not text_or_command.strip():
        return {"error": "nothing to check: text_or_command is empty"}
    if kind not in ("auto", "command", "text"):
        return {"error": 'kind must be "auto", "command" or "text"'}
    run_cwd = cwd or os.getcwd()
    if not os.path.isdir(run_cwd):
        return {"error": f"cwd is not a directory: {run_cwd}"}
    as_command = kind == "command" or (kind == "auto" and bool(_COMMAND_RE.match(text_or_command)))
    if as_command:
        result = _run_hook(text_or_command, run_cwd)
    else:
        with tempfile.TemporaryDirectory(prefix="guards-check-") as tmp:
            tmp = os.path.realpath(tmp)
            Path(tmp, "body.txt").write_text(text_or_command)
            result = _run_hook("gh issue comment 0 --body-file body.txt", tmp)
        if "explanation" in result:
            result["explanation"] = _TEXT_LABEL_RE.sub("your text", result["explanation"]).replace("from this command", "from your text")
    if os.environ.get("GUARDS_ALLOW_PUBLISH_SECRETS") == "1" and "explanation" in result:
        result["explanation"] += " Note: GUARDS_ALLOW_PUBLISH_SECRETS=1 is set in this environment, so the real hook would allow everything; this check ignored it."
    return result


if __name__ == "__main__":
    mcp.run()
