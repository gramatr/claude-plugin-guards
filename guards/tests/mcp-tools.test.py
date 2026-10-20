#!/usr/bin/env python3
"""guards/tests/mcp-tools.test.py — the agent-facing MCP tools and prompts
(mcp/guards_tools.py, registered by mcp/server.py).

No network: the guards service endpoint points at a closed port (the hook falls
back to the local scanner) and httpx is stubbed for guards_status. Repos and
files are temporary. Every credential-looking value is fabricated and built at
run time from pieces, so this file holds no literal one.

  python3 guards/tests/mcp-tools.test.py
  MCP_TOOLS_PATH=/path/to/other/guards_tools.py python3 ...   # negative control

Needs `mcp>=2`, `httpx`, `jq`, `git` (CI installs the first two). Where they are
missing a local run prints a skip; with CI=true it fails instead.
"""

import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MCP_DIR = os.path.join(HERE, "..", "mcp")
TOOLS_PATH = os.environ.get("MCP_TOOLS_PATH") or os.path.join(
    MCP_DIR, "guards_tools.py"
)

STATE = tempfile.mkdtemp(prefix="guards-tools-test-")
os.environ["GUARDS_STATE_DIR"] = STATE
os.environ["GUARDS_ENDPOINT"] = "http://127.0.0.1:9"  # closed port: local scanner only
for _k in (
    "GUARDS_ALLOW_PUBLISH_SECRETS",
    "GUARDS_PUBLISH_ASK",
    "GUARDS_ALLOW_CRED_READ",
):
    os.environ.pop(_k, None)

try:
    import httpx

    sys.path.insert(0, MCP_DIR)
    spec = importlib.util.spec_from_file_location("guards_tools_under_test", TOOLS_PATH)
    gt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gt)
    spec = importlib.util.spec_from_file_location(
        "guards_mcp_server_for_tools", os.path.join(MCP_DIR, "server.py")
    )
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)
except ImportError as exc:
    if os.environ.get("CI"):
        sys.exit(f"FAIL: cannot import the MCP server's dependencies in CI: {exc}")
    print(f"skip: {exc} (needs mcp>=2 and httpx)")
    sys.exit(0)

if not shutil.which("jq") or not shutil.which("git"):
    if os.environ.get("CI"):
        sys.exit("FAIL: jq and git are required")
    print("skip: needs jq and git")
    sys.exit(0)

# ---- fabricated values, assembled at run time -------------------------------
RAND = "q7Zk2mX9vB4nL8wR3tY6pC1sD5fG0hJa"  # 32 characters, fabricated
FAKE = RAND[:16]
PW_LINE = (
    "pass" + 'word = "' + FAKE + '"'
)  # a context-rule fixture (generic, not vendor-shaped)
VENDOR = {
    "aws": "AK" + "IA" + "ABCDEFGH" + "IJKLMNOP",
    "github": "gh" + "p_" + RAND + "ABCD",
    "slack": "xo" + "xb-" + "1234567890-" + "1234567890123-" + RAND[:24],
    "sk": "s" + "k-" + RAND + "xyz",
    "jwt": ".".join(
        [
            "ey" + "JhbGciOi" + "JIUzI1NiJ9",
            "ey" + "JzdWIiOiIx" + "MjM0NTY3ODkwIn0",
            RAND[:16],
        ]
    ),
    "pem": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "b64": "Zm9vYmFy" * 6 + "QmF6",
}
# What the scanner recognises: a PEM header always (a deterministic built-in pass); vendor token
# formats only with gitleaks, which the CI job does not have; sk- style keys and bare base64 never.
HAVE_GITLEAKS = bool(shutil.which("gitleaks"))
SCANNED = {"pem": VENDOR["pem"]}
if HAVE_GITLEAKS:
    SCANNED.update({k: VENDOR[k] for k in ("aws", "github", "slack", "jwt")})
RAW_VALUES = [FAKE, RAND, *VENDOR.values()]


def run_hook(command, cwd):
    """The publish guard exactly as the tool should call it (strict mode)."""
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
        "permission_mode": "auto",
    }
    p = subprocess.run(
        ["bash", gt.PUBLISH_HOOK],
        input=json.dumps(payload).encode(),
        capture_output=True,
        cwd=cwd,
        check=False,
    )
    out = p.stdout.decode().strip()
    if not out:
        return "allow", ""
    hso = json.loads(out)["hookSpecificOutput"]
    return hso.get("permissionDecision", "allow"), hso.get(
        "permissionDecisionReason", ""
    )


def read_hooks():
    out = {}
    for f in os.listdir(gt.HOOKS_DIR):
        with open(os.path.join(gt.HOOKS_DIR, f), "rb") as fh:
            out[f] = fh.read()
    return out


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def make_repo():
    d = tempfile.mkdtemp(prefix="guards-tools-repo-")
    sh("git", "init", "-q", cwd=d)
    sh("git", "config", "user.email", "t@example.invalid", cwd=d)
    sh("git", "config", "user.name", "t", cwd=d)
    return os.path.realpath(d)


class Base(unittest.TestCase):
    def assertValueFree(self, result, extra=()):
        blob = json.dumps(result)
        for v in (*RAW_VALUES, *extra):
            self.assertNotIn(v, blob, "a raw value leaked into a tool result")

    def tmp(self):
        d = tempfile.mkdtemp(prefix="guards-tools-t-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return os.path.realpath(d)

    def repo(self):
        d = make_repo()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d


class NegativeControl(Base):
    def test_the_leak_detector_catches_a_planted_leak(self):
        with self.assertRaises(AssertionError):
            self.assertValueFree({"line": "x " + VENDOR["github"]})
        with self.assertRaises(AssertionError):
            self.assertValueFree({"line": PW_LINE})


class CheckBeforePublish(Base):
    def matrix(self):
        repo = self.repo()
        staged_unmarked = self.repo()
        staged_marked = self.repo()
        for d, line in (
            (staged_unmarked, PW_LINE),
            (staged_marked, PW_LINE + "  # guards:synthetic"),
        ):
            with open(os.path.join(d, "fx.py"), "w") as f:
                f.write("x = 1\n" + line + "\n")
            sh("git", "add", "fx.py", cwd=d)
        bodyfile = os.path.join(repo, "body.md")
        with open(bodyfile, "w") as f:
            f.write("notes\n" + PW_LINE + "\n")
        clean = os.path.join(repo, "clean.md")
        with open(clean, "w") as f:
            f.write("notes only\n")
        return [
            ("clean text", "just a description of the change", repo, "text", "allow"),
            (
                "text with a fixture line",
                "see\n" + PW_LINE + "\n",
                repo,
                "text",
                "deny",
            ),
            ("harmless command", "echo hello", repo, "command", "allow"),
            (
                "command carrying a fake credential",
                'gh issue create --title t --body "' + PW_LINE.replace('"', "'") + '"',
                repo,
                "command",
                "deny",
            ),
            (
                "gh --body-file with a secret",
                "gh pr create --title t --body-file " + bodyfile,
                repo,
                "command",
                "deny",
            ),
            (
                "gh --body-file clean",
                "gh pr create --title t --body-file " + clean,
                repo,
                "command",
                "allow",
            ),
            (
                "git commit, fixture line unmarked",
                "git commit -m msg",
                staged_unmarked,
                "command",
                "deny",
            ),
            (
                "git commit, fixture line marked",
                "git commit -m msg",
                staged_marked,
                "command",
                "allow",
            ),
            (
                "git commit -F file, clean file, marked diff",
                "git commit -F " + clean,
                staged_marked,
                "command",
                "allow",
            ),
            (
                "git commit -F file with a secret",
                "git commit -F " + bodyfile,
                repo,
                "command",
                "deny",
            ),
        ]

    def test_matches_the_hook_on_the_same_input(self):
        for name, text, cwd, kind, expected in self.matrix():
            with self.subTest(name):
                got = gt.check_before_publish(text, cwd, kind)
                self.assertEqual(got["decision"], expected, got)
                self.assertValueFree(got)
                if kind == "command":
                    hook_dec, hook_reason = run_hook(text, cwd)
                    self.assertEqual(got["decision"], hook_dec)
                    if hook_dec == "deny":
                        self.assertEqual(
                            got["reason"],
                            hook_reason,
                            "the reason must be the hook's, verbatim",
                        )

    def test_deny_carries_the_rule_and_not_the_value(self):
        got = gt.check_before_publish("x\n" + PW_LINE + "\n", self.repo())
        self.assertEqual(got["decision"], "deny")
        self.assertIn("Blocked by guards publish-guard", got["reason"])
        self.assertIn("rule(s)", got["reason"])
        self.assertValueFree(got)

    def test_auto_detects_commands_versus_text(self):
        d = self.repo()
        self.assertIn("command", gt.check_before_publish("git status", d)["checked"])
        self.assertIn(
            "text body",
            gt.check_before_publish("an issue body that mentions git and gh", d)[
                "checked"
            ],
        )

    def test_vendor_token_in_a_command_is_denied_and_not_echoed(self):
        d = self.repo()
        for name, v in SCANNED.items():
            got = gt.check_before_publish(
                "gh issue create --title t --body 'leaked " + v + "'", d, "command"
            )
            self.assertEqual(got["decision"], "deny", name)
            self.assertValueFree(got)

    def test_a_bypass_env_is_ignored_and_noted(self):
        os.environ["GUARDS_ALLOW_PUBLISH_SECRETS"] = "1"
        try:
            got = gt.check_before_publish("x\n" + PW_LINE + "\n", self.repo())
        finally:
            os.environ.pop("GUARDS_ALLOW_PUBLISH_SECRETS")
        self.assertEqual(got["decision"], "deny")
        self.assertIn("GUARDS_ALLOW_PUBLISH_SECRETS", got["note"])

    def test_input_problems_are_unknown_never_allow(self):
        self.assertEqual(
            gt.check_before_publish("x", "/no/such/dir")["decision"], "unknown"
        )
        self.assertEqual(
            gt.check_before_publish("x", self.tmp(), "bogus")["decision"], "unknown"
        )
        real, gt.shutil.which = gt.shutil.which, lambda _n: None
        try:
            self.assertEqual(
                gt.check_before_publish("x", self.tmp())["decision"], "unknown"
            )
        finally:
            gt.shutil.which = real


class ExplainBlock(Base):
    def reason(self, text, *, with_json=False):
        if with_json:
            return json.dumps(
                {
                    "hookSpecificOutput": {
                        "permissionDecision": "deny",
                        "permissionDecisionReason": text,
                    }
                }
            )
        return text

    def test_real_deny_message_is_diagnosed_by_rule(self):
        d = self.repo()
        got = gt.check_before_publish("x\n" + PW_LINE + "\n", d)
        for with_json in (False, True):
            ex = gt.explain_block(self.reason(got["reason"], with_json=with_json))
            self.assertTrue(ex["recognized"])
            self.assertEqual(ex["guard"], "publish-guard")
            self.assertIn("secret-lead-in", ex["rules"])
            self.assertIn("guards:synthetic", " ".join(ex["next_steps"]))
            self.assertIn("does NOT apply", " ".join(ex["next_steps"]))
            self.assertValueFree(ex)

    def test_hard_rule_gets_the_runtime_fixture_advice(self):
        ex = gt.explain_block(
            "Blocked by guards publish-guard: this command would publish text that looks like it contains a credential (detector rule(s): private-key,github-pat)"
        )
        self.assertIn("private-key", ex["rules"])
        self.assertIn("run time", ex["diagnosis"] + " ".join(ex["next_steps"]))

    def test_each_known_guard_message_is_recognised(self):
        cases = {
            "did not finish in time": "publish-guard",
            "Blocked by guards publish-guard: no secret scanner could run": "publish-guard",
            "Blocked by guards credfile-guard: this would print credential material (a: b)": "credfile-guard",
            "sendmessage-guard: redacted": "sendmessage-guard",
            "guards mcp-output-guard: redacted credential material in the result of x": "mcp-output-guard",
        }
        for msg, guard in cases.items():
            full = msg if guard in msg else f"Blocked by guards {guard}: {msg}"
            ex = gt.explain_block(full)
            self.assertEqual(ex["guard"], guard, msg)
            self.assertTrue(ex["next_steps"])

    def test_never_suggests_a_bypass_and_never_echoes_input_values(self):
        ex = gt.explain_block(
            "Blocked by guards publish-guard: staged diff (detector rule(s): secret-lead-in) "
            + VENDOR["github"]
            + " "
            + FAKE
        )
        blob = json.dumps(ex)
        self.assertNotIn("export GUARDS_ALLOW", blob)
        self.assertIn("belong to the person", blob)
        self.assertValueFree(ex)

    def test_unknown_text_is_unrecognised_with_a_next_step(self):
        ex = gt.explain_block("something else entirely")
        self.assertFalse(ex["recognized"])
        self.assertTrue(ex["next_steps"])

    def test_rule_tokens_are_sanitised(self):
        ex = gt.explain_block(
            "Blocked by guards publish-guard (detector rule(s): ok-rule, "
            + "a" * 80
            + ")"
        )
        self.assertIn("ok-rule", ex["rules"])
        for r in ex["rules"]:
            self.assertRegex(r, r"^[A-Za-z0-9_.-]{1,64}$")


class PreparePublication(Base):
    def test_clean_text_writes_a_file_and_the_command(self):
        for kind, expect in (
            ("commit-message", "git commit -F "),
            ("pr-body", "gh pr create --title "),
            ("issue-body", "gh issue create --title "),
        ):
            with self.subTest(kind):
                res = gt.prepare_publication(
                    kind, "Fix the thing", "What changed and why.\n\n- one\n- two"
                )
                self.assertEqual(res["verdict"], "clean")
                self.assertTrue(res["ready"])
                self.assertTrue(res["command"].startswith(expect))
                self.assertIn(res["path"], res["command"])
                self.assertTrue(res["path"].startswith(STATE))
                self.assertEqual(oct(os.stat(res["path"]).st_mode & 0o777), "0o600")
                with open(res["path"]) as f:
                    text = f.read()
                self.assertIn("What changed and why.", text)
                if kind == "commit-message":
                    self.assertTrue(text.startswith("Fix the thing\n\n"))
                # the file the tool made is accepted by the real hook
                self.assertEqual(
                    gt.check_before_publish(res["command"], self.tmp(), "command")[
                        "decision"
                    ],
                    "allow",
                )

    def test_secret_lines_are_reported_redacted_and_never_written(self):
        body = "intro\n" + PW_LINE + "\ntail"
        res = gt.prepare_publication("pr-body", "Title", body)
        self.assertEqual(res["verdict"], "would-redact")
        self.assertFalse(res["ready"])
        self.assertEqual([r["line"] for r in res["redacted_lines"]], [2])
        self.assertIn("REDACTED", res["redacted_lines"][0]["redacted_line"])
        with open(res["path"]) as f:
            self.assertNotIn(FAKE, f.read())
        self.assertValueFree(res)

    def test_vendor_tokens_are_not_written_or_returned(self):
        for name, v in SCANNED.items():
            res = gt.prepare_publication("issue-body", "T", "see " + v + " here")
            with open(res["path"]) as f:
                self.assertNotIn(v, f.read(), name)
            self.assertValueFree(res)

    def test_a_secret_in_the_title_is_flagged_and_not_in_the_command(self):
        res = gt.prepare_publication("pr-body", "use " + PW_LINE, "body")
        self.assertTrue(res["title_would_be_redacted"])
        self.assertFalse(res["ready"])
        self.assertValueFree(res)

    def test_bad_input_is_rejected(self):
        self.assertIn("error", gt.prepare_publication("nope", "t", "b"))
        self.assertIn("error", gt.prepare_publication("pr-body", "two\nlines", "b"))
        self.assertIn("error", gt.prepare_publication("pr-body", " ", "b"))


class GuardsStatus(Base):
    def status(self, handler, *, env=None):
        real = gt.httpx.get
        gt.httpx.get = handler
        old = {k: os.environ.get(k) for k in (env or {})}
        os.environ.update(env or {})
        try:
            return gt.guards_status()
        finally:
            gt.httpx.get = real
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_service_up_reports_both_versions_and_the_hooks(self):
        req = httpx.Request("GET", "http://stub.invalid/about")
        st = self.status(
            lambda url, timeout=None: httpx.Response(
                200, json={"version": "9.9.9"}, request=req
            )
        )
        self.assertTrue(st["service"]["up"])
        self.assertEqual(st["service"]["version"], "9.9.9")
        with open(os.path.join(HERE, "..", "..", "VERSION")) as fh:
            self.assertEqual(st["plugin_version"], fh.read().strip())
        scripts = {h["script"] for h in st["hooks"]}
        self.assertTrue(
            {
                "publish-guard.sh",
                "credfile-guard.sh",
                "combined-hook.sh",
                "mcp-output-guard.sh",
                "sendmessage-guard.sh",
                "userpromptsubmit-guard.sh",
            }
            <= scripts
        )
        self.assertEqual(
            st["permission_mode_rules"]["ask_modes"], ["default", "acceptEdits", "plan"]
        )
        self.assertTrue(st["service"]["endpoint"].startswith("http://127.0.0.1:9"))

    def test_service_down_is_degraded_not_an_exception(self):
        def boom(url, timeout=None):
            raise httpx.ConnectError("refused")

        st = self.status(boom)
        self.assertFalse(st["service"]["up"])
        self.assertFalse(st["ok"])
        self.assertTrue(any("does not answer" in d for d in st["degraded"]))

    def test_non_2xx_is_down(self):
        req = httpx.Request("GET", "http://stub.invalid/about")
        st = self.status(
            lambda url, timeout=None: httpx.Response(503, text="x", request=req)
        )
        self.assertFalse(st["service"]["up"])

    def test_missing_jq_and_gitleaks_are_reported(self):
        real, gt.shutil.which = gt.shutil.which, lambda _n: None
        real_home = os.environ.get("HOME")
        os.environ["HOME"] = self.tmp()
        try:
            st = self.status(
                lambda url, timeout=None: (_ for _ in ()).throw(httpx.ConnectError("x"))
            )
        finally:
            gt.shutil.which = real
            os.environ["HOME"] = real_home
        blob = " ".join(st["degraded"])
        self.assertIn("jq is missing", blob)
        self.assertIn("gitleaks is missing", blob)

    def test_an_override_in_the_environment_is_reported(self):
        st = self.status(
            lambda url, timeout=None: (_ for _ in ()).throw(httpx.ConnectError("x")),
            env={"GUARDS_ALLOW_PUBLISH_SECRETS": "1"},
        )
        self.assertEqual(st["env_overrides"], {"GUARDS_ALLOW_PUBLISH_SECRETS": "1"})
        self.assertTrue(any("switched off" in d for d in st["degraded"]))


class MarkSynthetic(Base):
    def write(self, repo, name, text):
        p = os.path.join(repo, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_comment_syntax_by_file_type(self):
        cases = {
            "a.ts": "//",
            "a.tsx": "//",
            "a.js": "//",
            "a.jsx": "//",
            "a.go": "//",
            "a.java": "//",
            "a.rs": "//",
            "a.c": "//",
            "a.cpp": "//",
            "a.cs": "//",
            "a.swift": "//",
            "a.kt": "//",
            "a.py": "#",
            "a.sh": "#",
            "a.bash": "#",
            "a.yaml": "#",
            "a.yml": "#",
            "a.toml": "#",
            "a.rb": "#",
            "a.ini": "#",
            "a.conf": "#",
            "a.env": "#",
            ".env": "#",
            "Dockerfile": "#",
            "a.sql": "--",
            "a.lua": "--",
            "a.html": "<!--",
            "a.md": "<!--",
            "a.xml": "<!--",
        }
        for name, lead in cases.items():
            with self.subTest(name):
                self.assertTrue(
                    gt._comment_for("/r/" + name, "fake").startswith(lead), name
                )
        self.assertTrue(gt._comment_for("/r/a.html", "fake").endswith("-->"))
        self.assertIsNone(gt._comment_for("/r/a.json", "fake"))
        repo = self.repo()
        for name in ("a.ts", "a.py", "a.sql", "a.md", "Dockerfile"):
            with self.subTest(name):
                self.write(repo, name, "one\n" + PW_LINE + "\nthree\n")
                res = gt.mark_synthetic(name, [2], "fake login fixture", repo)
                self.assertEqual([c["line"] for c in res["changed"]], [2], res)
                with open(os.path.join(repo, name)) as f:
                    rows = f.read().split("\n")
                self.assertEqual((rows[0], rows[2]), ("one", "three"))
                self.assertIn("guards:synthetic", rows[1])
                self.assertValueFree(res)

    def test_the_marked_line_passes_the_hook_for_a_commit_and_the_unmarked_does_not(
        self,
    ):
        repo = self.repo()
        self.write(repo, "t.py", "x = 1\n" + PW_LINE + "\n")
        sh("git", "add", "t.py", cwd=repo)
        self.assertEqual(
            gt.check_before_publish("git commit -m m", repo)["decision"], "deny"
        )
        res = gt.mark_synthetic("t.py", [2], "fake password", repo)
        self.assertIn("changed", res, res)
        sh("git", "add", "t.py", cwd=repo)
        self.assertEqual(
            gt.check_before_publish("git commit -m m", repo)["decision"], "allow"
        )

    def test_returns_exactly_the_changed_lines_redacted(self):
        repo = self.repo()
        self.write(
            repo,
            "t.py",
            "a\n" + PW_LINE + "\nb\n" + PW_LINE + "  # guards:synthetic old\n",
        )
        res = gt.mark_synthetic("t.py", [2, 4, 2], "fake", repo)
        self.assertEqual([c["line"] for c in res["changed"]], [2])
        self.assertEqual(res["already_marked"], [4])
        self.assertIn("REDACTED", res["changed"][0]["now"])
        self.assertValueFree(res)

    def test_vendor_shaped_and_pem_lines_are_refused_and_nothing_changes(self):
        repo = self.repo()
        for name, v in VENDOR.items():
            with self.subTest(name):
                text = "ok = 1\nx = '" + v + "'\n" + PW_LINE + "\n"
                p = self.write(repo, "v.py", text)
                res = gt.mark_synthetic("v.py", [3, 2], "fake token", repo)
                self.assertIn("error", res)
                self.assertEqual(res["refused_lines"][0]["line"], 2)
                with open(p) as f:
                    self.assertEqual(
                        f.read(),
                        text,
                        "the file must be untouched when any line is refused",
                    )
                self.assertValueFree(res)

    def test_more_vendor_shapes_are_refused(self):
        repo = self.repo()
        for v in (
            "gh" + "o_" + RAND + "ABCD",
            "github" + "_pat_" + RAND + RAND,
            "AS" + "IA" + "ABCDEFGH" + "IJKLMNOP",
            "xo" + "xp-" + RAND,
            "s" + "k-" + "proj-" + RAND,
        ):
            self.write(repo, "m.py", "x = '" + v + "'\n")
            self.assertIn(
                "refused_lines", gt.mark_synthetic("m.py", [1], "fake", repo), v[:4]
            )

    def test_reason_is_required(self):
        repo = self.repo()
        p = self.write(repo, "t.py", PW_LINE + "\n")
        for bad in ("", "   ", None, "a\nb", "x" * 200, "see " + VENDOR["github"]):
            self.assertIn(
                "error", gt.mark_synthetic("t.py", [1], bad, repo), repr(bad)[:20]
            )
        with open(p) as f:
            self.assertNotIn("guards:synthetic", f.read())

    def test_paths_outside_the_repo_are_refused(self):
        repo = self.repo()
        outside = self.write(self.tmp(), "o.py", PW_LINE + "\n")
        self.assertIn("outside", gt.mark_synthetic(outside, [1], "fake", repo)["error"])
        self.assertIn(
            "outside", gt.mark_synthetic("../escape.py", [1], "fake", repo)["error"]
        )
        link = os.path.join(repo, "link.py")
        os.symlink(outside, link)
        self.assertIn(
            "outside", gt.mark_synthetic("link.py", [1], "fake", repo)["error"]
        )
        with open(outside) as f:
            self.assertNotIn("guards:synthetic", f.read())

    def test_not_a_git_repo_is_refused(self):
        d = self.tmp()
        self.write(d, "t.py", PW_LINE + "\n")
        self.assertIn(
            "git repository", gt.mark_synthetic("t.py", [1], "fake", d)["error"]
        )

    def test_bad_lines_and_types_are_refused(self):
        repo = self.repo()
        self.write(repo, "t.py", PW_LINE + "\n")
        self.write(repo, "t.json", '{"a": 1}\n')
        self.write(repo, "t.bin", "x\n")
        for lines in ([], [0], [-1], [99], ["1"], [True]):
            self.assertIn(
                "error", gt.mark_synthetic("t.py", lines, "fake", repo), lines
            )
        self.assertIn(
            "comment syntax", gt.mark_synthetic("t.json", [1], "fake", repo)["error"]
        )
        self.assertIn(
            "comment syntax", gt.mark_synthetic("t.bin", [1], "fake", repo)["error"]
        )

    def test_crlf_and_missing_final_newline_are_preserved(self):
        repo = self.repo()
        p = self.write(repo, "c.py", "a\r\n" + PW_LINE + "\r\nlast")
        gt.mark_synthetic("c.py", [2, 3], "fake", repo)
        with open(p, newline="") as f:
            data = f.read()
        self.assertTrue(data.startswith("a\r\n"))
        self.assertIn("guards:synthetic - fake\r\n", data)
        self.assertTrue(data.endswith("last  # guards:synthetic - fake"))


class ReportFalsePositive(Base):
    def test_writes_a_value_free_json_file(self):
        res = gt.report_false_positive(
            "secret-lead-in", 'password = "***REDACTED:SECRET***"', "login form fixture"
        )
        self.assertTrue(res["path"].startswith(STATE))
        with open(res["path"]) as f:
            rep = json.load(f)
        self.assertEqual(rep["rule"], "secret-lead-in")
        self.assertTrue(rep["value_free"])
        self.assertIn(res["path"], res["forward"])
        self.assertEqual(oct(os.stat(res["path"]).st_mode & 0o777), "0o600")
        self.assertNotIn("issue", res["forward"].lower().replace("issues disabled", ""))
        self.assertValueFree(res)

    def test_input_that_is_not_redacted_is_refused_and_nothing_is_written(self):
        before = (
            set(os.listdir(os.path.join(STATE, "reports")))
            if os.path.isdir(os.path.join(STATE, "reports"))
            else set()
        )
        for line in (
            PW_LINE,
            "token " + VENDOR["github"],
            "key=" + RAND + RAND,
            VENDOR["pem"],
            VENDOR["jwt"],
            VENDOR["b64"],
        ):
            res = gt.report_false_positive("generic-api-key", line, "")
            self.assertIn("error", res, line[:12])
            self.assertValueFree(res)
        res = gt.report_false_positive(
            "generic-api-key", "ok ***REDACTED***", "context " + VENDOR["github"]
        )
        self.assertIn("error", res)
        after = (
            set(os.listdir(os.path.join(STATE, "reports")))
            if os.path.isdir(os.path.join(STATE, "reports"))
            else set()
        )
        self.assertEqual(before, after)

    def test_bad_rule_and_shape_are_refused(self):
        for rule in ("", "has space", "x" * 80, "a;b"):
            self.assertIn(
                "error", gt.report_false_positive(rule, "ok ***REDACTED***", "")
            )
        self.assertIn("error", gt.report_false_positive("r", "two\nlines", ""))
        self.assertIn("error", gt.report_false_positive("r", " ", ""))


class NoToolWeakensAGuard(Base):
    def test_no_tool_or_prompt_is_a_bypass(self):
        names = [t.__name__ for t in gt.TOOLS] + [p.__name__ for p in gt.PROMPTS]
        for n in names:
            for bad in (
                "disable",
                "bypass",
                "allow",
                "override",
                "skip",
                "unguard",
                "turn_off",
                "ignore",
            ):
                self.assertNotIn(bad, n)
        with open(TOOLS_PATH) as fh:
            src = fh.read()
        self.assertNotIn(
            "GUARDS_ALLOW_PUBLISH_SECRETS=1 ",
            src.replace("GUARDS_ALLOW_PUBLISH_SECRETS=1 is set", ""),
        )

    def test_tools_do_not_modify_the_environment_or_the_hooks(self):
        env_before = dict(os.environ)
        hooks_before = read_hooks()
        repo = self.repo()
        gt.check_before_publish("hello", repo)
        gt.explain_block("Blocked by guards publish-guard: x")
        gt.prepare_publication("pr-body", "t", "b")
        gt.report_false_positive("r", "ok ***REDACTED***", "")
        self.assertEqual(env_before, dict(os.environ))
        self.assertEqual(hooks_before, read_hooks())

    def test_every_tool_scrubs_a_leak_in_its_own_result(self):
        # Backstop: even if a tool put a raw value in a result, _value_free removes it.
        leaked = {"a": {"b": ["fine", "x " + VENDOR["github"]]}, "c": "ok"}
        scrubbed = gt._value_free(leaked)
        self.assertValueFree(scrubbed)
        self.assertEqual(scrubbed["c"], "ok")
        self.assertEqual(scrubbed["a"]["b"][0], "fine")


class WrappedTools(Base):
    def test_a_tool_that_leaks_internally_is_scrubbed_on_the_way_out(self):
        real = gt._plugin_version
        gt._plugin_version = lambda: "v " + VENDOR["github"] + " " + VENDOR["jwt"]
        try:
            st = gt.guards_status()
        finally:
            gt._plugin_version = real
        self.assertValueFree(st)
        self.assertIn("REDACTED", st["plugin_version"])

    def test_every_tool_is_wrapped(self):
        for t in gt.TOOLS:
            self.assertTrue(hasattr(t, "__wrapped__"), t.__name__)


class Registration(Base):
    def test_server_registers_the_tools_and_prompts(self):
        async def go():
            tools = {t.name for t in await server.mcp.list_tools()}
            prompts = {p.name for p in await server.mcp.list_prompts()}
            return tools, prompts

        tools, prompts = asyncio.run(go())
        self.assertTrue(
            {
                "scan",
                "check_before_publish",
                "explain_block",
                "prepare_publication",
                "guards_status",
                "mark_synthetic",
                "report_false_positive",
            }
            <= tools
        )
        self.assertEqual(
            prompts & {"fix_a_block", "safe_pr_body", "fake_fixture_checklist"},
            {"fix_a_block", "safe_pr_body", "fake_fixture_checklist"},
        )

    def test_a_tool_called_through_the_server_is_value_free(self):
        async def go():
            return await server.mcp.call_tool(
                "explain_block",
                {
                    "message": "Blocked by guards publish-guard (detector rule(s): secret-lead-in) "
                    + VENDOR["github"]
                },
            )

        res = asyncio.run(go())
        self.assertValueFree(str(res))
        self.assertIn("secret-lead-in", str(res))

    def test_prompts_are_operational_and_name_the_tools(self):
        want = {
            "fix_a_block": [
                "explain_block",
                "check_before_publish",
                "prepare_publication",
                "mark_synthetic",
                "report_false_positive",
            ],
            "safe_pr_body": ["prepare_publication", "check_before_publish"],
            "fake_fixture_checklist": [
                "mark_synthetic",
                "check_before_publish",
                "guards:synthetic",
            ],
        }
        for p in gt.PROMPTS:
            text = p()
            self.assertLess(len(text), 2500)
            for needle in want[p.__name__]:
                self.assertIn(needle, text, p.__name__)
            self.assertValueFree(text)

        async def go():
            return await server.mcp.get_prompt("fix_a_block", {})

        self.assertIn("explain_block", str(asyncio.run(go())))


def tearDownModule():
    shutil.rmtree(STATE, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=0)
