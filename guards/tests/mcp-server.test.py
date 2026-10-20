#!/usr/bin/env python3
"""guards/tests/mcp-server.test.py — the plugin's MCP `scan` tool (mcp/server.py).

The HTTP client is stubbed, so no service is needed. Every outcome that is not
a real scan result must come back as {"error": ...} and never as something that
looks clean. All values are fabricated.

  python3 guards/tests/mcp-server.test.py
  MCP_SERVER_PATH=/path/to/other/server.py python3 ...   # negative control

Needs `mcp>=2` and `httpx` (CI installs them). Where they are missing, a local
run prints a skip; with CI=true it fails instead.
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
PATH = os.environ.get("MCP_SERVER_PATH") or os.path.join(HERE, "..", "mcp", "server.py")

try:
    import httpx

    spec = importlib.util.spec_from_file_location("guards_mcp_server", PATH)
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)
except ImportError as exc:
    if os.environ.get("CI"):
        sys.exit(f"FAIL: cannot import the MCP server's dependencies in CI: {exc}")
    print(f"skip: {exc} (needs mcp>=2 and httpx)")
    sys.exit(0)

REQUEST = httpx.Request("POST", "http://stub.invalid/v1/scan")
CLEAN = {
    "findings": [
        {"type": "secret", "verdict": "clean", "reason_code": None, "detail": {}},
        {"type": "pii", "verdict": "clean", "reason_code": None, "detail": {}},
        {"type": "injection", "verdict": "clean", "reason_code": None, "detail": {}},
    ],
    "redacted_text": "hello",
}


def run(coro):
    return asyncio.run(coro)


def reply(status, body=None, text=None):
    if text is not None:
        return httpx.Response(status, text=text, request=REQUEST)
    return httpx.Response(status, json=body, request=REQUEST)


class ScanTool(unittest.TestCase):
    def call(self, outcome, text="hello"):
        """Run scan() with httpx.post stubbed to return or raise `outcome`."""
        seen = {}

        def fake_post(url, json=None, timeout=None):
            seen.update(url=url, json=json, timeout=timeout)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        real, httpx.post = httpx.post, fake_post
        try:
            return server.scan(text), seen
        finally:
            httpx.post = real

    def assertError(self, result):
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertNotIn("findings", result)
        self.assertNotIn("redacted_text", result)

    def test_200_returns_the_scan_result_unchanged(self):
        result, seen = self.call(reply(200, CLEAN))
        self.assertEqual(result, CLEAN)
        self.assertTrue(seen["url"].endswith("/v1/scan"))
        self.assertEqual(seen["json"], {"text": "hello"})

    def test_200_with_a_secret_finding_is_passed_through(self):
        found = {
            "findings": [{"type": "secret", "verdict": "found", "detail": {}}],
            "redacted_text": "x",
        }
        result, _ = self.call(reply(200, found))
        self.assertEqual(result, found)

    def test_413_reports_status_limit_and_setting(self):
        detail = {
            "error": "text_too_large",
            "bytes": 70000,
            "limit_bytes": 65536,
            "setting": "SCAN_FULL_MAX_BYTES",
        }
        result, _ = self.call(reply(413, {"detail": detail}))
        self.assertError(result)
        msg = result["error"]
        self.assertIn("413", msg)
        self.assertIn("65536", msg)
        self.assertIn("SCAN_FULL_MAX_BYTES", msg)
        self.assertNotIn("unreachable", msg)

    def test_413_without_a_parsable_body_still_names_the_status(self):
        result, _ = self.call(reply(413, text="Request Entity Too Large"))
        self.assertError(result)
        self.assertIn("413", result["error"])
        self.assertNotIn("unreachable", result["error"])

    def test_500_reports_the_status_not_unreachable(self):
        result, _ = self.call(reply(500, text="boom"))
        self.assertError(result)
        self.assertIn("500", result["error"])
        self.assertNotIn("unreachable", result["error"])

    def test_other_non_2xx_is_an_error(self):
        for status in (400, 401, 404, 422, 503):
            result, _ = self.call(reply(status, {"detail": "nope"}))
            self.assertError(result)
            self.assertIn(str(status), result["error"])

    def test_200_that_is_not_a_scan_result_is_an_error(self):
        for bad in (
            reply(200, text="<html>proxy</html>"),
            reply(200, {}),
            reply(200, {"findings": None}),
            reply(200, [1]),
        ):
            result, _ = self.call(bad)
            self.assertError(result)

    def test_timeout_says_unreachable(self):
        result, _ = self.call(httpx.ReadTimeout("timed out"))
        self.assertError(result)
        self.assertIn("unreachable", result["error"])

    def test_connection_refused_says_unreachable(self):
        result, _ = self.call(httpx.ConnectError("connection refused"))
        self.assertError(result)
        self.assertIn("unreachable", result["error"])
        self.assertIn(server.GUARDS_ENDPOINT, result["error"])

    def test_result_is_json_serializable(self):
        for outcome in (
            reply(200, CLEAN),
            reply(413, {"detail": {"bytes": 1, "limit_bytes": 0, "setting": "S"}}),
            httpx.ConnectError("x"),
        ):
            json.dumps(self.call(outcome)[0])


GUIDE_URIS = [
    "guards://guide/publishing",
    "guards://guide/false-positives",
    "guards://guide/hooks",
    "guards://guide/diagnosing-a-block",
]


class Instructions(unittest.TestCase):
    """The server instructions land in the agent's system prompt: short, and carrying the three rules."""

    def test_short_enough_for_a_system_prompt(self):
        self.assertLessEqual(len(server.INSTRUCTIONS.split()), 150)
        self.assertEqual(server.mcp.instructions, server.INSTRUCTIONS)

    def test_carries_the_rules_and_the_pointers(self):
        text = server.INSTRUCTIONS
        for needle in (
            "guards:synthetic",
            "SAME line",
            "staged diff",
            "Never put a real credential",
            "Never disable",
            "false positive",
            "check_before_publish",
        ):
            self.assertIn(needle, text)
        for uri in GUIDE_URIS:
            self.assertIn(uri, text)

    def test_reaches_a_client_over_stdio(self):
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:  # pragma: no cover
            self.skipTest(f"mcp client not importable: {exc}")

        async def go():
            params = StdioServerParameters(
                command=sys.executable,
                args=[PATH],
                env={**os.environ, "GUARDS_ENDPOINT": "http://127.0.0.1:1"},
            )
            async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
                init = await session.initialize()
                uris = [str(x.uri) for x in (await session.list_resources()).resources]
                tools = [t.name for t in (await session.list_tools()).tools]
                return init.instructions, uris, tools

        instructions, uris, tools = asyncio.run(asyncio.wait_for(go(), 60))
        self.assertEqual(instructions, server.INSTRUCTIONS)
        self.assertEqual(sorted(uris), sorted(GUIDE_URIS))
        self.assertIn("check_before_publish", tools)
        self.assertIn("scan", tools)


class Resources(unittest.TestCase):
    def read(self, uri):
        parts = run(server.mcp.read_resource(uri))
        return "".join(p.content for p in parts)

    def test_the_four_guides_are_listed(self):
        listed = [str(r.uri) for r in run(server.mcp.list_resources())]
        self.assertEqual(sorted(listed), sorted(GUIDE_URIS))

    def test_each_guide_reads_as_nonempty_markdown(self):
        for uri in GUIDE_URIS:
            text = self.read(uri)
            self.assertTrue(text.startswith("# "), uri)
            self.assertGreater(len(text), 500, uri)

    def test_the_marker_scope_is_stated_in_the_false_positive_guide(self):
        text = self.read("guards://guide/false-positives")
        for needle in (
            "guards:synthetic",
            "SAME line",
            "ONLY the added lines of the staged diff of a git commit",
            "-m message",
            "--body-file",
            "STARTED",
            "does nothing",
        ):
            self.assertIn(needle, text)

    def test_the_publishing_guide_matches_the_hook_defaults(self):
        text = self.read("guards://guide/publishing")
        for needle in (
            "512 KB",
            "git commit",
            "gh api",
            "auto, bypassPermissions and dontAsk",
            "check_before_publish",
        ):
            self.assertIn(needle, text)

    def test_the_guides_do_not_trip_the_scanner_themselves(self):
        scan_sh = os.path.join(HERE, "..", "vendor", "secret-guard-core", "scan.sh")
        for uri in GUIDE_URIS + [None]:
            text = server.INSTRUCTIONS if uri is None else self.read(uri)
            out = subprocess.run(
                ["bash", scan_sh],
                input=text,
                capture_output=True,
                text=True,
                env={**os.environ, "GUARDS_ENDPOINT": "http://127.0.0.1:1"},
                check=False,
            ).stdout
            self.assertEqual(
                out,
                text,
                f"the scanner would redact part of {uri or 'the instructions'}",
            )


FAKE = "Zq8xK2mNp4LwTd9v"  # guards:synthetic


@unittest.skipUnless(
    shutil.which("bash") and shutil.which("jq") and shutil.which("git"),
    "needs bash, jq and git",
)
class CheckBeforePublish(unittest.TestCase):
    """The real publish-guard.sh, run through the tool, in throwaway repositories."""

    def setUp(self):
        self._env = dict(os.environ)
        os.environ["GUARDS_ENDPOINT"] = (
            "http://127.0.0.1:1"  # hermetic: no service, the local scanner runs
        )
        os.environ.pop("GUARDS_ALLOW_PUBLISH_SECRETS", None)
        os.environ.pop("GUARDS_PUBLISH_GUARD_HOOK", None)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def repo(self, name="repo"):
        d = os.path.join(self.tmp, name)
        os.makedirs(d)

        def git(*a):
            return subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)

        git("init", "-q", ".")
        git("config", "user.email", "t@example.invalid")
        git("config", "user.name", "t")
        with open(os.path.join(d, "README.md"), "w") as f:
            f.write("base\n")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        return d, git

    def assertNoValue(self, result):
        self.assertNotIn(FAKE, json.dumps(result))

    def test_text_with_a_credential_is_denied_with_the_line_located_and_redacted(self):
        text = f"Steps to reproduce\nDB_PASSWORD={FAKE}\nthen it failed"
        result = server.check_before_publish(text, kind="text")
        self.assertEqual(result["decision"], "deny")
        self.assertTrue(result["inspected"])
        self.assertIn(
            "your text, line 2: DB_PASSWORD=***REDACTED:SECRET***",
            result["explanation"],
        )
        self.assertIn("guards:synthetic", result["explanation"])
        self.assertNoValue(result)

    def test_clean_text_is_allowed_and_marked_inspected(self):
        result = server.check_before_publish(
            "The login flow fails after the token expires."
        )
        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["inspected"])
        self.assertIn("from your text", result["explanation"])

    def test_the_marker_does_not_excuse_text(self):
        result = server.check_before_publish(
            f"DB_PASSWORD={FAKE} # guards:synthetic", kind="text"
        )
        self.assertEqual(result["decision"], "deny")
        self.assertNoValue(result)

    def test_a_command_that_is_not_a_publish_is_allowed_but_not_inspected(self):
        result = server.check_before_publish("ls -la", kind="command")
        self.assertEqual(result["decision"], "allow")
        self.assertFalse(result["inspected"])

    def test_a_commit_is_checked_against_the_staged_diff_of_the_given_directory(self):
        d, git = self.repo()
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "cfg.ts"), "w") as f:
            f.write(f'a = 1\ndb_password: "{FAKE}"\n')
        git("add", "-A")
        result = server.check_before_publish('git commit -m "add cfg"', cwd=d)
        self.assertEqual(result["decision"], "deny")
        self.assertIn(
            'the staged diff, file src/cfg.ts, line 2: db_password: "***REDACTED:SECRET***"',
            result["explanation"],
        )
        self.assertNoValue(result)
        # the marker on the same line is honoured for the staged diff
        with open(os.path.join(d, "src", "cfg.ts"), "w") as f:
            f.write(f'a = 1\ndb_password: "{FAKE}" // guards:synthetic\n')
        git("add", "-A")
        result = server.check_before_publish('git commit -m "add cfg"', cwd=d)
        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["inspected"])

    def test_an_inline_override_does_not_change_the_answer(self):
        d, git = self.repo()
        with open(os.path.join(d, "cfg.ts"), "w") as f:
            f.write(f'db_password: "{FAKE}"\n')
        git("add", "-A")
        result = server.check_before_publish(
            "GUARDS_ALLOW_PUBLISH_SECRETS=1 git commit -m x", cwd=d
        )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("does nothing", result["explanation"])
        self.assertNoValue(result)

    def test_the_session_override_is_ignored_and_reported(self):
        os.environ["GUARDS_ALLOW_PUBLISH_SECRETS"] = "1"
        result = server.check_before_publish(f"DB_PASSWORD={FAKE}", kind="text")
        self.assertEqual(result["decision"], "deny")
        self.assertIn(
            "GUARDS_ALLOW_PUBLISH_SECRETS=1 is set in this environment",
            result["explanation"],
        )
        self.assertNoValue(result)

    def test_a_private_key_never_comes_back(self):
        key = subprocess.run(
            ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        if not key:
            self.skipTest("openssl cannot make a throwaway key")
        body = key.splitlines()[1]
        result = server.check_before_publish("Here is the key:\n" + key, kind="text")
        self.assertEqual(result["decision"], "deny")
        self.assertNotIn(body, json.dumps(result))

    def test_a_hook_that_cannot_run_is_an_error_never_an_allow(self):
        os.environ["GUARDS_PUBLISH_GUARD_HOOK"] = os.path.join(self.tmp, "missing.sh")
        result = server.check_before_publish("hello", kind="text")
        self.assertIn("error", result)
        self.assertEqual(result["decision"], "unknown")
        crash = os.path.join(self.tmp, "crash.sh")
        with open(crash, "w") as f:
            f.write("#!/usr/bin/env bash\nexit 7\n")
        os.environ["GUARDS_PUBLISH_GUARD_HOOK"] = crash
        result = server.check_before_publish("hello", kind="text")
        self.assertIn("error", result)
        self.assertEqual(result["decision"], "unknown")
        junk = os.path.join(self.tmp, "junk.sh")
        with open(junk, "w") as f:
            f.write("#!/usr/bin/env bash\necho 'not json'\n")
        os.environ["GUARDS_PUBLISH_GUARD_HOOK"] = junk
        result = server.check_before_publish("hello", kind="text")
        self.assertIn("error", result)
        self.assertEqual(result["decision"], "unknown")

    def test_bad_arguments_are_errors(self):
        self.assertIn("error", server.check_before_publish("   "))
        self.assertIn("error", server.check_before_publish("x", kind="nope"))
        self.assertIn(
            "error",
            server.check_before_publish("x", cwd=os.path.join(self.tmp, "no-such-dir")),
        )

    def test_the_result_is_json_serializable(self):
        json.dumps(server.check_before_publish(f"DB_PASSWORD={FAKE}", kind="text"))


if __name__ == "__main__":
    unittest.main(verbosity=0)
