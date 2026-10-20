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
import importlib.util
import json
import os
import sys
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
        found = {"findings": [{"type": "secret", "verdict": "found", "detail": {}}], "redacted_text": "x"}
        result, _ = self.call(reply(200, found))
        self.assertEqual(result, found)

    def test_413_reports_status_limit_and_setting(self):
        detail = {"error": "text_too_large", "bytes": 70000, "limit_bytes": 65536, "setting": "SCAN_FULL_MAX_BYTES"}
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
        for bad in (reply(200, text="<html>proxy</html>"), reply(200, {}), reply(200, {"findings": None}), reply(200, [1])):
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
        for outcome in (reply(200, CLEAN), reply(413, {"detail": {"bytes": 1, "limit_bytes": 0, "setting": "S"}}), httpx.ConnectError("x")):
            json.dumps(self.call(outcome)[0])


if __name__ == "__main__":
    unittest.main(verbosity=0)
