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
"""

import os

import httpx
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("guards")

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


if __name__ == "__main__":
    mcp.run()
