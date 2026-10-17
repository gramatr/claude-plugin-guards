#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=2", "httpx"]
# ///
"""
guards/mcp/server.py — MCP front-end for explicit tool-call access to
secret-guard, pii-guard, and injection-guard.

Fulfills injection-guard's own README roadmap item: "MCP server
front-end for explicit tool-call access (vs. automatic hook-based
gating only)."

Three INDEPENDENT tools, not a pipeline. combined-hook.sh sequences the
three guards internally for a specific, unrelated reason: Claude Code's
PostToolUse hooks run in parallel with undefined resolution order when
more than one tries to rewrite the same tool's output, so that script
chains them to produce one deterministic rewrite. That constraint does
not apply here — an MCP tool call is explicit and standalone, so each
tool below is a direct, independent call to its own daemon. Call one,
two, or all three, in any order; none of them know about or depend on
the others.

No new detection logic — this is a protocol adapter only. Same
fail-explicit posture as an interactive tool call deserves: unlike the
hooks (which fail OPEN and pass tool output through unchanged so a
session never silently stalls), a daemon that's unreachable here
returns an explicit {"error": ...} rather than a false "clean" result,
because the caller asked for a scan and deserves to know it didn't
happen rather than assume it passed.
"""

import os

import httpx
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("guards")

SECRET_GUARD_ENDPOINT = os.environ.get("SECRET_GUARD_ENDPOINT", "http://127.0.0.1:8732")
PII_GUARD_ENDPOINT = os.environ.get("PII_GUARD_ENDPOINT", "http://127.0.0.1:8731")
INJECTION_GUARD_ENDPOINT = os.environ.get("INJECTION_GUARD_ENDPOINT", "http://127.0.0.1:8730")
INJECTION_GUARD_AUTH_TOKEN = os.environ.get("INJECTION_GUARD_AUTH_TOKEN", "")


def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
    try:
        resp = httpx.post(url, json=payload, headers=headers or {}, timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": f"guard unreachable at {url}: {e}"}


@mcp.tool()
def scan_secrets(text: str) -> dict:
    """Scan text for live credentials (AWS keys, GitHub/GitLab/Slack tokens, Stripe keys, etc.) via secret-guard.

    Returns {"found": bool, "redacted_text": str} on success, or
    {"error": str} if secret-guard's daemon is unreachable — callers
    must not treat an error as "clean."
    """
    return _post(f"{SECRET_GUARD_ENDPOINT}/scan", {"text": text})


@mcp.tool()
def scan_pii(text: str) -> dict:
    """Scan text for personal data (names, emails, SSNs, phone numbers, etc.) via pii-guard.

    Returns {"found": bool, "redacted_text": str} on success, or
    {"error": str} if pii-guard's daemon is unreachable. Note:
    pii-guard's measured recall is 78.8% and it only covers Presidio's
    entity set — ~63% of PII in one real-world sample fell outside
    that coverage. Not exhaustive; treat a "not found" result as
    "not found by this entity set," not "confirmed absent."
    """
    return _post(f"{PII_GUARD_ENDPOINT}/analyze", {"text": text})


@mcp.tool()
def classify_injection(text: str) -> dict:
    """Classify text for jailbreak/direct-override prompt-injection attempts via injection-guard.

    Returns {"malicious": bool, "score": float} on success, or
    {"error": str} if injection-guard's daemon is unreachable.

    SCOPE, stated plainly because the underlying model's own vendor
    documentation states it this way: this detects explicit attempts
    to override prior instructions or safety behavior (jailbreaks,
    persona hijacks). It is NOT a reliable control for indirect
    injection — malicious instructions embedded in data an agent reads
    that don't use override language. Measured recall on that case
    (InjecAgent, real tool-output injections) is 6%. Do not rely on a
    "not malicious" result as a safety guarantee for content an agent
    is about to act on.
    """
    headers = {}
    if INJECTION_GUARD_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {INJECTION_GUARD_AUTH_TOKEN}"
    return _post(f"{INJECTION_GUARD_ENDPOINT}/classify", {"text": text}, headers)


if __name__ == "__main__":
    mcp.run()
