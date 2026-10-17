#!/usr/bin/env python3
"""guards/vendor/secret-guard-core/server.py

Minimal HTTP wrapper around scan.sh so secret-guard presents the same
kind of service interface as pii-guard-daemon and injection-guard-daemon
(resident process, POST /scan, /health) instead of being the odd one
out as a bare script invoked directly by the hook.

Deliberately NOT a daemon in the "loads an expensive model once" sense
secret-guard's siblings are — gitleaks is a fast, zero-model pattern
scanner, so there is no warm-state benefit here. This exists purely for
interface consistency (one Docker Compose stack, one HTTP shape across
all three guards), not because scan.sh needed to become resident.

No text is logged, cached, or persisted anywhere by this process —
scan.sh already discards its temp files on exit (see its own trap), and
this wrapper never writes the request body to disk or to its own
stdout/stderr (only scan.sh's own stderr finding summary, which never
contains the matched value, passes through).
"""
import http.server
import json
import os
import subprocess
import sys

HOST = os.environ.get("SECRET_GUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECRET_GUARD_PORT", "8732"))
SCAN_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.sh")


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/scan":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            text = json.loads(raw).get("text", "") if raw else ""
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        try:
            result = subprocess.run(
                [SCAN_SH],
                input=text,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            # Fail open: scan.sh itself fails open on missing deps; a
            # timeout gets the same treatment rather than blocking the
            # caller indefinitely.
            self._json(200, {"found": False, "redacted_text": text})
            return

        redacted = result.stdout
        # scan.sh captures its working text via bash command substitution
        # ($(cat ...)), which unconditionally strips trailing newlines —
        # so a clean input with a trailing newline comes back one
        # byte shorter even though nothing was redacted. Compare with
        # trailing newlines stripped on both sides (found by testing
        # against secret-guard's own clean.txt fixture, which triggered
        # a false "found": true before this fix).
        found = redacted.rstrip("\n") != text.rstrip("\n")
        self._json(200, {"found": found, "redacted_text": redacted})

    def log_message(self, format, *args):
        # Default BaseHTTPRequestHandler logging writes the request
        # line (method + path + status) to stderr — never the body, so
        # no scanned text reaches a log line. Kept, not silenced,
        # because request-shape logging without content is fine and
        # useful for operational visibility.
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))


def main():
    if not os.access(SCAN_SH, os.X_OK):
        os.chmod(SCAN_SH, 0o755)
    server = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write(f"secret-guard-server: listening on {HOST}:{PORT}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
