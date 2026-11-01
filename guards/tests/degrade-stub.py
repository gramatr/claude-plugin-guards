#!/usr/bin/env python3
"""guards/tests/degrade-stub.py — a fake guards-unified that fails in one chosen way.

  python3 -I degrade-stub.py DIR MODE [DELAY_SECONDS]

Serves GET /health, GET /about, POST /v1/scan and POST /v1/scan/secret on a free
localhost port and writes that port to DIR/port. Each request is logged to
DIR/requests as "METHOD PATH BYTES" (never the text). MODE picks the failure:

  up           every axis answers, nothing found
  slow         every route sleeps DELAY seconds first, then answers like "up"
  axiserr      the PII and injection axes answer verdict "error" (no reason code);
               the secret axis is fine
  unavailable  like axiserr but the axes carry the stable reason codes
               PII_UNAVAILABLE / INJECTION_UNAVAILABLE, and /about lists the axes
  secerr       the secret axis answers verdict "error" (SECRET_SCAN_TIMEOUT)
  http500      every route answers 500
  malformed    every route answers 200 with a body that is not a scan result

Fabricated markers in the text drive a finding in the modes that scan:
STUBSECRET123 is a secret (redacted), STUBPII is a PERSON, STUBINJECT is malicious.
It exists for the degraded-service tests and degrade-bench.sh; nothing here
scans anything for real.
"""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Quiet(ThreadingHTTPServer):
    # HTTPServer.server_bind calls socket.getfqdn(), a reverse DNS lookup that takes ~35 s on the
    # GitHub macOS runner; a test stub on 127.0.0.1 needs no name.
    def server_bind(self):
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


out_dir = sys.argv[1]
mode = sys.argv[2]
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0

AXES = {
    "pii": {"state": "ok", "reason_code": None},
    "injection": {"state": "ok", "reason_code": None},
}
if mode == "unavailable":
    AXES["injection"] = {"state": "unavailable", "reason_code": "INJECTION_UNAVAILABLE"}


def secret_finding(text):
    if mode == "secerr":
        return {
            "type": "secret",
            "verdict": "error",
            "reason_code": ["SECRET_SCAN_TIMEOUT"],
            "detail": {"error": "timeout"},
        }
    if "STUBSECRET123" in text:
        red = text.replace("STUBSECRET123", "***REDACTED:SECRET***")
        return {
            "type": "secret",
            "verdict": "found",
            "reason_code": ["SECRET_STUB"],
            "detail": {"redacted_text": red},
        }
    return {"type": "secret", "verdict": "clean", "reason_code": None, "detail": {}}


def model_finding(kind, text):
    if mode in ("axiserr", "unavailable"):
        code = None
        if mode == "unavailable":
            code = [f"{kind.upper()}_UNAVAILABLE"]
        if mode == "axiserr" or kind == "injection":
            return {
                "type": kind,
                "verdict": "error",
                "reason_code": code,
                "detail": {"error": "stub"},
            }
    if kind == "pii":
        hit = "STUBPII" in text
        ents = [{"entity_type": "PERSON"}] if hit else []
        return {
            "type": "pii",
            "verdict": "found" if hit else "clean",
            "reason_code": None,
            "detail": {"entities": ents, "redacted_text": text},
        }
    hit = "STUBINJECT" in text
    return {
        "type": "injection",
        "verdict": "malicious" if hit else "clean",
        "reason_code": None,
        "detail": {"score": 0.99, "chunks_scanned": 1},
    }


class Handler(BaseHTTPRequestHandler):
    # Keep the base signature; the stub logs nothing.
    def log_message(self, format, *args):
        return None

    def reply(self, status, body):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log(self, size):
        with open(f"{out_dir}/requests", "a") as f:
            f.write(f"{self.command} {self.path} {size}\n")

    def do_GET(self):
        self.log(0)
        if mode == "http500":
            return self.reply(500, {"detail": "stub"})
        if self.path == "/about":
            return self.reply(
                200,
                {"service": "guards-unified", "version": "stub", "axes": AXES}
                if mode == "unavailable"
                else {"service": "guards-unified", "version": "stub"},
            )
        return self.reply(200, {"status": "ok"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        text = json.loads(raw or b"{}").get("text", "")
        self.log(len(text.encode()))
        if mode == "http500":
            return self.reply(500, {"detail": "stub"})
        if mode == "malformed":
            return self.reply(200, b'{"unexpected": true}')
        if mode == "slow":
            time.sleep(delay)
        secret = secret_finding(text)
        red = (
            secret["detail"].get("redacted_text", text)
            if secret["verdict"] == "found"
            else text
        )
        if self.path == "/v1/scan/secret":
            return self.reply(200, {"findings": [secret], "redacted_text": red})
        findings = [
            secret,
            model_finding("pii", text),
            model_finding("injection", text),
        ]
        return self.reply(200, {"findings": findings, "redacted_text": red})


server = Quiet(("127.0.0.1", 0), Handler)
with open(f"{out_dir}/port", "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
