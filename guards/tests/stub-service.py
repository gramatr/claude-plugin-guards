#!/usr/bin/env python3
"""guards/tests/stub-service.py — a fake guards-unified for hook tests.

  python3 -I stub-service.py DIR [DELAY_SECONDS] [MAX_BYTES]

Serves POST /v1/scan and /v1/scan/secret on a free localhost port and writes
that port to DIR/port. Each request is logged to DIR/requests as
"PATH BYTES". Fabricated markers in the text drive the answer:

  STUBSECRET123  secret finding, redacted_text has it replaced
  STUBPII        pii finding (PERSON), combined redacted_text has <PERSON>
  STUBINJECT     injection verdict malicious

MAX_BYTES (default unlimited) mimics the real 413 on oversize text; DELAY
sleeps before answering. Nothing here scans anything for real.
"""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

out_dir = sys.argv[1]
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0
max_bytes = int(sys.argv[3]) if len(sys.argv) > 3 else 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        text = json.loads(raw or b"{}").get("text", "")
        size = len(text.encode())
        with open(f"{out_dir}/requests", "a") as log:
            log.write(f"{self.path} {size}\n")
        if max_bytes and size > max_bytes:
            detail = {
                "error": "text_too_large",
                "bytes": size,
                "limit_bytes": max_bytes,
                "setting": "SCAN_FULL_MAX_BYTES",
            }
            return self.reply(413, {"detail": detail})
        time.sleep(delay)
        secret = {
            "type": "secret",
            "verdict": "clean",
            "reason_code": None,
            "detail": {},
        }
        redacted = text
        if "STUBSECRET123" in text:
            redacted = text.replace("STUBSECRET123", "***REDACTED:SECRET***")
            secret = {
                "type": "secret",
                "verdict": "found",
                "reason_code": ["SECRET_STUB"],
                "detail": {"redacted_text": redacted},
            }
        has_pii = "STUBPII" in text
        pii = {
            "type": "pii",
            "verdict": "found" if has_pii else "clean",
            "reason_code": None,
            "detail": {"entities": [{"entity_type": "PERSON"}] if has_pii else []},
        }
        inj = {
            "type": "injection",
            "verdict": "malicious" if "STUBINJECT" in text else "clean",
            "reason_code": None,
            "detail": {"score": 0.99},
        }
        combined = redacted.replace("STUBPII", "<PERSON>")
        self.reply(200, {"findings": [secret, pii, inj], "redacted_text": combined})


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(f"{out_dir}/port", "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
