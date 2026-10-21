#!/usr/bin/env python3
"""guards/tests/capture-listener.py — a localhost HTTP listener that records requests.

  python3 -I capture-listener.py DIR

Listens on a free 127.0.0.1 port and writes that port to DIR/port. Each request
is recorded as three files, N counting up from 1:

  DIR/req.N.path   request line target
  DIR/req.N.hdr    one "Name: value" line per header
  DIR/req.N.body   raw body bytes

Paths:

  /fast   answer 200 at once
  /slow   record, create DIR/inflight, hold the connection for HOLD seconds, so a
          test can read the client's /proc/<pid>/cmdline while it is running
  /auth   answer 401 with a Basic challenge until an Authorization header
          arrives (clients such as wget send netrc/askpass credentials only
          after a challenge), then behave like /slow

Used by outbound-safeforms.test.sh with fabricated values only. It checks
nothing and answers every request the same way.
"""

import os
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


HOLD = 1.5
out_dir = sys.argv[1]
count = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def record(self):
        global count
        count += 1
        n = count
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        base = os.path.join(out_dir, f"req.{n}")
        with open(base + ".path", "w") as f:
            f.write(self.path)
        with open(base + ".hdr", "w") as f:
            f.writelines(f"{name}: {value}\n" for name, value in self.headers.items())
        with open(base + ".body", "wb") as f:
            f.write(body)

    def answer(self, status, extra=None):
        self.send_response(status)
        for name, value in extra or []:
            self.send_header(name, value)
        self.send_header("Content-Length", "3" if status == 200 else "0")
        self.end_headers()
        if status == 200:
            self.wfile.write(b"ok\n")

    def handle_any(self):
        self.record()
        if self.path.startswith("/auth") and not self.headers.get("Authorization"):
            self.answer(401, [("WWW-Authenticate", 'Basic realm="test"')])
            return
        if self.path.startswith(("/slow", "/auth")):
            open(os.path.join(out_dir, "inflight"), "w").close()
            time.sleep(HOLD)
        self.answer(200)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any


server = Quiet(("127.0.0.1", 0), Handler)
with open(os.path.join(out_dir, "port.tmp"), "w") as f:
    f.write(str(server.server_address[1]))
os.rename(os.path.join(out_dir, "port.tmp"), os.path.join(out_dir, "port"))
server.serve_forever()
