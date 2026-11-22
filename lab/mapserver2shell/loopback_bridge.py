#!/usr/bin/env python3
"""Loopback-only HTTP -> CGI bridge for the mapserv PoC. Binds 127.0.0.1 only."""
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("MAPSERV_BIN", os.path.join(HERE, "build-asan2", "mapserv"))
PORT = int(os.environ.get("PORT", "8077"))
STDERR_LOG = os.path.join(HERE, "bridge-child-stderr.log")

BASE_ENV = dict(os.environ)
BASE_ENV.update(
    MAPSERVER_CONFIG_FILE=os.path.join(HERE, "mapserver.conf"),
    MS_MAP_PATTERN="^/",
    ASAN_OPTIONS="detect_leaks=0:symbolize=1:abort_on_error=0",
    GATEWAY_INTERFACE="CGI/1.1",
    SERVER_SOFTWARE="lab-loopback-bridge/1.0",
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        path, _, query = self.path.partition("?")
        env = dict(BASE_ENV)
        env.update(
            REQUEST_METHOD="GET",
            QUERY_STRING=query,
            SCRIPT_NAME="/mapserv",
            PATH_INFO="",
            SERVER_NAME="127.0.0.1",
            SERVER_PORT=str(PORT),
            SERVER_PROTOCOL="HTTP/1.1",
            REMOTE_ADDR="127.0.0.1",
        )
        try:
            proc = subprocess.run([BIN], env=env, capture_output=True, timeout=30)
        except Exception as exc:  # noqa: BLE001 - bridge reports child failure
            self.send_error(500, f"mapserv exec failed: {exc}")
            return
        with open(STDERR_LOG, "ab") as log:
            log.write(
                f"\n=== path={path!r} rc={proc.returncode} ===\n".encode()
                + proc.stderr
            )
        head, sep, body = proc.stdout.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = proc.stdout.partition(b"\n\n")
        if not sep:
            head, body = b"", proc.stdout
        self.send_response(200 if proc.returncode == 0 else 500)
        for line in head.splitlines():
            if b":" in line:
                key, value = line.split(b":", 1)
                self.send_header(key.decode().strip(), value.decode().strip())
        self.send_header("X-Lab-Child-Rc", str(proc.returncode))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("bridge: " + (fmt % args) + "\n")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"listening on 127.0.0.1:{PORT} -> {BIN}", flush=True)
    srv.serve_forever()
