#!/usr/bin/env python3
"""Lab-only loopback upload service for the CVE-2026-125396 rung-5 chain.

Accepts an attacker-controlled request body containing a PostScript document
and a Type 1 font, saves them under a permitted upload directory, then runs the
lab Ghostscript binary on the saved document with -dSAFER. Nothing here binds
off 127.0.0.1 or contacts any external system. Configuration (gs binary, marker
path, upload root) comes from the harness environment, not from the request.
"""

import base64
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

GS_BIN = os.environ["GS_BIN"]
MARKER = os.environ["R5_MARKER"]
UPLOAD_ROOT = Path(os.environ["R5_UPLOAD_ROOT"])
PORT = int(sys.argv[1])
REQUEST = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"service": "ghostscript2shell-r5-lab", "safer": True})

    def do_POST(self):
        global REQUEST
        if self.path != "/upload":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 4_000_000:
            self._send(400, {"error": "bad length"})
            return
        try:
            body = json.loads(self.rfile.read(length))
            doc = base64.b64decode(body["doc"], validate=True)
            font = base64.b64decode(body["font"], validate=True)
        except (ValueError, KeyError, TypeError):
            self._send(400, {"error": "bad body"})
            return

        REQUEST += 1
        directory = UPLOAD_ROOT / f"request-{REQUEST:04d}"
        directory.mkdir(parents=True, exist_ok=True)

        docpath = directory / "document.ps"
        fontpath = directory / "font.pfa"
        docpath.write_bytes(doc)
        fontpath.write_bytes(font)

        cmd = [
            GS_BIN, "-q", "-dNODISPLAY", "-dSAFER",
            f"--permit-file-read={directory}/*",
            f"-sR5_FONT_PATH={fontpath}",
            f"-sR5_MARKER_PATH={MARKER}",
            str(docpath),
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=45)
            rc, out, err = (result.returncode,
                            result.stdout.decode("utf-8", "replace"),
                            result.stderr.decode("utf-8", "replace"))
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", "TIMEOUT"
        self._send(200, {"rc": rc, "stdout": out, "stderr": err,
                         "upload": str(directory)})

    def log_message(self, fmt, *args):
        sys.stderr.write("r5-server: " + fmt % args + "\n")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write(f"r5-server listening 127.0.0.1:{PORT} gs={GS_BIN}\n")
    sys.stderr.flush()
    server.serve_forever()
