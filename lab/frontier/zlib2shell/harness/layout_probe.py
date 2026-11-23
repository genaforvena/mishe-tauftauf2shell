#!/usr/bin/env python3
"""zlib2shell W2 — reproducible gdb heap-layout probe for the live TCP server.

Builds the plain vulnerable server from the pinned tarball with gzwrite.c
swapped, stops at gzwrite.c:389 (before gz_vacate's memmove), walks the glibc
chunks following state->in and scans the destination range for code pointers.
A plant-started 127.0.0.1 client stalls the peer exactly as tcp_probe.py does.
Author-side feasibility evidence, not a witness verdict.
"""
import os, random, re, shutil, socket, subprocess, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = ROOT + "/src"


def build(tmp):
    subprocess.run(["cp", "-r", SRC + "/zlib-1.3.2/.", tmp], check=True)
    shutil.copy(SRC + "/gzwrite.c.parent", tmp + "/gzwrite.c")
    env = dict(os.environ, CC="gcc", CFLAGS="-g -O0")
    with open(tmp + "/build.log", "w") as log:
        subprocess.run(["./configure", "--static"], cwd=tmp, env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
        subprocess.run(["make", "-s", "-j4"], cwd=tmp, env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
        subprocess.run(["gcc", "-g", "-O0", "-I.", HERE + "/tcp_server.c",
                        "libz.a", "-o", tmp + "/srv"], cwd=tmp, env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    return tmp + "/srv"


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--binary")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="zlib2shell-layout.") as tmp:
        binary = a.binary or build(tmp)
        rnd = random.Random(0x5A17C7)
        payload = bytes(rnd.getrandbits(8) for _ in range(100000))
        cmd = ["gdb", "-q", "-batch", "-ex", "set pagination off",
               "-ex", "break gzwrite.c:389", "-ex", "run",
               "-ex", "print strm->avail_in",
               "-ex", "print/x state->in[0]",
               "-ex", "print/x state->in[17]",
               "-ex", "print/x state->in[16384]",
               "-ex", "source " + HERE + "/layout.gdb",
               "--args", binary]
        env = dict(os.environ, ASAN_OPTIONS="abort_on_error=0:detect_leaks=0",
                   TCP_SNDBUF="4096")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env,
                                text=True, bufsize=1)
        lines, port = [], None
        deadline = time.time() + 30
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line)
            m = re.match(r"^PORT=(\d+)\s*$", line)
            if m:
                port = int(m.group(1))
                break
        print("PORT_SEEN=%s" % port)
        if port is None:
            proc.kill()
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                s.settimeout(10)
                s.connect(("127.0.0.1", port))
                s.sendall(payload)
                head = b""
                while len(head) < 10:
                    c = s.recv(10 - len(head))
                    if not c:
                        break
                    head += c
                print("CLIENT_HEADER_BYTES=%d" % len(head))
            except OSError as e:
                print("CLIENT_ERROR=%s" % type(e).__name__)
        rest, _ = proc.communicate(timeout=60)
        text = "".join(lines) + (rest or "")
        with open(a.out, "w") as f:
            f.write(text)
        for line in text.splitlines():
            if line.startswith(("LAYOUT_", "CHUNK", "SCAN_", "EXEC_PTR",
                                "REQ_BYTES=", "WRITTEN=")):
                print(line)
        print("SERVER_RC=%d" % proc.returncode)


main()
