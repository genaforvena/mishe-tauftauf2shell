#!/usr/bin/env python3
"""zlib2shell — loopback TCP client for harness/tcp_server.c.

Starts one server case, sends the peer's own incompressible request bytes,
then either reads only the gzip header and stops (stall) or keeps draining
(drain control). In gdb mode, parses the readback after gz_vacate()'s memmove
and checks that the destination bytes are the peer's bytes at the computed
source offsets. All sockets are plant-started 127.0.0.1 sockets.
"""
import argparse
import os
import random
import re
import socket
import subprocess
import sys
import time

REQ = 100000


def peer_payload():
    rnd = random.Random(0x5A17C7)
    return bytes(rnd.getrandbits(8) for _ in range(REQ))


def gdb_values(text):
    """Values of the four print commands, in order, after the breakpoint."""
    tail = text.split("Breakpoint 1, gz_vacate", 1)[-1]
    vals = re.findall(r"^\$\d+ = (0x[0-9a-fA-F]+|\d+)$", tail, re.M)
    return vals


def gdb_after(text, command):
    m = re.search(r"^" + re.escape(command) + r"\s*$", text, re.M)
    if not m:
        return None
    v = re.search(r"^\$\d+ = (0x[0-9a-fA-F]+|\d+)", text[m.end():], re.M)
    return v.group(1) if v else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--mode", choices=("stall", "drain", "slowdrain", "gdb"), required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    payload = peer_payload()
    cmd = [a.binary]
    if a.mode == "gdb":
        cmd = ["gdb", "-q", "-batch", "-ex", "set pagination off",
               "-ex", "break gzwrite.c:395", "-ex", "run",
               "-ex", "print strm->avail_in",
               "-ex", "print/x state->in[0]",
               "-ex", "print/x state->in[17]",
               "-ex", "print/x state->in[16384]",
               "--args", a.binary]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=0:detect_leaks=0"
    env["TCP_SNDBUF"] = "1048576" if a.mode == "drain" else "4096"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env,
                            text=True, bufsize=1)

    lines = []
    port = None
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
    if port is None:
        proc.kill()
        rest = proc.stdout.read()
        text = "".join(lines) + rest
        with open(a.out, "w") as f:
            f.write(text)
        print("SERVER_RC=NA")
        print("CLIENT_ERROR=no-port")
        return 0

    header_len = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # A 4 KiB advertised window (kernel doubles it) is what stops the
        # server's gzwrite() with EAGAIN once the peer reads only the gzip
        # header. The drain control needs an adequate window to be a real
        # "peer keeps up" control: a 4 KiB window stalls even a draining peer.
        rcvbuf = (1 << 20) if a.mode == "drain" else 4096
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.settimeout(10)
        s.connect(("127.0.0.1", port))
        s.sendall(payload)
        if a.mode in ("drain", "slowdrain"):
            s.settimeout(20)
            try:
                while s.recv(65536):
                    pass
            except socket.timeout:
                lines.append("CLIENT_DRAIN_TIMEOUT=1\n")
        else:
            head = b""
            while len(head) < 10:
                chunk = s.recv(10 - len(head))
                if not chunk:
                    break
                head += chunk
            header_len = len(head)
            lines.append("CLIENT_HEADER_BYTES=%d\n" % header_len)
            # Socket stays open; the peer deliberately stops reading.
    except OSError as e:
        lines.append("CLIENT_ERROR=%s\n" % type(e).__name__)

    try:
        rest, _ = proc.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        proc.kill()
        rest, _ = proc.communicate()
        lines.append("SERVER_TIMEOUT=1\n")
    text = "".join(lines) + (rest or "")
    with open(a.out, "w") as f:
        f.write(text)

    print("SERVER_RC=%d" % proc.returncode)

    def field(name):
        m = re.search(r"^%s=([^\s]+)\s*$" % name, text, re.M)
        return m.group(1) if m else "NA"

    for name in ("REQ_BYTES", "WRITTEN", "PRINTF_RC", "SERVER_DONE"):
        print("%s=%s" % (name, field(name)))

    if a.mode == "gdb":
        vals = gdb_values(text)
        if len(vals) >= 4:
            avail = int(vals[0], 0)
            base = REQ - avail
            exp = [payload[base + off] for off in (0, 17, 16384)]
            obs = [int(v, 0) for v in vals[1:4]]
            print("GDB_AVAIL_IN=%d" % avail)
            print("SRC_OFFSET_BASE=%d" % base)
            for off, e, o in zip((0, 17, 16384), exp, obs):
                print("DST%d_EXPECTED=%02x" % (off, e))
                print("DST%d_OBSERVED=%02x" % (off, o))
            print("PEER_BYTE_CHECK=%s" %
                  ("PASS" if exp == obs else "FAIL"))
        else:
            print("PEER_BYTE_CHECK=NA")
    else:
        for tag in ("heap-buffer-overflow", "WRITE of size", "gz_vacate",
                    "AddressSanitizer", "16384-byte region"):
            print("HAS_%s=%s" % (tag.upper().replace(" ", "_").replace("-", "_"),
                                  "1" if tag in text else "0"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
