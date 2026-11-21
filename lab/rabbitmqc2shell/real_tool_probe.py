#!/usr/bin/env python3
"""Loopback-only AMQP 0-9-1 front end for the REAL amqp-publish tool.

Completes just enough handshake for amqp_login/amqp_channel_open to succeed,
then drains the tool's method/header/body frames and answers channel/connection
close. Nothing is sent off 127.0.0.1. Used by run_real_tool.sh to test whether
a real high-level publisher reaches the pinned amqp_connection.c:467 OOB.
"""
import os
import socket
import subprocess
import sys
import threading

PORT = int(os.environ.get("RMQ2_PORT", "15680"))
BODY_LEN = int(os.environ.get("RMQ2_BODY_LEN", "200000"))
TOOL = os.environ["RMQ2_TOOL"]
LOG = os.environ["RMQ2_LOG"]
LIBDIR = os.environ["RMQ2_LIBDIR"]
POPTDIR = os.environ["RMQ2_POPTDIR"]


def longstr(s):
    b = s.encode()
    return len(b).to_bytes(4, "big") + b


def mframe(ch, cls, meth, args=b""):
    p = cls.to_bytes(2, "big") + meth.to_bytes(2, "big") + args
    return (bytes([1]) + ch.to_bytes(2, "big")
            + len(p).to_bytes(4, "big") + p + b"\xce")


def read_exact(c, n):
    out = b""
    while len(out) < n:
        part = c.recv(n - len(out))
        if not part:
            raise EOFError("peer closed")
        out += part
    return out


def read_frame(c):
    h = read_exact(c, 7)
    n = int.from_bytes(h[3:7], "big")
    p = read_exact(c, n + 1)
    return h[0], int.from_bytes(h[1:3], "big"), p[:-1]


def logged_frame(c, result, tag):
    f = read_frame(c)
    result.setdefault("frames", []).append([tag, f[0], f[1], f[2][:8].hex()])
    return f


def serve(listener, result):
    c = None
    try:
        c, _ = listener.accept()
        c.settimeout(30)
        result["header"] = read_exact(c, 8).hex()
        start_args = (b"\x00\x09" + (0).to_bytes(4, "big")
                      + longstr("PLAIN") + longstr("en_US"))
        c.sendall(mframe(0, 10, 10, start_args))  # connection.start
        logged_frame(c, result, "start-ok")
        tune_args = ((0).to_bytes(2, "big") + (131072).to_bytes(4, "big")
                     + (0).to_bytes(2, "big"))
        c.sendall(mframe(0, 10, 30, tune_args))  # connection.tune (10,30)
        logged_frame(c, result, "tune-ok")
        c.sendall(mframe(0, 10, 41, b"\x00"))  # connection.open-ok (10,41)
        logged_frame(c, result, "connection.open")
        c.sendall(mframe(1, 20, 11, b"\x00\x00\x00\x00"))  # channel.open-ok
        result["handshake"] = "complete"
        while True:
            f = logged_frame(c, result, "publish")
            if f[0] == 1 and len(f[2]) >= 4:
                cls = int.from_bytes(f[2][0:2], "big")
                meth = int.from_bytes(f[2][2:4], "big")
                if (cls, meth) == (20, 40):
                    c.sendall(mframe(1, 20, 41))  # channel.close-ok
                elif (cls, meth) == (10, 50):
                    c.sendall(mframe(0, 10, 51))  # connection.close-ok
                    break
    except Exception as e:
        result["server_err"] = repr(e)
    finally:
        if c is not None:
            try:
                c.close()
            except Exception:
                pass


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", PORT))
listener.listen(1)
result = {}
t = threading.Thread(target=serve, args=(listener, result), daemon=True)
t.start()

env = os.environ.copy()
env["LD_LIBRARY_PATH"] = LIBDIR + ":" + POPTDIR + "/lib/x86_64-linux-gnu"
env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
with open(LOG, "wb") as log:
    p = subprocess.run([TOOL, "--server", "127.0.0.1", "--port", str(PORT),
                        "-e", "x", "-r", "k"],
                       input=b"\x5a" * BODY_LEN, stdout=log,
                       stderr=subprocess.STDOUT, env=env, timeout=60)
listener.close()
t.join(timeout=3)
print("rc", p.returncode)
print("result", result)
print("---log---")
print(open(LOG, "r", errors="replace").read()[:6000])
