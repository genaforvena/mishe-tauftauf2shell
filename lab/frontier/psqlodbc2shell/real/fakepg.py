#!/usr/bin/env python3
"""Minimal loopback PostgreSQL v3 handshake for the psqlODBC reachability
probe. Not a PostgreSQL server: it answers the startup handshake with
AuthenticationOk and bare success replies so a real driver can parse SQL
locally. Binds 127.0.0.1 only; no external address is ever contacted.
"""
import socket
import struct
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 59432


def msg(tag, body=b""):
    return tag + struct.pack("!I", len(body) + 4) + body


def i32(v):
    return struct.pack("!I", v)


def strmsg(tag, k, v):
    return msg(tag, k.encode() + b"\0" + v.encode() + b"\0")


def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle(c):
    try:
        hdr = recv_exact(c, 4)
        if hdr is None:
            return
        n = struct.unpack("!I", hdr)[0]
        body = recv_exact(c, n - 4)
        if body is None:
            return
        if n == 8 and body == i32(80877103):  # SSLRequest
            c.sendall(b"N")
            hdr = recv_exact(c, 4)
            if hdr is None:
                return
            n = struct.unpack("!I", hdr)[0]
            body = recv_exact(c, n - 4)
            if body is None:
                return
        print("STARTUP", body.split(b"\0")[:8], flush=True)
        out = msg(b"R", i32(0))
        for k, v in (("server_version", "14.0"), ("client_encoding", "UTF8"),
                     ("standard_conforming_strings", "on"),
                     ("integer_datetimes", "on"), ("DateStyle", "ISO, MDY"),
                     ("TimeZone", "UTC")):
            out += strmsg(b"S", k, v)
        out += msg(b"K", i32(1234) + i32(5678))
        out += msg(b"Z", b"I")
        c.sendall(out)
        while True:
            tag = recv_exact(c, 1)
            if tag is None:
                return
            hdr = recv_exact(c, 4)
            if hdr is None:
                return
            ln = struct.unpack("!I", hdr)[0]
            payload = recv_exact(c, ln - 4)
            if payload is None:
                return
            print("MSG", tag.decode(errors="replace"), ln, flush=True)
            if tag == b"X":
                return
            if tag == b"Q":
                c.sendall(msg(b"C", b"SELECT 0\0") + msg(b"Z", b"I"))
            elif tag == b"P":
                c.sendall(msg(b"1"))
            elif tag == b"B":
                c.sendall(msg(b"2"))
            elif tag == b"D":
                c.sendall(msg(b"t", i32(0)) + msg(b"T", i32(0)))
            elif tag == b"E":
                c.sendall(msg(b"C", b"SELECT 0\0"))
            elif tag == b"S":
                c.sendall(msg(b"Z", b"I"))
            else:
                c.sendall(msg(b"Z", b"I"))
    except Exception as e:
        print("SERVER ERROR", repr(e), flush=True)
    finally:
        c.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(2)
print("LISTEN 127.0.0.1:%d" % PORT, flush=True)
while True:
    c, addr = s.accept()
    print("ACCEPT", addr, flush=True)
    threading.Thread(target=handle, args=(c,), daemon=True).start()
