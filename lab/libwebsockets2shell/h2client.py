#!/usr/bin/env python3
"""Loopback-only HTTP/2 prior-knowledge client: one HEADERS with a long :path.

Sends the HTTP/2 connection preface, an empty SETTINGS frame and one HEADERS
frame whose HPACK-decoded :path is PATHLEN bytes.  No external addresses.
"""
import socket
import struct
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18777
PATHLEN = int(sys.argv[2]) if len(sys.argv) > 2 else 64
FILLER = sys.argv[3].encode() if len(sys.argv) > 3 else b"A"


def frame(ftype, flags, stream, payload):
    return struct.pack(">I", len(payload))[1:] + bytes((ftype, flags)) + \
        struct.pack(">I", stream) + payload
def hpack_int(n):
    if n < 127:
        return bytes((n,))
    out = bytearray((127,))
    n -= 127
    while n >= 128:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def hpack_literal(index, value):
    return bytes((index,)) + hpack_int(len(value)) + value


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# :path (static index 5) first so the long value is decoded before other
# headers can consume the configured header arena.
path = b"/" + (FILLER * PATHLEN)[:PATHLEN]
block = hpack_literal(5, path)
block += bytes((0x82,))                     # :method GET (index 2)
block += bytes((0x86,))                     # :scheme http (index 6)
block += hpack_literal(1, b"localhost")     # :authority

s = socket.create_connection(("127.0.0.1", PORT), timeout=4)
s.sendall(PREFACE)
s.sendall(frame(4, 0, 0, b""))              # SETTINGS
s.sendall(frame(1, 0x5, 1, block))          # HEADERS, END_STREAM|END_HEADERS
s.settimeout(2)
try:
    data = s.recv(4096)
    print("recv", len(data), data[:64].hex())
except Exception as e:
    print("recv none:", type(e).__name__)
s.close()
print("sent pathlen", len(path), "block bytes", len(block))
