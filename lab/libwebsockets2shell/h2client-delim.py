#!/usr/bin/env python3
"""Throwaway loopback HPACK probe: arbitrary :path with a URI delimiter."""
import socket, struct, sys

PORT = int(sys.argv[1])
PREFIX = int(sys.argv[2])          # bytes before delimiter, including leading '/'
DELIM = sys.argv[3].encode()       # '&' | ';' | '?'
MARKER = bytes.fromhex(sys.argv[4]) if len(sys.argv[4]) == 2 and all(
    ch in '0123456789abcdefABCDEF' for ch in sys.argv[4]) else sys.argv[4].encode()
TAIL = int(sys.argv[5]) if len(sys.argv) > 5 else 20

path = b"/" + b"A" * (PREFIX - 1) + DELIM + MARKER * TAIL

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
block = hpack_literal(5, path)
block += bytes((0x82,))
block += bytes((0x86,))
block += hpack_literal(1, b"localhost")

s = socket.create_connection(("127.0.0.1", PORT), timeout=4)
s.sendall(PREFACE)
s.sendall(frame(4, 0, 0, b""))
s.sendall(frame(1, 0x5, 1, block))
s.settimeout(2)
try:
    data = s.recv(4096)
    print("recv", len(data), data[:64].hex())
except Exception as e:
    print("recv none:", type(e).__name__)
s.close()
print("prefix", PREFIX, "delim", DELIM.hex(), "marker", MARKER.hex(),
      "pathlen", len(path), "path", path.hex())
