#!/usr/bin/env python3
"""Register a loopback peer, send a NAK with a caller-chosen token_size,
and print the forwarded NAK's wire token. Used on the one-line fixed plain
build to test W6's zero-leak result at a larger token. Loopback only.
"""
import socket
import struct
import sys
import time

SN_PORT = int(sys.argv[1])
PEER_PORT = int(sys.argv[2])
TOKEN_SIZE = int(sys.argv[3])
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
time.sleep(2)
register = (common(5) + struct.pack("!I", COOKIE) + MAC
            + struct.pack("!I", 0) + bytes([0]) + bytes(16)
            + struct.pack("!HH", 0, 0) + struct.pack("!I", 0))
peer.sendto(register, ("127.0.0.1", SN_PORT))
reply = recv(peer, 4)
if reply is None:
    print("W8: no REGISTER_SUPER reply", flush=True)
    sys.exit(1)
print(f"W8: REGISTER_SUPER reply len={len(reply[0])}", flush=True)

token = bytes([0x48, 0x5a, 0x4d, 0x49]) * (TOKEN_SIZE // 4)
nak = (common(8) + struct.pack("!I", COOKIE) + MAC
       + struct.pack("!HH", 0, TOKEN_SIZE) + token)
assert len(nak) == 38 + TOKEN_SIZE
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.sendto(nak, ("127.0.0.1", SN_PORT))
sender.close()
print(f"W8: sent NAK len={len(nak)} token_size={TOKEN_SIZE}", flush=True)

for _ in range(12):
    reply = recv(peer, 1)
    if reply is None:
        continue
    data = reply[0]
    wire = data[38:]
    nonzero = sum(1 for b in wire if b)
    print(f"W8: forwarded len={len(data)} wire_token_len={len(wire)} "
          f"nonzero={nonzero} first={wire[:8].hex()} "
          f"at48={wire[48:56].hex()} at96={wire[96:104].hex()} "
          f"at128={wire[128:136].hex()} at256={wire[256:264].hex()} "
          f"at400={wire[400:408].hex()} last={wire[-8:].hex()}", flush=True)
    print(f"W8: wire_token_hex={wire.hex()}", flush=True)
    break
else:
    print("W8: no forwarded NAK within 12 s", flush=True)
