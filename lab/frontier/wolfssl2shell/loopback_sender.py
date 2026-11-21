#!/usr/bin/env python3
"""Loopback-only helpers: capture a real DTLS 1.3 ClientHello, then replay it
with distinct legacy record sequence numbers into a local wolfSSL server.

Usage:
  loopback_sender.py capture PORT FILE
  loopback_sender.py replay FILE PORT N [delay_us]
"""
import socket
import sys
import time


def capture(port, path):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(8)
    data, peer = s.recvfrom(65535)
    with open(path, "wb") as f:
        f.write(data)
    print("FACT captured_bytes=%d peer=%s:%d prefix=%s" %
          (len(data), peer[0], peer[1], data[:16].hex()))
    s.close()


def replay(path, port, count, delay_us=0, unified=False):
    with open(path, "rb") as f:
        ch = bytearray(f.read())
    if len(ch) < 13 or ch[0] != 22 or ch[1:3] != b"\xfe\xfd":
        raise SystemExit("captured datagram is not a legacy DTLS handshake record")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for seq in range(1, count + 1):
        if unified:
            hs = bytearray(ch[13:])
            hs[4:6] = (seq % 65536).to_bytes(2, "big")
            pkt = bytearray([0x2c]) + seq.to_bytes(2, "big") + \
                len(hs).to_bytes(2, "big") + hs
        else:
            pkt = bytearray(ch)
            pkt[5:11] = seq.to_bytes(6, "big")  # legacy 64-bit record number
            pkt[17:19] = (seq % 65536).to_bytes(2, "big")
        s.sendto(pkt, ("127.0.0.1", port))
        if delay_us:
            time.sleep(delay_us / 1e6)
    print("FACT replayed=%d target=127.0.0.1:%d" % (count, port))
    s.close()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    if sys.argv[1] == "capture":
        capture(int(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == "replay":
        replay(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
               int(sys.argv[5]) if len(sys.argv) > 5 else 0,
               len(sys.argv) > 6 and sys.argv[6] == "unified")
    else:
        raise SystemExit(__doc__)
