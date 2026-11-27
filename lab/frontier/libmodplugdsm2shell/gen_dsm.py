#!/usr/bin/env python3
"""Generate a minimal DSM stream with N PATT chunks (nPat is unchecked).

Layout follows the verbatim pinned src/load_dsm.cpp structs (packed):
DSMFILEHEADER = 4s + u32 + 4s + 4s + u32
DSMSONG       = 28s + H + H + I + 5H + 4B + 16B + 128B (192 bytes)
DSMPATT       = 4s + u32 (8 bytes), patt_len=0 -> no note bytes consumed.
This is frontier scaffolding, not upstream source.
"""
import struct
import sys

song = bytearray(192)
n_patt = int(sys.argv[2]) if len(sys.argv) > 2 else 241
struct.pack_into("<4H", song, 36, 0, 0, 0, 4)  # numord, numsmp, numpat, numtrk
song[44:48] = bytes([64, 64, 6, 125])          # globalvol, mastervol, speed, bpm
body = bytearray(song)
for _ in range(n_patt):
    body += struct.pack("<4sI", b"PATT", 0)
body += b"\x00" * 16  # loop requires dwMemPos < dwMemLength - 8
buf = bytearray(b"RIFF" + struct.pack("<I", len(body) + 4) + b"DSMF" + b"SONG"
                + struct.pack("<I", len(song)) + body)
with open(sys.argv[1], "wb") as f:
    f.write(buf)
print(f"wrote {sys.argv[1]} bytes={len(buf)} patt={n_patt}")
