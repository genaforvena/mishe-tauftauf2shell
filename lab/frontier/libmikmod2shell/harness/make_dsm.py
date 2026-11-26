#!/usr/bin/env python3
"""Build minimal DSM files matching the pinned DSM_Load() field layout.

All bytes are generated locally; nothing is fetched or probed.  Each PATT
chunk has 64 rows with flag=0 (empty row), which DSM_ReadPattern accepts.
"""
import struct
import sys


def song_chunk(numord, numsmp, numpat, numtrk):
    song = bytearray(192)
    song[0:28] = b"local-dsm-trigger".ljust(28, b"\0")
    struct.pack_into("<H", song, 28, 0x0100)   # version
    struct.pack_into("<H", song, 30, 0)       # flags
    struct.pack_into("<I", song, 32, 0)       # reserved2
    struct.pack_into("<H", song, 36, numord)
    struct.pack_into("<H", song, 38, numsmp)
    struct.pack_into("<H", song, 40, numpat)
    struct.pack_into("<H", song, 42, numtrk)  # read as numchn
    song[44] = 0                              # globalvol
    song[45] = 0                              # mastervol
    song[46] = 6                              # speed
    song[47] = 125                            # bpm
    # panpos[16] and orders[128] stay zero.
    return b"SONG" + struct.pack("<I", len(song)) + bytes(song)


def patt_chunk():
    data = struct.pack("<h", 64) + bytes(64)  # length + 64 empty rows
    return b"PATT" + struct.pack("<I", len(data)) + data


def inst_chunk():
    data = bytes(64)  # zeroed DSMINST; no sample payload needed for the header path
    return b"INST" + struct.pack("<I", len(data)) + data


def build(path, numpat, numtrk, patterns):
    body = (song_chunk(1, 1, numpat, numtrk) + inst_chunk()
            + b"".join(patt_chunk() for _ in range(patterns)))
    riff = b"RIFF" + struct.pack("<I", len(body) + 4) + b"DSMF" + body
    with open(path, "wb") as f:
        f.write(riff)
    print(f"{path}: {len(riff)} bytes numchn={numtrk} numpat={numpat} "
          f"product={numtrk * numpat} truncated={(numtrk * numpat) & 0xffff} "
          f"patt={patterns}")


if __name__ == "__main__":
    outdir = sys.argv[1]
    build(f"{outdir}/attack.dsm", 32769, 2, 2)   # 65538 -> 2 tracks, 4 writes
    build(f"{outdir}/attack16.dsm", 4097, 16, 2)  # 65552 -> 16 tracks, 32 writes
    build(f"{outdir}/safe.dsm", 2, 2, 2)          # 4 -> 4 tracks, 4 writes
